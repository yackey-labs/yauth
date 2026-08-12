package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Trusted-proxy list keywords accepted by [ParseTrustedProxies] alongside
// literal IPs and CIDRs.
const (
	// TrustedProxiesPrivate expands to loopback, link-local, RFC1918,
	// RFC6598 (CGNAT) and IPv6 unique-local ranges — the address space a
	// reverse proxy, ingress controller or service mesh sidecar lives in.
	// It is the DEFAULT when no list is configured.
	TrustedProxiesPrivate = "private"
	// TrustedProxiesAll trusts every peer, restoring the pre-hardening
	// behaviour of believing X-Forwarded-For unconditionally. Only correct
	// when something in front of yauth already strips/rewrites the header
	// on ingress, because any client that can reach the listener can then
	// forge its own address into every audit row.
	TrustedProxiesAll = "all"
	// TrustedProxiesNone believes no forwarding header at all: the client
	// IP is always the immediate peer. Correct for a listener exposed
	// directly to clients.
	TrustedProxiesNone = "none"
)

// privatePrefixes is the address space [TrustedProxiesPrivate] expands to.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC6598 CGNAT / k8s node CIDRs
	netip.MustParsePrefix("::1/128"),        // loopback
	netip.MustParsePrefix("fc00::/7"),       // unique-local
	netip.MustParsePrefix("fe80::/10"),      // link-local
}

// TrustedProxies decides whose X-Forwarded-For / X-Real-IP yauth believes
// when it resolves the client IP of a request.
//
// The zero value is usable and means [TrustedProxiesPrivate]: forwarding
// headers are honoured only when the immediate peer (r.RemoteAddr) is a
// loopback/private/link-local address. That default keeps the audit trail
// of every proxied deployment intact — an ingress, sidecar or local nginx
// sits on private space — while closing header forgery for a listener that
// clients reach directly, where the peer is a public address.
//
// Construct a non-default policy with [ParseTrustedProxies].
type TrustedProxies struct {
	// configured distinguishes "operator supplied a list" from the zero
	// value, which resolves to privatePrefixes.
	configured bool
	all        bool
	prefixes   []netip.Prefix
}

// ParseTrustedProxies builds a policy from a list of literal IPs, CIDRs and
// the keywords "private", "all" and "none". A nil/empty list yields the zero
// value (the private-ranges default).
//
// Examples:
//
//	["private"]                     the default
//	["10.0.0.0/8", "172.20.1.5"]    an explicit ingress range plus one host
//	["private", "173.245.48.0/20"]  private space plus a CDN edge range
//	["none"]                        never believe a forwarding header
//	["all"]                         believe it from anyone (pre-v0 behaviour)
func ParseTrustedProxies(specs []string) (TrustedProxies, error) {
	var t TrustedProxies
	seen := false
	for _, raw := range specs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		seen = true
		switch strings.ToLower(s) {
		case TrustedProxiesPrivate:
			t.prefixes = append(t.prefixes, privatePrefixes...)
			continue
		case TrustedProxiesAll:
			t.all = true
			continue
		case TrustedProxiesNone:
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			t.prefixes = append(t.prefixes, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return TrustedProxies{}, fmt.Errorf("trusted_proxies: %q is not an IP, a CIDR, or one of %q/%q/%q", raw, TrustedProxiesPrivate, TrustedProxiesAll, TrustedProxiesNone)
		}
		a = a.Unmap()
		t.prefixes = append(t.prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	t.configured = seen
	return t, nil
}

// Trusts reports whether addr is a proxy whose forwarding headers may be
// believed.
func (t TrustedProxies) Trusts(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if !t.configured {
		return containsAddr(privatePrefixes, addr)
	}
	if t.all {
		return true
	}
	return containsAddr(t.prefixes, addr)
}

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	a := addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP resolves the address yauth attributes the request to. It is the
// ONE function both sides of session IP-binding use — the value stored on a
// session at login and the value compared against it on every later request
// — so a proxied deployment cannot store one source and compare another.
//
// Resolution walks the forwarding chain from the closest hop outward:
//
//  1. Start at the immediate peer, r.RemoteAddr's host.
//  2. If that peer is not trusted, it IS the client — forwarding headers
//     are ignored, so a direct client cannot name itself.
//  3. Otherwise consume X-Forwarded-For right-to-left (the rightmost entry
//     was appended by the closest proxy and is the most trustworthy) and
//     return the first entry that is not itself a trusted proxy.
//  4. If every hop in the chain is trusted, the leftmost entry is the
//     client — this is the case for an all-private deployment, and it is
//     also what [TrustedProxiesAll] degrades to, which is exactly the old
//     unconditional behaviour.
//  5. With no X-Forwarded-For, X-Real-IP is honoured from a trusted peer.
//
// Unparseable X-Forwarded-For entries are skipped rather than returned, so
// junk in the header can never reach an audit row. The result is the
// canonical form of the address (IPv6 unmapped, no brackets, no port); "" is
// returned only when RemoteAddr is empty.
func (t TrustedProxies) ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	peerRaw := hostOnly(r.RemoteAddr)
	if peerRaw == "" {
		return ""
	}
	peer, err := netip.ParseAddr(peerRaw)
	if err != nil {
		// Not an address we can reason about (a unix socket, a test
		// fixture). Never trust a peer we cannot classify.
		return peerRaw
	}
	peer = peer.Unmap()
	if !t.Trusts(peer) {
		return peer.String()
	}

	if xff := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(xff) != "" {
		parts := strings.Split(xff, ",")
		var leftmost string
		found := false
		for i := len(parts) - 1; i >= 0; i-- {
			a, ok := parseForwardedAddr(parts[i])
			if !ok {
				continue
			}
			if !t.Trusts(a) {
				return a.String()
			}
			leftmost = a.String()
			found = true
		}
		// Every hop was itself trusted: the leftmost entry is the client.
		if found {
			return leftmost
		}
		return peer.String()
	}

	if v := r.Header.Get("X-Real-IP"); strings.TrimSpace(v) != "" {
		if a, ok := parseForwardedAddr(v); ok {
			return a.String()
		}
	}
	return peer.String()
}

// hostOnly strips the port from a host:port pair, tolerating a bare host and
// bracketed IPv6.
func hostOnly(remoteAddr string) string {
	s := strings.TrimSpace(remoteAddr)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}

// parseForwardedAddr parses one X-Forwarded-For / X-Real-IP entry. Proxies
// are inconsistent about ports, brackets and IPv6 zones, so all three are
// tolerated.
func parseForwardedAddr(s string) (netip.Addr, bool) {
	v := strings.TrimSpace(s)
	if v == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	if host, _, err := net.SplitHostPort(v); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Unmap().WithZone(""), true
		}
	}
	return netip.Addr{}, false
}

// trustedProxiesKey is the context key carrying the deployment's policy.
type trustedProxiesKey struct{}

// WithTrustedProxies returns a context carrying t, so [RequestIP] and the
// rate limiter resolve the client IP under the deployment's policy rather
// than the built-in default.
func WithTrustedProxies(ctx context.Context, t TrustedProxies) context.Context {
	return context.WithValue(ctx, trustedProxiesKey{}, t)
}

// TrustedProxiesFromContext returns the policy carried by ctx, or the
// zero-value (private-ranges) default when none was installed.
func TrustedProxiesFromContext(ctx context.Context) TrustedProxies {
	if ctx == nil {
		return TrustedProxies{}
	}
	if t, ok := ctx.Value(trustedProxiesKey{}).(TrustedProxies); ok {
		return t
	}
	return TrustedProxies{}
}

// TrustedProxiesMiddleware installs t on every request's context. The YAuth
// router applies it outermost; consumers that guard their OWN routes with
// [Middleware.RequireAuth] and run a non-default policy should apply it to
// those routes too, so the IP their audit rows record matches the one yauth
// recorded at login.
func TrustedProxiesMiddleware(t TrustedProxies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(WithTrustedProxies(r.Context(), t)))
		})
	}
}

// RequestIP extracts the client IP of a request under the trusted-proxy
// policy carried by its context (the built-in private-ranges default when
// none was installed). The result is a pointer because domain session fields
// accept *string; nil means "no address could be determined".
//
// It used to believe the leftmost X-Forwarded-For entry from any peer, which
// made every audit row, session IPAddress and AuthEvent.IPAddress forgeable
// by the client that generated them. See [TrustedProxies.ClientIP].
func RequestIP(r *http.Request) *string {
	ip := TrustedProxiesFromContext(r.Context()).ClientIP(r)
	if ip == "" {
		return nil
	}
	return &ip
}
