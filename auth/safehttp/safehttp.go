// Package safehttp is yauth's single outbound-egress guard: the one place
// that decides where the process is willing to open a connection when the
// destination was chosen by a *caller* rather than by the operator's code.
//
// yauth has several such destinations — a webhook receiver registered over the
// admin API, an audit-export SIEM, the `jwks_uri` of an OAuth2 client, the
// `iss` of an as-yet-unverified software statement, an SSO connection's
// discovery document. Every one of them turns the server's network position
// into a primitive the caller can aim: at the cloud metadata service
// (169.254.169.254), at a database or admin port bound to loopback, at
// anything inside the VPC that a browser could never reach. When the response
// (or even just its status code) is reflected back to that caller, blind SSRF
// becomes a read primitive.
//
// The two core helpers here were lifted verbatim from
// plugins/oauth2server/client_auth.go, where they had guarded the `jwks_uri`
// fetch since that hole was first closed; only the error prefix changed. They
// are deliberately unchanged in behaviour so the oauth2server SSRF tests keep
// passing across the move:
//
//   - IsPrivateIP classifies a *resolved* literal.
//   - DialContext resolves the host itself, checks every A record, and then
//     dials the resolved literal — so a DNS-rebinding answer that flips from
//     public to private between the check and the connect cannot win: the
//     address that was checked is the address that is dialled.
//
// Two policy layers sit on top:
//
//   - ValidateDestinationURL is the *create-time* check. It refuses a scheme
//     that is not http(s) and a literal private IP, but it deliberately does
//     NOT resolve hostnames. An in-cluster destination
//     ("http://otel-collector.observability.svc.cluster.local:4318") is a
//     legitimate, extremely common configuration; whether a hostname points
//     somewhere private is a dial-time question, and answering it at create
//     time would both lock out real installs and be defeated by a TTL.
//   - Client is the *dial-time* enforcement, and it is what actually holds:
//     a row that predates the guard (or a hostname that resolves privately
//     later) is refused when the connection is attempted rather than silently
//     dropped, so the failure is visible in the delivery/outbox record.
//
// The allowPrivate escape hatch exists because shipping to an in-cluster
// collector or a syslog sidecar is a first-class deployment shape. It is
// opt-in, never the default, and it is not absolute: see IsAlwaysDeniedIP.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// privateIPBlocks is the RFC 1918 + link-local + unspecified set, built once.
// It was a composite literal inside IsPrivateIP, which meant five net.IPNet
// values and their backing byte slices were allocated on every call — and this
// package is the library's single outbound-egress chokepoint, so that call runs
// per resolved address on every webhook delivery, every OIDC discovery and JWKS
// fetch, and every syslog audit export.
var privateIPBlocks = []net.IPNet{
	{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
	{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
	{IP: net.IP{169, 254, 0, 0}, Mask: net.CIDRMask(16, 32)}, // link-local
	{IP: net.IP{0, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},      // 0.0.0.0/8
}

// alwaysDeniedLinkLocal and alwaysDeniedUnspecified are hoisted for the same
// reason as privateIPBlocks.
var (
	alwaysDeniedLinkLocal   = net.IPNet{IP: net.IP{169, 254, 0, 0}, Mask: net.CIDRMask(16, 32)}
	alwaysDeniedUnspecified = net.IPNet{IP: net.IP{0, 0, 0, 0}, Mask: net.CIDRMask(8, 32)}
)

// IsPrivateIP reports whether addr is a loopback, link-local, or RFC 1918
// address — used to block SSRF after DNS resolution so that DNS rebinding
// cannot bypass a pre-dial hostname check.
//
// Lifted unchanged from plugins/oauth2server (isPrivateIP).
func IsPrivateIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	// Unwrap IPv4-in-IPv6 (e.g. ::ffff:127.0.0.1)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// IsAlwaysDeniedIP reports whether addr is in a range that is never a
// legitimate destination, not even for a deployment that has deliberately
// opted into private egress.
//
// This is the floor under allowPrivate. The reason a deployment turns
// allowPrivate on is an in-cluster collector or a sidecar — loopback and
// RFC 1918. Nobody ships webhooks or audit logs to 169.254.169.254; that
// address is the cloud instance-metadata service, and reaching it is the
// entire point of the attack this package exists to stop. Without this floor,
// every install that flips the knob (which is most of the in-cluster ones)
// would get the IMDS hole straight back.
//
// 0.0.0.0/8 rides along because "0.0.0.0" is a well-known localhost alias on
// Linux and exists only as a bypass.
//
// Note that this is applied only by Client — callers that use DialContext
// directly (oauth2server's development escape hatch for a loopback jwks_uri)
// keep their existing all-or-nothing meaning.
func IsAlwaysDeniedIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return alwaysDeniedLinkLocal.Contains(ip) || alwaysDeniedUnspecified.Contains(ip) || ip.IsLinkLocalUnicast()
}

// DialContext returns a DialContext function that rejects connections to
// private/loopback addresses after DNS resolution (defeating DNS rebinding).
//
// Lifted unchanged from plugins/oauth2server (safeDialContext) apart from the
// error prefix, which used to name jwks_uri and now has several callers.
func DialContext(nd *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("safehttp: invalid address %q", addr)
		}
		resolved, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("safehttp: resolve %q: %w", host, err)
		}
		for _, ip := range resolved {
			if IsPrivateIP(ip) {
				return nil, fmt.Errorf("safehttp: %q resolved to non-public address %s; "+
					"refusing to connect (enable the caller's allow-private-destinations "+
					"option if this destination is intentional)", host, ip)
			}
		}
		return nd.DialContext(ctx, network, net.JoinHostPort(resolved[0], port))
	}
}

// defaultDialer is the shared dial tuning: the same 10s connect / 30s
// keep-alive the oauth2server fetches have always used.
func defaultDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
}

// Client builds an *http.Client for a caller-supplied destination.
//
// allowPrivate governs WHERE the client may dial — never whether redirects are
// followed. That distinction matters: a redirect is how an attacker who only
// controls a *public* receiver reaches a private one, so CheckRedirect is set
// unconditionally and cannot be disarmed by flipping the private-egress knob.
//
// maxRedirects <= 0 means "do not follow any redirect": the client returns the
// 3xx response itself (http.ErrUseLastResponse) so the caller records the real
// status rather than the result of a hop it never sanctioned. This is what
// stops a signed POST being laundered into a GET carrying the signature header
// to a second host — Go copies every header except Authorization and Cookie
// across a redirect.
//
// timeout is used verbatim; callers derive their own context budgets from
// Client.Timeout, so silently substituting a default here would shorten them.
func Client(allowPrivate bool, timeout time.Duration, maxRedirects int) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if allowPrivate {
		// Opted into private egress: keep Go's own resolution and its
		// multi-address failover (an in-cluster Service name routinely has
		// several A records, and substituting a resolve-then-dial-the-first
		// helper here would turn a healthy destination into a flaky one), and
		// enforce the floor with a Control hook instead. Control runs after
		// resolution with the address actually being connected to, so it is
		// rebinding-proof for the same reason DialContext is.
		nd := defaultDialer()
		nd.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			if IsAlwaysDeniedIP(host) {
				return fmt.Errorf("safehttp: refusing to connect to link-local address %s "+
					"(the cloud metadata service is never a valid destination, even with "+
					"private destinations allowed)", host)
			}
			return nil
		}
		transport.DialContext = nd.DialContext
	} else {
		transport.DialContext = DialContext(defaultDialer())
	}
	return &http.Client{
		Timeout: timeout,
		// otelhttp so each outbound call emits a CLIENT span and propagates
		// the W3C traceparent to the peer.
		Transport: otelhttp.NewTransport(transport),
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if maxRedirects <= 0 {
				return http.ErrUseLastResponse
			}
			if len(via) >= maxRedirects {
				return errors.New("safehttp: too many redirects")
			}
			return nil
		},
	}
}

// ValidateDestinationURL is the create-time check for a caller-supplied
// destination URL. It refuses what can never be legitimate, and nothing else.
//
// It does NOT resolve hostnames, on purpose: refusing a hostname because it
// currently resolves privately would lock out every deployment shipping to an
// in-cluster collector, and would be trivially defeated by a short TTL anyway.
// Where a hostname points is decided at dial time by Client.
func ValidateDestinationURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a valid URL", raw)
	}
	// A non-http(s) scheme never reaches a socket through net/http anyway, but
	// accepting one persists a row that is dialled (and fails) on every single
	// event forever, and it is the shape a future transport change would turn
	// into a file-read. Refuse it at the door.
	switch u.Scheme {
	case "http", "https":
	case "":
		return fmt.Errorf("destination URL %q is not absolute (it needs an http:// or https:// scheme)", raw)
	default:
		return fmt.Errorf("destination URL must use http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("destination URL %q has no host", raw)
	}
	return validateHostLiteral(u.Hostname(), allowPrivate)
}

// ValidateDestinationHost is ValidateDestinationURL for destinations that are
// a bare host rather than a URL — the syslog exporter dials host:port directly.
func ValidateDestinationHost(host string, allowPrivate bool) error {
	if host == "" {
		return errors.New("destination host is required")
	}
	return validateHostLiteral(host, allowPrivate)
}

func validateHostLiteral(host string, allowPrivate bool) error {
	if net.ParseIP(host) == nil {
		// A hostname: resolved (and re-checked) at dial time.
		return nil
	}
	if IsAlwaysDeniedIP(host) {
		return fmt.Errorf("%s is a link-local address (the cloud instance metadata service); "+
			"it is never a valid destination", host)
	}
	if !allowPrivate && IsPrivateIP(host) {
		return fmt.Errorf("%s is a private or loopback address; set allow_private_destinations "+
			"to export to an in-cluster destination", host)
	}
	return nil
}
