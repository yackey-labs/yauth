// crosssite.go holds the cross-site state-change guard: ONE predicate,
// applied at the authenticated chokepoints, that refuses a state-changing
// request the browser itself reports as coming from another site while it
// carries yauth's ambient session cookie.
//
// What was broken. Every cookie-authenticated route in this repo authorized
// on the ambient credential alone. ResolveAuth read the session cookie,
// requireAuth / RequireAdmin (and their huma twins) checked role and
// must_change_password, and the handler ran. Nothing on that path ever asked
// WHERE the request came from. So any page an authenticated operator had open
// could issue a state-changing POST at the yauth origin, the browser attached
// the victim's cookie for it, and the write landed:
//
//   - The bodyless admin levers need no trick at all. POST
//     /admin/users/{id}/suspend takes a POINTER body and its handler is
//     explicitly lenient about an absent one; /unban, /unsuspend and
//     /impersonate take a bare id. A plain auto-submitting
//     <form method="post"> — a simple request, never preflighted — reaches
//     every one of them.
//   - The routes that DO need a body are barely harder. humaapi registers
//     huma.DefaultFormats, and huma falls back to application/json when a
//     request carries NO Content-Type header at all; a cross-site fetch()
//     with `new Blob(body, {type: ""})` omits Content-Type, stays a simple
//     request, and is parsed as JSON regardless.
//
// The attacker never reads the response — CORS still blocks that — which is
// irrelevant: suspend, ban, role changes, membership deletes and client
// registration are one-way writes.
//
// Why THIS guard and not a broader one. The obvious blanket rules all break
// first-party callers, and a guard that breaks the console is a guard an
// operator turns off:
//
//   - "Refuse any request carrying an Origin" kills the same-origin SPA,
//     which sends Origin on every cross-origin-mode fetch.
//   - "Refuse unless Origin is present" kills curl, k6, an embedder's Go
//     integration suite and any server-side client — none of which a CSRF can
//     drive, because there is no browser to attach an ambient cookie.
//   - A synthesised CSRF token / double-submit cookie would close strictly
//     more (see the residuals below), but it is a client-library contract
//     change and a second CSRF scheme alongside oauth2server's existing signed
//     csrf_token. This guard is the layer such a scheme would sit ON TOP OF,
//     not a replacement for it.
//
// What it deliberately does NOT close, said plainly so it is not mistaken for
// coverage:
//
//   - Script running on any SAME-SITE origin (a marketing subdomain, an XSS
//     in a sibling app) still passes — rule (d) accepts Sec-Fetch-Site:
//     same-site, because a console on a sibling host is the overwhelmingly
//     common deployment and refusing it would break far more than it fixes.
//   - A browser that sends NEITHER Sec-Fetch-Site NOR Origin still passes —
//     rule (e). No shipping browser does that on a cross-site write
//     (Sec-Fetch-Site: Chrome 76+, Firefox 90+, Safari 16.4+; older Safari
//     still sends Origin on a cross-origin POST), and failing those closed
//     breaks every embedder's headless test suite for no attacker gain.
package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/yackey-labs/yauth/domain"
)

// CrossSiteWriteDetail is the `detail` / message returned when the guard
// refuses a request. It MUST name both escape hatches: this is the
// highest-blast-radius refusal in the library, and an operator reading a
// support ticket has to be able to find the knob without the source.
const CrossSiteWriteDetail = "cross-site state-changing request refused: this request carried a session cookie and the browser reported it as cross-site. Add the calling origin to server.cross_site_writes.origins (which defaults to server.cors.allowed_origins), or set server.cross_site_writes.allow: true to turn this check off."

// RefuseCrossSiteWrite reports whether r must be refused as a cross-site
// state change made with an ambient (cookie) credential.
//
// The rules are evaluated in this ORDER, and the order is the design — each
// early return names a caller that must keep working:
//
//	a. Config.AllowCrossSiteWrites  -> allow (operator kill switch)
//	b. machine credential           -> allow (a CSRF cannot attach one)
//	c. GET / HEAD / OPTIONS         -> allow (not a state change)
//	d. Sec-Fetch-Site says same-origin / same-site / none -> allow
//	e. no Sec-Fetch-Site AND no Origin -> allow (not a browser)
//	f. Origin's host == r.Host      -> allow (same origin, old browser)
//	f2. Origin's host == Config.SelfOrigin's host -> allow (proxied/SSR)
//	g. Origin on the effective allow-list -> allow
//	h. otherwise refuse.
//
// Rule (d) accepting "same-site" is a documented LIMIT, not an oversight:
// script on ANY sibling origin of the deployment's registrable domain still
// passes. See the package comment above.
//
// It is EXPORTED for the same reason [MustRotatePassword] is: a handler that
// resolves identity itself with ResolveAuth / ResolveAdmin rather than
// wrapping with RequireAuth does not inherit the chokepoint, and silently
// misses this gate. plugins/oauth2server's DCR handler is exactly that shape
// and calls this directly.
func RefuseCrossSiteWrite(cfg Config, r *http.Request, au *domain.AuthUser) bool {
	// (a) Kill switch. Zero value = guard ON: yauth.New stores the config it
	// is handed verbatim with no defaulting pass, so an `Enabled bool` would
	// be false for every embedder that builds its config in Go and this would
	// ship doing nothing — the same opt-out polarity, for the same reason, as
	// SecurityHeadersConfig.Disabled.
	if cfg.AllowCrossSiteWrites {
		return false
	}

	// (b) Machine credentials are not ambient. A cross-site page cannot make
	// a browser attach an Authorization or X-Api-Key header (setting one
	// forces a preflight this server would refuse), so bearer / user-scoped
	// api-key / service-account callers have nothing to steal here — and
	// automation that happens to run from a build agent sending an Origin
	// must not start failing. isMachineMethod is REUSED rather than
	// re-derived so the machine/human split stays in one switch.
	if au == nil || isMachineMethod(au.Method) {
		return false
	}

	// (c) Safe methods. A cross-site GET's response is unreadable to the
	// attacker anyway (CORS), and refusing reads would break every embedded
	// dashboard for zero gain. This guard is about STATE CHANGES.
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}

	// (d) Fetch Metadata, the browser's own first-party signal, is the
	// primary check: "same-origin" is the first-party SPA, "none" is a
	// user-typed URL or bookmark, and "same-site" is the console on a sibling
	// subdomain. Accepting same-site is the guard's stated limit.
	secFetchSite := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))
	switch strings.ToLower(secFetchSite) {
	case "same-origin", "same-site", "none":
		return false
	}

	origin := strings.TrimSpace(r.Header.Get("Origin"))

	// (e) Neither header: not a browser. curl, k6, an embedder's Go suite, a
	// server-side client. No shipping browser omits both on a cross-site
	// write, and none of these callers has an ambient cookie an attacker
	// could borrow — the cookie was put there by whoever wrote the script.
	if secFetchSite == "" && origin == "" {
		return false
	}

	originHost := hostOfOrigin(origin)

	// (f) Origin echoes the host this request was addressed to. This is the
	// pre-Fetch-Metadata browser making a same-origin POST. Compare the HOST
	// only and ignore the scheme: behind a TLS-terminating proxy r.TLS is nil
	// and the scheme is unknowable from here — the same reasoning
	// security_headers.go already applies to HSTS.
	if originHost != "" && originHost == strings.ToLower(r.Host) {
		return false
	}

	// (f2) Origin matches the deployment's own BaseURL. Two first-party
	// callers land here and would otherwise be refused by (f): a proxy that
	// rewrites Host to an upstream name, and an SSR/BFF that forwards the
	// browser's request verbatim — httputil.ReverseProxy forwards Origin —
	// together with the session cookie. Host-only comparison again, for the
	// same reason as (f).
	if originHost != "" && originHost == hostOfOrigin(cfg.SelfOrigin) {
		return false
	}

	// (g) The declared cross-origin callers. Defaults to the CORS allow-list,
	// which carries the cross-domain-SPA population across this change with
	// ZERO new config: such an SPA must already be listed there, because a
	// credentialed XHR cannot read its response otherwise.
	if origin != "" && crossSiteOriginAllowed(cfg, origin) {
		return false
	}

	// (h) A browser told us this is cross-site, the origin is not one we
	// serve, and the request is trying to change state on an ambient cookie.
	return true
}

// RefuseCrossSiteWrite is the method form, for the four gates in this package
// (which hold the Middleware, not a bare Config) and for consumers holding a
// *Middleware handle.
func (m *Middleware) RefuseCrossSiteWrite(r *http.Request, au *domain.AuthUser) bool {
	return RefuseCrossSiteWrite(m.cfg, r, au)
}

// crossSiteOriginAllowed reports whether origin is on the effective
// cross-site-write allow-list (exact, case-insensitive, host-and-port — the
// same comparison CORS makes).
//
// It deliberately does NOT call matchOrigin: that function returns true for a
// literal "*" unconditionally, which is right for CORS and wrong here.
// yauthcfg already REJECTS `allowed_origins: ["*"]` together with
// `allow_credentials: true`, so a "*" that reaches this guard by inheritance
// from CORS came from an operator who explicitly DECLINED credentialed
// cross-origin access. Reading that as consent to cross-site credentialed
// WRITES inverts their stated intent — and allow_credentials=false is no
// protection at all here, because a CSRF write never needs to read the
// response.
//
// A "*" is honoured only when the operator aimed it at this guard
// (server.cross_site_writes.origins, set explicitly) or when it came from a
// CORS policy that DID grant credentialed cross-origin access.
func crossSiteOriginAllowed(cfg Config, origin string) bool {
	wildcardIsConsent := !cfg.CrossSiteWriteOriginsFromCORS || cfg.CORSAllowCredentials
	for _, o := range cfg.CrossSiteWriteOrigins {
		o = strings.TrimSpace(o)
		if o == "*" {
			if wildcardIsConsent {
				return true
			}
			continue
		}
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

// hostOfOrigin returns the lowercased host[:port] of a serialized origin, or
// "" when there is none to compare. The empty result is what makes the
// opaque origin ("null", which is what a sandboxed iframe or a
// data:/file: document sends) fall through to the allow-list rather than
// accidentally matching a host.
func hostOfOrigin(origin string) string {
	if origin == "" {
		return ""
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}
