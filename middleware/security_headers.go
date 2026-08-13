package middleware

import "net/http"

// defaultCSP is the Content-Security-Policy yauth's own responses carry.
//
// INVARIANT this policy depends on: the ONLY HTML that YAuth.Router() serves is
// oauth2server.writeLoggedOut's logout confirmation page, and that page is
// fully self-contained — no <script>, <style>, <link>, <img> or <form>, and no
// route renders an auto-submitting POST form (ssosaml uses the HTTP-Redirect
// binding for its AuthnRequest). Everything else the router emits is JSON.
// So `default-src 'none'` and `form-action 'none'` cost nothing today.
//
// If a future router-served document needs subresources, it must either narrow
// this constant or set its own Content-Security-Policy header before the
// response is written — the check-then-set rule below will then leave that
// value alone. NOTE that no Go test can catch a too-tight CSP: there is no
// browser in the loop, so the positive controls only prove the page still
// renders, not that a browser would execute it. That is why the policy lives
// in one named constant rather than being scattered across handlers.
const defaultCSP = "frame-ancestors 'none'; default-src 'none'; base-uri 'none'; form-action 'none'"

// SecurityHeadersConfig tunes [SecurityHeaders].
type SecurityHeadersConfig struct {
	// Disabled turns the middleware off entirely. The ZERO VALUE ENABLES
	// the headers, and that polarity is load-bearing: yauth.New stores the
	// YAuthConfig it is handed verbatim with no defaulting pass, so an
	// `Enabled bool` would read false for every Go-builder embedder and
	// this middleware would ship doing nothing. Opt-out only — do not
	// invert it.
	Disabled bool

	// HSTS is the Strict-Transport-Security value. EMPTY (the default)
	// means the header is never emitted. Even when set it is only sent on
	// a request that actually arrived over TLS — see [SecurityHeaders].
	HSTS string

	// Override replaces the default value of a single header, keyed by
	// canonical header name ("X-Frame-Options", "Content-Security-Policy",
	// "Referrer-Policy", "X-Content-Type-Options"). An override is still
	// subject to the check-then-set rule, so an embedding application that
	// already set the header still wins over the operator's override.
	// Names outside the four defaults are ignored: this middleware exists
	// to guarantee a floor, not to be a general header-injection surface.
	Override map[string]string
}

// SecurityHeaders returns middleware that gives every response yauth emits the
// four headers that have no reason ever to be absent from an auth API.
//
// What was broken: YAuth.Router() composed only CORS, tracing and the
// trusted-proxy wrapper, so EVERY response family went out bare — the public
// /config JSON the SPA fetches before login, the problem+json 401 from an
// unauthenticated /admin/users, the OIDC discovery document, and the text/html
// page GET /oauth/end_session renders. An OWASP ZAP run over 272 URLs flagged
// it across the whole surface and it was reproduced by hand with curl -D-.
//
// What an attacker got: /oauth/end_session is browser-facing, state-changing
// (it deletes the session row and clears the session cookie) and returns HTML.
// With neither X-Frame-Options nor a CSP frame-ancestors directive an attacker
// page frames it invisibly and clickjacks a victim into being logged out; the
// /oauth/authorize consent surface has the same shape. The default session
// cookie is SameSite=Lax, which already withholds the cookie from a
// cross-site framed subresource, so the sharpest version of that attack needs
// either same-site framing or a deployment configured CookieSameSite="None" —
// this is a real fix for those two, and defence in depth otherwise. nosniff
// and Referrer-Policy are the same shape of floor: an error body that a
// browser MIME-sniffs, and a Referer that carries whatever was in the URL.
//
// Why this guard and not a broader one:
//
//   - CHECK-THEN-SET, never unconditional Set. An embedding application that
//     wraps ya.Router() and has already set its own Content-Security-Policy
//     (a console that legitimately needs script-src, say) must keep its value;
//     yauth may only fill in what is missing. That wrapper is the reason this
//     rule is load-bearing.
//   - Header().Set, never Header().Add. plugins/ssosaml already emits
//     X-Content-Type-Options through a huma output struct on two error shapes;
//     Add would give those responses a duplicate header.
//   - HSTS keys on r.TLS ONLY. There is no vetted scheme signal available
//     here: TrustedProxiesMiddleware resolves the CLIENT IP, not the request
//     scheme, so X-Forwarded-Proto is attacker-writable as far as this layer
//     knows. And it stays off unless an operator opts in, because emitting it
//     unconditionally breaks plain-HTTP local development and can strand a
//     domain for a year — that failure is worse than the finding.
//
// Scope: this covers what YAuth.Router() serves. mcpauth is deliberately NOT
// covered — its proxyFetch drives the router into an httptest recorder and
// discards the recorded header map, so these headers can neither reach nor
// clobber mcpauth's own consent page, which keeps its own frame-ancestors
// policy.
func SecurityHeaders(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg.Disabled {
			return next
		}
		// Resolved once at wrap time, not per request. Ordered rather than
		// a map so the emitted set is deterministic.
		headers := []struct{ name, value string }{
			{"X-Content-Type-Options", "nosniff"},
			{"Referrer-Policy", "no-referrer"},
			{"X-Frame-Options", "DENY"},
			{"Content-Security-Policy", defaultCSP},
		}
		for i := range headers {
			if v := cfg.Override[headers[i].name]; v != "" {
				headers[i].value = v
			}
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set BEFORE next.ServeHTTP: a handler that has already called
			// WriteHeader has frozen the header map, and several yauth
			// responses (the CORS preflight 204, huma's problem+json
			// errors, the end_session HTML) write immediately.
			h := w.Header()
			for _, hdr := range headers {
				if h.Get(hdr.name) == "" {
					h.Set(hdr.name, hdr.value)
				}
			}
			// r.TLS is the only trustworthy statement that this request
			// arrived encrypted. No opt-in, or no TLS, means no header.
			if cfg.HSTS != "" && r.TLS != nil && h.Get("Strict-Transport-Security") == "" {
				h.Set("Strict-Transport-Security", cfg.HSTS)
			}
			next.ServeHTTP(w, r)
		})
	}
}
