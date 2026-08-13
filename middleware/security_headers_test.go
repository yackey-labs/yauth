// Unit-level guards for middleware.SecurityHeaders.
//
// What was broken: YAuth.Router() wrapped only CORS, tracing and the
// trusted-proxy resolver, so every response yauth emitted — including the
// browser-facing, state-changing text/html page GET /oauth/end_session renders
// — went out with no Content-Security-Policy, no X-Frame-Options, no nosniff
// and no Referrer-Policy. The router-level proof of the fix lives in the root
// package (security_headers_test.go, driven through the real pentest harness);
// what that test CANNOT reach are the three switches on this middleware, each
// of which is a way for the fix to be quietly wrong:
//
//   - Strict-Transport-Security has two independent guards (an operator opt-in
//     AND r.TLS != nil). The root test only proves it is absent over plain
//     HTTP, which a middleware that never emits HSTS at all would also pass.
//     TestSecurityHeaders_HSTS is the POSITIVE CONTROL for that: it pins the
//     one combination that must emit the header, alongside the two that must
//     not. r.TLS is the only signal used on purpose — TrustedProxiesMiddleware
//     resolves the client IP, not the request scheme, so there is no vetted
//     X-Forwarded-Proto to consult here.
//   - Disabled must actually disable, and its ZERO VALUE must enable. That
//     polarity is load-bearing: yauth.New stores the YAuthConfig it is handed
//     verbatim with no defaulting pass, so an `Enabled bool` would read false
//     for every Go-builder embedder and the fix would ship doing nothing.
//   - The values are written with Header().Set, never Header().Add.
//     plugins/ssosaml already emits X-Content-Type-Options through a huma
//     output struct on two error shapes; Add there would produce a duplicate
//     header on the wire.
package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// secHdrEchoHandler is the downstream handler under test: a plain 200 that
// writes nothing to the header map, so anything observed on the recorder came
// from the middleware.
func secHdrEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func secHdrServe(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// secHdrTLSRequest is a request that arrived over TLS, which is the only fact this
// middleware is willing to treat as "the connection was encrypted".
func secHdrTLSRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://idp.test/config", nil)
	r.TLS = &tls.ConnectionState{}
	return r
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	const value = "max-age=31536000; includeSubDomains"

	t.Run("emitted over TLS when the operator opted in", func(t *testing.T) {
		// POSITIVE CONTROL for the whole HSTS branch: without this, a
		// middleware that never emits Strict-Transport-Security would
		// satisfy every other HSTS assertion in the suite.
		rec := secHdrServe(SecurityHeaders(SecurityHeadersConfig{HSTS: value})(secHdrEchoHandler()), secHdrTLSRequest())
		if got := rec.Header().Get("Strict-Transport-Security"); got != value {
			t.Errorf("Strict-Transport-Security = %q, want %q", got, value)
		}
	})

	t.Run("absent over TLS when the operator did not opt in", func(t *testing.T) {
		rec := secHdrServe(SecurityHeaders(SecurityHeadersConfig{})(secHdrEchoHandler()), secHdrTLSRequest())
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("Strict-Transport-Security = %q, want it absent — HSTS must never be a default", got)
		}
	})

	t.Run("absent on plain HTTP even when opted in", func(t *testing.T) {
		// A plain-HTTP listener is a local development stack. An HSTS
		// header here pins the developer's browser to https for the whole
		// max-age and can strand a domain — worse than the finding.
		r := httptest.NewRequest(http.MethodGet, "http://idp.test/config", nil)
		rec := secHdrServe(SecurityHeaders(SecurityHeadersConfig{HSTS: value})(secHdrEchoHandler()), r)
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("Strict-Transport-Security = %q on a plain-HTTP request, want it absent", got)
		}
	})

	t.Run("X-Forwarded-Proto is not a scheme signal", func(t *testing.T) {
		// TrustedProxiesMiddleware vets the client IP, not the scheme, so
		// nothing has vouched for this header by the time we see it.
		r := httptest.NewRequest(http.MethodGet, "http://idp.test/config", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		rec := secHdrServe(SecurityHeaders(SecurityHeadersConfig{HSTS: value})(secHdrEchoHandler()), r)
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("Strict-Transport-Security = %q, want it absent — X-Forwarded-Proto must not enable HSTS", got)
		}
	})
}

func TestSecurityHeaders_ZeroValueEnablesAndDisabledDisables(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://idp.test/config", nil)

	// POSITIVE CONTROL: the zero config — what every embedder that never
	// mentions SecurityHeaders ends up with — must emit the full set.
	rec := secHdrServe(SecurityHeaders(SecurityHeadersConfig{})(secHdrEchoHandler()), r)
	for name, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": defaultCSP,
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("zero config: %s = %q, want %q", name, got, want)
		}
	}

	rec = secHdrServe(SecurityHeaders(SecurityHeadersConfig{Disabled: true})(secHdrEchoHandler()),
		httptest.NewRequest(http.MethodGet, "http://idp.test/config", nil))
	for _, name := range []string{"X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Content-Security-Policy"} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("Disabled: %s = %q, want it absent", name, got)
		}
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("Disabled: handler was not passed through: %d %q", rec.Code, rec.Body.String())
	}
}

func TestSecurityHeaders_OverrideAndNoDuplicates(t *testing.T) {
	// A downstream handler that emits its own nosniff — the shape
	// plugins/ssosaml's flowOutput produces on its 404/error responses. The
	// wire must carry exactly ONE value, which is why the middleware uses
	// Header().Set and not Header().Add.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusNotFound)
	})
	rec := secHdrServe(SecurityHeaders(SecurityHeadersConfig{})(inner),
		httptest.NewRequest(http.MethodGet, "http://idp.test/saml/nope", nil))
	if vals := rec.Header().Values("X-Content-Type-Options"); len(vals) != 1 {
		t.Errorf("X-Content-Type-Options emitted %d times (%v), want exactly 1", len(vals), vals)
	}

	// An operator override replaces one default and leaves the rest alone.
	const frameOpt = "SAMEORIGIN"
	rec = secHdrServe(SecurityHeaders(SecurityHeadersConfig{
		Override: map[string]string{"X-Frame-Options": frameOpt},
	})(secHdrEchoHandler()), httptest.NewRequest(http.MethodGet, "http://idp.test/config", nil))
	if got := rec.Header().Get("X-Frame-Options"); got != frameOpt {
		t.Errorf("X-Frame-Options = %q, want the override %q", got, frameOpt)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != defaultCSP {
		t.Errorf("Content-Security-Policy = %q, want the untouched default %q", got, defaultCSP)
	}

	// An embedding application that already set the header still wins over
	// BOTH the default and the operator override — check-then-set applies
	// to the resolved value, not just to the built-in one.
	const embedder = "frame-ancestors https://console.example.test"
	outer := SecurityHeaders(SecurityHeadersConfig{
		Override: map[string]string{"Content-Security-Policy": "default-src 'self'"},
	})(secHdrEchoHandler())
	rec = httptest.NewRecorder()
	rec.Header().Set("Content-Security-Policy", embedder)
	outer.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://idp.test/config", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != embedder {
		t.Errorf("embedder's CSP = %q, want it preserved as %q", got, embedder)
	}
}
