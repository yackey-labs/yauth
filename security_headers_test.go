// Security response headers on the yauth router.
//
// What was broken: YAuth.Router() (yauth.go) composes exactly three wrappers —
// middleware.CORS (only when CORS.AllowedOrigins is non-empty),
// middleware.TraceMiddleware (only when telemetry is on) and
// middleware.TrustedProxiesMiddleware. There is no security-header wrapper
// anywhere in the repo, so EVERY response yauth emits — the public JSON
// config document the SPA fetches before login, the RFC 9457 problem+json 401
// an unauthenticated /admin/users call produces, the OIDC discovery document,
// and the text/html page GET /oauth/end_session renders — goes out with no
// Content-Security-Policy, no X-Frame-Options, no X-Content-Type-Options and
// no Referrer-Policy. An OWASP ZAP run over 272 URLs flagged this on the whole
// surface; it was then confirmed by hand with curl -D- against a live stack.
//
// Why it mattered: /oauth/end_session is browser-facing, state-changing (it
// deletes the session row and emits Set-Cookie: yauth_session=; Max-Age=0 —
// see oauth2server.handleEndSession) and returns HTML. With neither
// X-Frame-Options nor a CSP frame-ancestors directive, an attacker page can
// frame it invisibly and clickjack a victim into being logged out; the
// /oauth/authorize consent surface has the same shape. Separately, the absence
// of Referrer-Policy means a magic-link or password-reset landing page — whose
// token travels in the URL query string — leaks that live credential in the
// Referer header of any cross-origin subresource, and the absence of nosniff
// leaves even the error bodies open to MIME sniffing.
//
// These tests drive the real router through the shared pentest harness
// (newPentestHarness, pentest_test.go) mounted at /api/auth exactly as an
// embedder mounts it, plus the status and oidc plugins so the /config and
// /.well-known/openid-configuration response families the scanner walked are
// actually reachable.
//
// Each refusal-shaped assertion is paired with a POSITIVE CONTROL so a future
// "fix" cannot pass by breaking the endpoint outright:
//   - the end_session row asserts the logged-out HTML body AND the
//     session-clearing Set-Cookie are still there alongside the headers;
//   - the /config row asserts the JSON body still decodes;
//   - TestRouter_DoesNotClobberAnEmbeddersHeaders proves the wrapper yields to
//     a host application that already has its own policy, rather than winning
//     by force;
//   - TestRouter_HSTSOnlyOnPlainHTTPRequest is the guard against "fixing" this
//     by emitting Strict-Transport-Security unconditionally, which would break
//     plain-HTTP local development and can strand a domain.
package yauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/plugins/status"
)

// securityHeaderHarness boots the pentest stack with the two extra plugins the
// scanner's response families come from.
func securityHeaderHarness(t *testing.T, wrap func(http.Handler) http.Handler) *pentestHarness {
	t.Helper()
	return newPentestHarness(t, pentestOpts{
		disableLockout: true,
		extraPlugins: []plugin.Plugin{
			status.New(),
			oidc.New(oidc.Config{Issuer: "http://idp.test", BasePath: "/api/auth"}),
		},
		wrapRouter: wrap,
	})
}

// TestRouter_SetsSecurityHeadersOnEveryResponseFamily walks one representative
// request per response family ZAP reported on and asserts the four headers that
// have no reason ever to be absent from a yauth response.
func TestRouter_SetsSecurityHeadersOnEveryResponseFamily(t *testing.T) {
	h := securityHeaderHarness(t, nil)

	cases := []struct {
		name        string
		path        string
		wantStatus  int
		wantCTStart string
	}{
		{"public JSON 200", "/api/auth/config", http.StatusOK, "application/json"},
		{"OIDC discovery", "/api/auth/.well-known/openid-configuration", http.StatusOK, "application/json"},
		{"problem+json 401", "/api/auth/admin/users", http.StatusUnauthorized, "application/problem+json"},
		{"browser-facing HTML", "/api/auth/oauth/end_session", http.StatusOK, "text/html"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, h.url+tc.path, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// POSITIVE CONTROL: the route must still be the route. If a
			// future change makes the headers appear by 404ing or by
			// rewriting the content type, this fails first.
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("GET %s: status = %d, want %d (body %q)",
					tc.path, resp.StatusCode, tc.wantStatus, truncBody(body))
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, tc.wantCTStart) {
				t.Fatalf("GET %s: Content-Type = %q, want prefix %q", tc.path, ct, tc.wantCTStart)
			}

			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("GET %s: X-Content-Type-Options = %q, want %q — the response is MIME-sniffable",
					tc.path, got, "nosniff")
			}
			if got := resp.Header.Get("Referrer-Policy"); got == "" {
				t.Errorf("GET %s: Referrer-Policy is absent — a token in the landing URL leaks via Referer",
					tc.path)
			}
			if got := resp.Header.Get("X-Frame-Options"); got == "" {
				t.Errorf("GET %s: X-Frame-Options is absent — the response is framable", tc.path)
			}
			csp := resp.Header.Get("Content-Security-Policy")
			if !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Errorf("GET %s: Content-Security-Policy = %q, want it to contain %q — nothing stops an attacker framing this",
					tc.path, csp, "frame-ancestors 'none'")
			}
		})
	}
}

// TestEndSession_StillLogsOutWithHeaders is the positive control for the
// sharpest row above: adding headers must not disturb what end_session is for.
// It must still delete the session row and still send the clearing Set-Cookie,
// and its HTML body must still render (a CSP chosen for this page must not be
// so tight the page stops working).
func TestEndSession_StillLogsOutWithHeaders(t *testing.T) {
	h := securityHeaderHarness(t, nil)

	email := uniqueEmail("endsession")
	register(t, h, newJar(t), email, pentestStdPW)
	_, cookie := loginToCookie(t, h, email, pentestStdPW)
	if cookie == nil || cookie.Value == "" {
		t.Fatalf("login did not mint a %s cookie", h.cookieNm)
	}

	// The session exists before we log out — otherwise the "gone" assertion
	// below would pass vacuously.
	if _, err := h.repo.GetSessionByTokenHash(context.Background(), auth.HashToken(cookie.Value)); err != nil {
		t.Fatalf("session not resolvable before end_session: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, h.url+"/api/auth/oauth/end_session", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: h.cookieNm, Value: cookie.Value})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("end_session: status = %d, want 200 (body %q)", resp.StatusCode, truncBody(body))
	}
	// The session row is gone.
	if _, err := h.repo.GetSessionByTokenHash(context.Background(), auth.HashToken(cookie.Value)); err == nil {
		t.Fatalf("session still resolvable after end_session — logout was broken")
	}
	// The clearing Set-Cookie is still emitted.
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == h.cookieNm && c.Value == "" && c.MaxAge <= 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("end_session sent no clearing Set-Cookie for %q: %v", h.cookieNm, resp.Cookies())
	}
	// The page still renders.
	if !strings.Contains(string(body), "You have been logged out") {
		t.Fatalf("end_session body no longer renders the logged-out page: %q", truncBody(body))
	}

	// And it carries the anti-clickjacking headers.
	if resp.Header.Get("X-Frame-Options") == "" &&
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("end_session is framable: X-Frame-Options=%q CSP=%q",
			resp.Header.Get("X-Frame-Options"), resp.Header.Get("Content-Security-Policy"))
	}
}

// TestRouter_DoesNotClobberAnEmbeddersHeaders proves the header wrapper is
// additive. An embedding application that has already set its own
// Content-Security-Policy (a host app that legitimately needs script-src, say)
// must keep its value — yauth may only fill in what is missing. Without this
// guard the obvious implementation (unconditional Header().Set) silently
// overrides the host's policy.
func TestRouter_DoesNotClobberAnEmbeddersHeaders(t *testing.T) {
	const embedderCSP = "default-src 'self'; frame-ancestors https://console.example.test"
	const embedderReferrer = "strict-origin-when-cross-origin"

	h := securityHeaderHarness(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", embedderCSP)
			w.Header().Set("Referrer-Policy", embedderReferrer)
			next.ServeHTTP(w, r)
		})
	})

	resp, err := http.Get(h.url + "/api/auth/config")
	if err != nil {
		t.Fatalf("GET /config: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// POSITIVE CONTROL: the route still works through the embedder's wrapper.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /config: status = %d, want 200 (body %q)", resp.StatusCode, truncBody(body))
	}
	var cfg map[string]any
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("GET /config: body is not JSON (%v): %q", err, truncBody(body))
	}
	if _, ok := cfg["allow_signups"]; !ok {
		t.Fatalf("GET /config: expected allow_signups in body, got %v", cfg)
	}

	if got := resp.Header.Get("Content-Security-Policy"); got != embedderCSP {
		t.Errorf("embedder's Content-Security-Policy was clobbered: got %q, want %q", got, embedderCSP)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != embedderReferrer {
		t.Errorf("embedder's Referrer-Policy was clobbered: got %q, want %q", got, embedderReferrer)
	}
	// The header the embedder did NOT set must still be filled in by yauth.
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q — yauth must fill in headers the embedder omitted",
			got, "nosniff")
	}
}

// TestRouter_HSTSOnlyOnPlainHTTPRequest is the regression guard named in the
// risk section: Strict-Transport-Security must never be emitted on a request
// that did not arrive over TLS. httptest.NewServer is plain HTTP, which is
// exactly the shape of a local development stack — an HSTS header here would
// pin the developer's browser to https for a year.
func TestRouter_HSTSOnlyOnPlainHTTPRequest(t *testing.T) {
	h := securityHeaderHarness(t, nil)

	for _, path := range []string{"/api/auth/config", "/api/auth/oauth/end_session"} {
		resp, err := http.Get(h.url + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
			t.Errorf("GET %s over plain HTTP: Strict-Transport-Security = %q, want it absent", path, got)
		}
	}
}

func truncBody(b []byte) string {
	s := string(b)
	if len(s) > 240 {
		return s[:240] + "…"
	}
	return s
}
