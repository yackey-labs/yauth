// Unit table for the cross-site state-change guard.
//
// What was broken: every cookie-authenticated route authorized on the ambient
// session cookie alone. ResolveAuth read the cookie, requireAuth /
// RequireAdmin (and their huma twins) checked role and must_change_password,
// and the handler ran — nothing ever asked WHERE the request came from. A page
// an admin merely had open could POST /admin/users/{id}/suspend (bodyless, so
// a plain auto-submitting form reached it) and the write landed. The
// end-to-end proof of that drives the real router in the root package's
// security_cross_site_write_test.go; this file pins the predicate underneath
// it.
//
// Everything here is about ORDER. RefuseCrossSiteWrite is a sequence of early
// returns, and each one exists to keep a specific legitimate caller working —
// a machine credential, curl, an old browser posting same-origin, an SSR
// proxy, a declared cross-domain SPA. Reordering them, or letting one swallow
// another, is how this guard would quietly start refusing first-party traffic
// (or quietly stop refusing attackers). Every row asserts the boolean, so the
// order is locked, not merely the outcome of the common case.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/domain"
)

// xsHuman is the ambient-credential caller the guard is about: a cookie
// session. Empty Method is treated as cookie throughout the middleware, so it
// gets its own row below.
func xsHuman() *domain.AuthUser {
	return &domain.AuthUser{Method: domain.AuthMethodCookie}
}

func xsMachine(method string) *domain.AuthUser {
	return &domain.AuthUser{Method: method}
}

func TestRefuseCrossSiteWrite(t *testing.T) {
	// Every row is a POST to this host unless it says otherwise, because the
	// interesting question is never the method — it is which signal decides.
	const host = "auth.example.com"

	cases := []struct {
		name    string
		cfg     Config
		method  string
		host    string
		headers map[string]string
		au      *domain.AuthUser
		want    bool
		why     string
	}{
		// --- (a) kill switch, ahead of everything ---
		{
			name:    "a: kill switch beats every other signal",
			cfg:     Config{AllowCrossSiteWrites: true},
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
			why:     "server.cross_site_writes.allow: true is the operator's 2am escape hatch; nothing may outrank it",
		},

		// --- (b) machine credentials are not ambient ---
		{
			name:    "b: bearer is exempt",
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsMachine(domain.AuthMethodBearer),
			want:    false,
			why:     "a cross-site page cannot make a browser attach an Authorization header",
		},
		{
			name:    "b: user-scoped api key is exempt",
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsMachine(domain.AuthMethodAPIKey),
			want:    false,
			why:     "X-Api-Key is not ambient; setting it forces a preflight this server refuses",
		},
		{
			name:    "b: service account is exempt",
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsMachine(domain.AuthMethodServiceAccount),
			want:    false,
			why:     "the machine/human split lives in isMachineMethod and must not be re-derived here",
		},
		{
			name:    "b: nil principal is exempt",
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      nil,
			want:    false,
			why:     "no resolved identity means no ambient authority to abuse; the 401 belongs to the caller, not this guard",
		},
		{
			name:    "b: empty method is a HUMAN, not a machine",
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsMachine(""),
			want:    true,
			why:     "the resolver treats an empty method as cookie; classifying it as machine would open the whole hole again",
		},

		// --- (c) safe methods ---
		{
			name:    "c: cross-site GET is allowed",
			method:  http.MethodGet,
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
			why:     "the response is unreadable cross-origin anyway; refusing reads breaks embedded dashboards",
		},
		{
			name:    "c: cross-site HEAD is allowed",
			method:  http.MethodHead,
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
		},
		{
			name:    "c: cross-site OPTIONS is allowed",
			method:  http.MethodOptions,
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
			why:     "a preflight must reach the CORS middleware, not a 403",
		},
		{
			name:    "c: DELETE is a state change like any other",
			method:  http.MethodDelete,
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    true,
		},

		// --- (d) Fetch Metadata ---
		{
			name:    "d: same-origin passes",
			headers: map[string]string{"Origin": "https://" + host, "Sec-Fetch-Site": "same-origin"},
			au:      xsHuman(),
			want:    false,
		},
		{
			name:    "d: same-site passes — the documented LIMIT",
			headers: map[string]string{"Origin": "https://console.example.com", "Sec-Fetch-Site": "same-site"},
			au:      xsHuman(),
			want:    false,
			why:     "a console on a sibling host is the common deployment; script on ANY sibling origin therefore still passes",
		},
		{
			name:    "d: none passes",
			headers: map[string]string{"Sec-Fetch-Site": "none"},
			au:      xsHuman(),
			want:    false,
			why:     "user-typed URL or bookmark",
		},
		{
			name:    "d: header matching is case-insensitive",
			headers: map[string]string{"Origin": "https://" + host, "Sec-Fetch-Site": "Same-Origin"},
			au:      xsHuman(),
			want:    false,
		},

		// --- (e) not a browser ---
		{
			name:   "e: neither header passes (curl, CI, server-side client)",
			au:     xsHuman(),
			want:   false,
			why:    "no shipping browser omits both on a cross-site write; failing these closed breaks every embedder's suite",
			method: http.MethodPost,
		},
		{
			name:    "e: Sec-Fetch-Site cross-site with NO Origin is still refused",
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    true,
			why:     "the browser stated it plainly; the absent Origin does not soften that",
		},

		// --- (f) Origin echoes the requested host ---
		{
			name:    "f: Origin host == r.Host passes (pre-Fetch-Metadata browser)",
			headers: map[string]string{"Origin": "https://" + host},
			au:      xsHuman(),
			want:    false,
		},
		{
			name:    "f: scheme is ignored, host is what matters",
			headers: map[string]string{"Origin": "http://" + host},
			au:      xsHuman(),
			want:    false,
			why:     "behind a TLS-terminating proxy r.TLS is nil and the scheme is unknowable here",
		},
		{
			name:    "f: host comparison is case-insensitive",
			headers: map[string]string{"Origin": "https://AUTH.EXAMPLE.COM"},
			au:      xsHuman(),
			want:    false,
		},
		{
			name:    "f: a different PORT is a different origin",
			headers: map[string]string{"Origin": "https://" + host + ":8443"},
			au:      xsHuman(),
			want:    true,
			why:     "host-and-port, as CORS compares; a co-tenant on another port is not us",
		},
		{
			name:    "f: a suffix of the host does not match",
			headers: map[string]string{"Origin": "https://evil-auth.example.com"},
			au:      xsHuman(),
			want:    true,
		},

		// --- (f2) Origin matches the deployment's own BaseURL ---
		{
			name:    "f2: Origin matching SelfOrigin passes even when r.Host differs",
			cfg:     Config{SelfOrigin: "https://auth.example.com"},
			host:    "yauth.internal.svc:8080",
			headers: map[string]string{"Origin": "https://auth.example.com", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
			why:     "a proxy that rewrites Host, and an SSR/BFF that forwards the browser's Origin with the cookie, are first-party",
		},
		{
			name:    "f2: SelfOrigin path and scheme are ignored, host compared",
			cfg:     Config{SelfOrigin: "http://auth.example.com/api/auth"},
			host:    "yauth.internal.svc:8080",
			headers: map[string]string{"Origin": "https://auth.example.com"},
			au:      xsHuman(),
			want:    false,
		},
		{
			name:    "f2: an unset SelfOrigin matches nothing",
			host:    "yauth.internal.svc:8080",
			headers: map[string]string{"Origin": "https://auth.example.com"},
			au:      xsHuman(),
			want:    true,
			why:     "an empty SelfOrigin must not become a wildcard that matches an opaque origin",
		},

		// --- (g) the allow-list ---
		{
			name:    "g: a listed origin passes",
			cfg:     Config{CrossSiteWriteOrigins: []string{"https://app.example.com"}},
			headers: map[string]string{"Origin": "https://app.example.com", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
		},
		{
			name:    "g: list matching is case-insensitive",
			cfg:     Config{CrossSiteWriteOrigins: []string{"https://APP.example.com"}},
			headers: map[string]string{"Origin": "https://app.example.com", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
		},
		{
			name:    "g: an unlisted origin is refused",
			cfg:     Config{CrossSiteWriteOrigins: []string{"https://app.example.com"}},
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    true,
		},
		{
			name: `g: "*" INHERITED from CORS without credentials is NOT consent`,
			cfg: Config{
				CrossSiteWriteOrigins:         []string{"*"},
				CrossSiteWriteOriginsFromCORS: true,
				CORSAllowCredentials:          false,
			},
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    true,
			why:     `yauthcfg rejects "*" + allow_credentials, so this operator explicitly DECLINED credentialed cross-origin access`,
		},
		{
			name: `g: "*" inherited from a CREDENTIALED CORS policy is consent`,
			cfg: Config{
				CrossSiteWriteOrigins:         []string{"*"},
				CrossSiteWriteOriginsFromCORS: true,
				CORSAllowCredentials:          true,
			},
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
			why:     "only reachable when a Go caller assembles CORSConfig by hand; they already granted every origin credentialed access",
		},
		{
			name: `g: "*" set on cross_site_writes.origins is consent`,
			cfg: Config{
				CrossSiteWriteOrigins:         []string{"*"},
				CrossSiteWriteOriginsFromCORS: false,
			},
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
			why:     "aimed at THIS guard on purpose; the escape hatch the 403 advertises has to work",
		},
		{
			name: `g: a non-wildcard entry still matches under an inherited list`,
			cfg: Config{
				CrossSiteWriteOrigins:         []string{"*", "https://app.example.com"},
				CrossSiteWriteOriginsFromCORS: true,
			},
			headers: map[string]string{"Origin": "https://app.example.com", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    false,
			why:     "the ignored wildcard must not abort the scan before the real entries",
		},
		{
			name:    "g: the opaque origin is refused",
			cfg:     Config{CrossSiteWriteOrigins: []string{"https://app.example.com"}},
			headers: map[string]string{"Origin": "null", "Sec-Fetch-Site": "cross-site"},
			au:      xsHuman(),
			want:    true,
			why:     `a sandboxed iframe / data: document sends Origin: null; it must not match a host and must not be treated as absent`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = http.MethodPost
			}
			h := tc.host
			if h == "" {
				h = host
			}
			r := httptest.NewRequest(method, "https://"+h+"/admin/users/u1/suspend", nil)
			r.Host = h
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := RefuseCrossSiteWrite(tc.cfg, r, tc.au); got != tc.want {
				t.Errorf("RefuseCrossSiteWrite = %v, want %v\nwhy this row exists: %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestRefuseCrossSiteWrite_DetailNamesBothKnobs: the refusal body is the only
// thing an operator holding a support ticket has. It must name both escape
// hatches verbatim, and the root-package end-to-end suite asserts these exact
// substrings come back over the wire.
func TestRefuseCrossSiteWrite_DetailNamesBothKnobs(t *testing.T) {
	for _, want := range []string{"cross_site_writes.origins", "cross_site_writes.allow"} {
		if !strings.Contains(CrossSiteWriteDetail, want) {
			t.Errorf("CrossSiteWriteDetail does not name %q: %q", want, CrossSiteWriteDetail)
		}
	}
}
