package mcpauth_test

// Item-1 (CSRF) + design-gap (RequireScope) + Item-10 (PublicURL) tests.
//
// The CSRF cases drive Guard end to end through testServer: a session cookie
// plus a cross-site POST must 403, while the same request same-origin, safe
// method, bearer-authed, or headerless (curl/API clients) must pass. The
// RequireScope cases pin the enforced path — delegated principals missing a
// scope — and document the gap: non-delegated credentials satisfy every
// scope by design (domain.Principal.HasScope).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/mcpauth"
	"github.com/yackey-labs/yauth/middleware"
)

func doGuardReq(t *testing.T, srv string, method string, cookie string, headers map[string]string, body string) *http.Response {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req, err := http.NewRequest(method, srv+"/mcp", rdr) //nolint:noctx
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s /mcp: %v", method, err)
	}
	resp.Body.Close() //nolint:errcheck
	return resp
}

func TestGuard_CSRF_CrossOriginCookiePOSTRefused(t *testing.T) {
	srv, repo := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	cookie := seedSession(t, repo)

	resp := doGuardReq(t, srv.URL, http.MethodPost, cookie,
		map[string]string{"Origin": "https://evil.test", "Content-Type": "application/json"}, `{"x":1}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin cookie POST: status = %d, want 403", resp.StatusCode)
	}
}

func TestGuard_CSRF_SameOriginCookiePOSTPasses(t *testing.T) {
	srv, repo := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	cookie := seedSession(t, repo)

	resp := doGuardReq(t, srv.URL, http.MethodPost, cookie,
		map[string]string{"Origin": srv.URL, "Content-Type": "application/json"}, `{"x":1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-origin cookie POST: status = %d, want 200", resp.StatusCode)
	}
}

func TestGuard_CSRF_BearerCrossOriginPasses(t *testing.T) {
	srv, repo := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	token := mintBearerToken(t, srv, repo)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"x":1}`)) //nolint:noctx
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://evil.test")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer cross-origin POST: status = %d, want 200 (machine credentials are not ambient)", resp.StatusCode)
	}
}

func TestGuard_CSRF_NoOriginCookiePOSTPasses(t *testing.T) {
	// curl / server-side API clients send neither Sec-Fetch-Site nor Origin —
	// no browser is driving, so there is no ambient cookie to steal.
	srv, repo := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	cookie := seedSession(t, repo)

	resp := doGuardReq(t, srv.URL, http.MethodPost, cookie, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("headerless cookie POST: status = %d, want 200", resp.StatusCode)
	}
}

func TestGuard_CSRF_CrossOriginCookieGETPasses(t *testing.T) {
	// Safe methods are reads; refusing them breaks dashboards for zero gain.
	srv, repo := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	cookie := seedSession(t, repo)

	resp := doGuardReq(t, srv.URL, http.MethodGet, cookie,
		map[string]string{"Origin": "https://evil.test"}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cross-origin cookie GET: status = %d, want 200 (safe method)", resp.StatusCode)
	}
}

func TestGuard_CSRF_SecFetchSiteSameOriginPasses(t *testing.T) {
	srv, repo := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	cookie := seedSession(t, repo)

	resp := doGuardReq(t, srv.URL, http.MethodPost, cookie,
		map[string]string{"Sec-Fetch-Site": "same-origin", "Content-Type": "application/json"}, `{"x":1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Sec-Fetch-Site: same-origin POST: status = %d, want 200", resp.StatusCode)
	}
}

// --- RequireScope ---

func scopeHandler(t *testing.T, scopes ...string) http.Handler {
	t.Helper()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mcpauth.RequireScope(scopes...)(inner)
}

func reqWithAuthUser(scopes ...string) *http.Request {
	uid := "u1"
	au := &domain.AuthUser{
		User:      domain.User{ID: uid},
		Principal: domain.NewDelegatedUserPrincipal(uid, []string{"rp.test"}, scopes),
	}
	r := httptest.NewRequest(http.MethodPost, "https://idp.test/mcp", nil)
	return r.WithContext(middleware.WithAuthUser(r.Context(), au))
}

func TestRequireScope_DelegatedMissingScope403(t *testing.T) {
	h := scopeHandler(t, "mcp:invoke")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithAuthUser("other:scope"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `error="insufficient_scope"`) {
		t.Errorf("WWW-Authenticate = %q, want insufficient_scope challenge", got)
	}
}

func TestRequireScope_DelegatedWithScopePasses(t *testing.T) {
	h := scopeHandler(t, "mcp:invoke")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithAuthUser("mcp:invoke"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRequireScope_NonDelegatedPassesByDesign(t *testing.T) {
	// The documented gap: a non-delegated credential (cookie, first-party
	// bearer, API key) acts with the user's full authority — HasScope is
	// true for every scope. This pins that behaviour so a future change
	// that silently narrows cookies fails loudly here first.
	au := &domain.AuthUser{User: domain.User{ID: "u1"}} // zero Principal: non-delegated
	r := httptest.NewRequest(http.MethodPost, "https://idp.test/mcp", nil)
	r = r.WithContext(middleware.WithAuthUser(r.Context(), au))
	rec := httptest.NewRecorder()
	scopeHandler(t, "mcp:invoke").ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (non-delegated callers are unrestricted)", rec.Code)
	}
}

func TestRequireScope_NoAuthUser401WithDiscovery(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://idp.test/mcp", nil)
	rec := httptest.NewRecorder()
	scopeHandler(t, "mcp:invoke").ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "oauth-protected-resource") {
		t.Errorf("WWW-Authenticate = %q, want RFC 9728 discovery challenge", got)
	}
}

// --- Item 10: PublicURL ---

func TestMount_PublicURLImmuneToHostSpoof(t *testing.T) {
	cfg := mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize", PublicURL: "https://mcp.example.com"}
	srv, _ := testServer(t, cfg)

	// Attacker-controlled Host header must not leak into the documents when
	// PublicURL is set.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/.well-known/oauth-protected-resource", nil) //nolint:noctx
	req.Host = "evil.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc["resource"] != "https://mcp.example.com" {
		t.Errorf("resource = %v, want PublicURL origin (Host spoof leaked)", doc["resource"])
	}
	as, _ := doc["authorization_servers"].([]any)
	if len(as) != 1 || as[0] != "https://mcp.example.com/api/auth" {
		t.Errorf("authorization_servers = %v, want [PublicURL+base]", doc["authorization_servers"])
	}
}
