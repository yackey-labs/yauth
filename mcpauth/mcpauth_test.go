package mcpauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/mcpauth"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// testServer builds a yauth with the oauth2server plugin mounted under
// /api/auth and mcpauth wired onto the root mux, mirroring a real MCP server.
func testServer(t *testing.T, cfg mcpauth.Config) (*httptest.Server, *memrepo.Repo) {
	t.Helper()
	r := memrepo.New()
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:      "http://idp.test",
			BasePath:    cfg.AuthBasePath,
			AccessTTL:   5 * time.Minute,
			AuthCodeTTL: time.Minute,
		})).
		WithPlugin(oidc.New(oidc.Config{Issuer: "http://idp.test", BasePath: cfg.AuthBasePath})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	mcpauth.Mount(mux, ya, cfg)
	mux.Handle("/mcp", mcpauth.Guard(ya, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			t.Error("Guard let request through without injecting AuthUser")
		}
		w.WriteHeader(http.StatusOK)
	})))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// seedSession creates a user and an active session, returning the raw
// yauth_session cookie value the cookie resolver validates.
func seedSession(t *testing.T, r *memrepo.Repo) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	dn := "alice"
	u, err := r.CreateUser(ctx, domain.NewUser{
		ID:            uuid.NewString(),
		Email:         "alice@idp.test",
		DisplayName:   &dn,
		EmailVerified: true,
		Role:          "user",
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	raw, _, err := auth.IssueSession(ctx, r, u.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return raw
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc
}

func TestProtectedResourceMetadata(t *testing.T) {
	cfg := mcpauth.Config{
		AuthBasePath: "/api/auth",
		ConsentPath:  "/authorize",
		ResourceName: "test-mcp",
		Scopes: []mcpauth.Scope{
			{Name: "query:read", Description: "Run read-only queries"},
			{Name: "alerts:write", Description: "Manage alerts"},
		},
	}
	srv, _ := testServer(t, cfg)

	status, doc := getJSON(t, srv.URL+"/.well-known/oauth-protected-resource")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if doc["resource"] != srv.URL {
		t.Errorf("resource = %v, want %s", doc["resource"], srv.URL)
	}
	as, _ := doc["authorization_servers"].([]any)
	if len(as) != 1 || as[0] != srv.URL+"/api/auth" {
		t.Errorf("authorization_servers = %v, want [%s/api/auth]", doc["authorization_servers"], srv.URL)
	}
	if doc["resource_name"] != "test-mcp" {
		t.Errorf("resource_name = %v", doc["resource_name"])
	}
	scopes, _ := doc["scopes_supported"].([]any)
	if len(scopes) != 2 || scopes[0] != "query:read" || scopes[1] != "alerts:write" {
		t.Errorf("scopes_supported = %v, want app catalog", doc["scopes_supported"])
	}
}

func TestAuthServerMetadataPatched(t *testing.T) {
	cfg := mcpauth.Config{
		AuthBasePath: "/api/auth",
		ConsentPath:  "/authorize",
		Scopes:       []mcpauth.Scope{{Name: "query:read", Description: "x"}},
	}
	srv, _ := testServer(t, cfg)

	status, doc := getJSON(t, srv.URL+"/.well-known/oauth-authorization-server")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	// authorization_endpoint must point at the SPA consent route, not yauth's
	// JSON /oauth/authorize endpoint.
	if got := doc["authorization_endpoint"]; got != srv.URL+"/authorize" {
		t.Errorf("authorization_endpoint = %v, want %s/authorize", got, srv.URL)
	}
	// token_endpoint comes straight from yauth and proves we proxied a real doc.
	if got, _ := doc["token_endpoint"].(string); got == "" {
		t.Errorf("token_endpoint missing; metadata was not proxied from yauth")
	}
	// scopes_supported is overridden with the app catalog.
	scopes, _ := doc["scopes_supported"].([]any)
	if len(scopes) != 1 || scopes[0] != "query:read" {
		t.Errorf("scopes_supported = %v, want [query:read]", doc["scopes_supported"])
	}
}

func TestAuthServerMetadataPathSuffixed(t *testing.T) {
	cfg := mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"}
	srv, _ := testServer(t, cfg)

	// RFC 8414 §3.1 path-insertion form.
	status, doc := getJSON(t, srv.URL+"/.well-known/oauth-authorization-server/api/auth")
	if status != http.StatusOK {
		t.Fatalf("path-suffixed status = %d, want 200", status)
	}
	if got := doc["authorization_endpoint"]; got != srv.URL+"/authorize" {
		t.Errorf("path-suffixed authorization_endpoint = %v", got)
	}
}

func TestGuardUnauthorized(t *testing.T) {
	srv, _ := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})

	resp, err := http.Get(srv.URL + "/mcp") //nolint:noctx
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	want := `Bearer resource_metadata="` + srv.URL + `/.well-known/oauth-protected-resource"`
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (not text/plain)", ct)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Errorf("body is not JSON: %v", err)
	}
	if doc["error"] != "unauthorized" {
		t.Errorf("error = %v, want unauthorized", doc["error"])
	}
}

func TestGuardAuthorizedInjectsUser(t *testing.T) {
	srv, repo := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	cookie := seedSession(t, repo)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp", nil) //nolint:noctx
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// 200 proves Guard authenticated the session; the guarded handler (in
	// testServer) fails the test if AuthUserFromContext came back empty, so a
	// 200 here also proves the AuthUser was injected for downstream handlers.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (Guard rejected a valid session)", resp.StatusCode)
	}
}

func TestOpenIDConfigurationProxied(t *testing.T) {
	srv, _ := testServer(t, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	// The root alias must proxy yauth's OIDC discovery doc (the oidc plugin
	// serves it under /api/auth; MCP/OIDC clients probe root).
	status, doc := getJSON(t, srv.URL+"/.well-known/openid-configuration")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (proxy not wired)", status)
	}
	if got, _ := doc["issuer"].(string); got == "" {
		t.Errorf("issuer missing; discovery doc was not proxied from yauth")
	}
	// authorization_endpoint must be patched to the SPA consent route (same as the
	// AS metadata) so OIDC relying parties (e.g. ssooidc) drive the consent UI
	// instead of hitting yauth's JSON /oauth/authorize.
	if got := doc["authorization_endpoint"]; got != srv.URL+"/authorize" {
		t.Errorf("openid-configuration authorization_endpoint = %v, want %s/authorize", got, srv.URL)
	}
}

// TestRootDiscoveryCORS verifies the root .well-known discovery aliases
// mcpauth.Mount registers honor yauth's configured CORS policy. Browser-based
// OIDC relying parties (SPAs) fetch openid-configuration cross-origin, so the
// response must carry Access-Control-Allow-Origin for an allowed origin — and
// must NOT for a disallowed one. Regression guard for the gap where these
// root handlers bypassed yauth's CORS middleware (the inner router's headers
// are dropped by the proxying recorder), blocking SPA logins.
func TestRootDiscoveryCORS(t *testing.T) {
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.CORS = yauth.CORSConfig{
		AllowedOrigins:   []string{"https://rp.test"},
		AllowCredentials: true,
	}
	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:      "http://idp.test",
			BasePath:    "/api/auth",
			AccessTTL:   5 * time.Minute,
			AuthCodeTTL: time.Minute,
		})).
		WithPlugin(oidc.New(oidc.Config{Issuer: "http://idp.test", BasePath: "/api/auth"})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	mcpauth.Mount(mux, ya, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	get := func(t *testing.T, path, origin string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil) //nolint:noctx
		req.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close() //nolint:errcheck
		return resp
	}

	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource",
	} {
		resp := get(t, path, "https://rp.test")
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://rp.test" {
			t.Errorf("%s: Access-Control-Allow-Origin = %q, want %q", path, got, "https://rp.test")
		}
	}

	// A disallowed origin must not receive ACAO.
	resp := get(t, "/.well-known/openid-configuration", "https://evil.test")
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin: Access-Control-Allow-Origin = %q, want empty", got)
	}
}
