package yauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// writeRSAKeys is shared with from_config_wiring_test.go (same package).

// buildIDP builds a full single-tenant IdP (asymjwt + oauth2server + oidc) so
// the discovery doc carries authorization/token endpoints, using issuer and
// basePath as supplied.
func buildIDP(t *testing.T, issuer, basePath string) *yauth.YAuth {
	t.Helper()
	r := memrepo.New()
	dir := t.TempDir()
	priv, pub := writeRSAKeys(t, dir)
	asym, err := asymjwt.New(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPath: priv, PublicKeyPath: pub, KID: "test-kid",
	})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(asym).
		WithPlugin(oauth2server.New(oauth2server.Config{Issuer: issuer, BasePath: basePath})).
		WithPlugin(oidc.New(oidc.Config{Issuer: issuer, BasePath: basePath})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	return ya
}

// getJSON fetches url, asserts a 200, and decodes the JSON body into a map.
func mountGetJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	res, err := http.Get(url) //nolint:gosec // test-controlled URL
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", url, res.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return doc
}

// TestMount_Defaults covers the zero-MountOptions layout: discovery is served
// both at the root and under the prefix (identical docs), the token endpoint
// routes under the prefix, and the bare prefix redirects to prefix/.
func TestMount_Defaults(t *testing.T) {
	ya := buildIDP(t, "http://idp.test", "/api/auth")
	mux := http.NewServeMux()
	ya.Mount(mux, yauth.MountOptions{}) // APIPrefix unset, DiscoveryAtRoot nil
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rootDoc := mountGetJSON(t, srv.URL+"/.well-known/openid-configuration")
	prefixDoc := mountGetJSON(t, srv.URL+"/api/auth/.well-known/openid-configuration")

	rootJSON, _ := json.Marshal(rootDoc)
	prefixJSON, _ := json.Marshal(prefixDoc)
	if string(rootJSON) != string(prefixJSON) {
		t.Fatalf("root and prefix discovery docs differ:\n root=%s\n prefix=%s", rootJSON, prefixJSON)
	}

	// The token endpoint is POST-only; a GET that ROUTES to it returns 405
	// (method not allowed), not 404 (no route). 404 would mean the API did
	// not mount under the prefix.
	res, err := http.Get(srv.URL + "/api/auth/oauth/token") //nolint:gosec // test URL
	if err != nil {
		t.Fatalf("GET token: %v", err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		t.Fatalf("GET /api/auth/oauth/token returned 404 — token endpoint not routed under prefix")
	}

	// Bare prefix must redirect to prefix/ — assert the redirect itself, not
	// the followed response, by disabling redirect-following.
	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	rres, err := noRedirect.Get(srv.URL + "/api/auth")
	if err != nil {
		t.Fatalf("GET bare prefix: %v", err)
	}
	rres.Body.Close()
	if rres.StatusCode < 300 || rres.StatusCode >= 400 {
		t.Fatalf("GET /api/auth: status %d, want a 3xx redirect", rres.StatusCode)
	}
	if loc := rres.Header.Get("Location"); loc != "/api/auth/" {
		t.Fatalf("GET /api/auth: Location %q, want %q", loc, "/api/auth/")
	}
}

// TestMount_ValueFlow asserts the issuer-as-identity contract: the root
// discovery doc's issuer is the bare origin, while the endpoint URLs all sit
// under the API prefix.
func TestMount_ValueFlow(t *testing.T) {
	const issuer = "https://idp.example.com"
	ya := buildIDP(t, issuer, "/api/auth")
	mux := http.NewServeMux()
	ya.Mount(mux, yauth.MountOptions{})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	doc := mountGetJSON(t, srv.URL+"/.well-known/openid-configuration")

	if doc["issuer"] != issuer {
		t.Fatalf("issuer = %v, want %q", doc["issuer"], issuer)
	}
	wantBase := issuer + "/api/auth/"
	for _, field := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		v, ok := doc[field].(string)
		if !ok {
			t.Fatalf("%s missing or not a string: %v", field, doc[field])
		}
		if !strings.HasPrefix(v, wantBase) {
			t.Fatalf("%s = %q, want prefix %q", field, v, wantBase)
		}
	}
}

// TestMount_DiscoveryAtRootFalse: with DiscoveryAtRoot explicitly false, the
// root .well-known is NOT served (404) but the prefixed one still works.
func TestMount_DiscoveryAtRootFalse(t *testing.T) {
	ya := buildIDP(t, "http://idp.test", "/api/auth")
	mux := http.NewServeMux()
	off := false
	ya.Mount(mux, yauth.MountOptions{DiscoveryAtRoot: &off})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	res, err := http.Get(srv.URL + "/.well-known/openid-configuration") //nolint:gosec // test URL
	if err != nil {
		t.Fatalf("GET root discovery: %v", err)
	}
	io.Copy(io.Discard, res.Body) //nolint:errcheck
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("root discovery status = %d, want 404 (discovery should be prefix-only)", res.StatusCode)
	}

	// Still available under the prefix.
	_ = mountGetJSON(t, srv.URL+"/api/auth/.well-known/openid-configuration")
}
