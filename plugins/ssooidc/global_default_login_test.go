package ssooidc_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/ssooidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// ssooidcServerWithRepo builds a minimal RP and returns its repo for direct
// seeding (the admin surface is not needed here).
func ssooidcServerWithRepo(t *testing.T) (*httptest.Server, *memrepo.Repo) {
	t.Helper()
	r := memrepo.New()
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	ssoP, err := ssooidc.New(ssooidc.Config{EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(ssoP).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// seedGlobal seeds an active global (org-less) OIDC connection directly.
func seedGlobal(t *testing.T, r *memrepo.Repo, name string) string {
	t.Helper()
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	c, err := ssooidc.SeedConnection(t.Context(), r, key, ssooidc.SeedConnectionInput{
		OrganizationID:         "", // global
		Name:                   name,
		JitProvisioningEnabled: true,
		OIDC: ssooidc.OidcConnectionConfig{
			// Discovery is never fetched successfully — the test only asserts
			// connection RESOLUTION (anything but the selector 400).
			DiscoveryURL: "https://idp.invalid/.well-known/openid-configuration",
			ClientID:     "cid",
			ClientSecret: "secret",
			Scopes:       []string{"openid"},
		},
	})
	if err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	return c.ID
}

func bodyOf(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

// TestSsoLoginDefaultsToOnlyGlobalConnection: with exactly one active global
// connection, GET /sso/login with NO selector resolves it (no more 400) — the
// single-IdP org-less shape needs no connection_id plumbing. With two, the
// ambiguity is an explicit 400 mentioning connection_id.
func TestSsoLoginDefaultsToOnlyGlobalConnection(t *testing.T) {
	srv, r := ssooidcServerWithRepo(t)

	// No connections at all → 400 "one of ...".
	res, err := http.Get(srv.URL + "/api/auth/sso/login")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("no connections: expected 400, got %d", res.StatusCode)
	}
	res.Body.Close()

	seedGlobal(t, r, "Primary IdP")

	// Exactly one active global → resolution succeeds; the flow proceeds past
	// the selector and fails at the (unreachable) IdP instead.
	res, err = http.Get(srv.URL + "/api/auth/sso/login")
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, res); res.StatusCode == http.StatusBadRequest && strings.Contains(body, "one of connection_id") {
		t.Fatalf("single global was not used as the default: %d %s", res.StatusCode, body)
	}

	// Two active globals → ambiguous, explicit 400.
	seedGlobal(t, r, "Second IdP")
	res, err = http.Get(srv.URL + "/api/auth/sso/login")
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, res); res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "connection_id") {
		t.Fatalf("two globals: expected ambiguity 400, got %d %s", res.StatusCode, body)
	}
}
