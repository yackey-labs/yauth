package oauth2server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// signFederationRequest signs a guided-federation request (a software_statement
// with a return_uri) with the peer's key.
func (p *peerIssuer) signFederationRequest(t *testing.T, iss, returnURI string, redirectURIs []string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(iss).IssuedAt(now).Expiration(now.Add(10*time.Minute)).
		Claim("redirect_uris", redirectURIs).
		Claim("client_name", "Peer App").
		Claim("scope", "openid email profile groups").
		Claim("return_uri", returnURI).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), p.key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// opServerWithAdmin builds an OP (DCR + handshake routes) with an admin api-key.
func opServerWithAdmin(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.AllowAdminMachineCallers = true
	now := time.Now().UTC()
	adminID := uuid.NewString()
	if _, err := r.CreateUser(t.Context(), domain.NewUser{ID: adminID, Email: "admin@op.test", Role: "admin", EmailVerified: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatal(err)
	}
	role := "admin"
	if err := r.CreateAPIKey(t.Context(), domain.NewAPIKey{ID: uuid.NewString(), UserID: &adminID, KeyPrefix: gen.Prefix, KeyHash: gen.Hash, Name: "test", Role: &role, CreatedByUserID: adminID, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{Issuer: "http://op.test", BasePath: "/api/auth", DCREnabled: true, AllowPrivateNetworkJWKSURI: true})).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, gen.Plaintext
}

func postFed(t *testing.T, srv *httptest.Server, path, apiKey, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close() //nolint:errcheck
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// Full OP handshake: review → approve (mints client + grant) → redeem (creds),
// and the grant is single-use.
func TestFederateHandshake_ApproveRedeem(t *testing.T) {
	peer := newPeerIssuer(t)
	op, adminKey := opServerWithAdmin(t)
	reqJWT := peer.signFederationRequest(t, peer.srv.URL, "https://app.test/api/auth/sso/federate/return", []string{"https://app.test/api/auth/sso/callback"})
	jsonReq := `{"federation_request":"` + reqJWT + `"}`

	code, out := postFed(t, op, "/api/auth/federate/review", adminKey, jsonReq)
	if code != http.StatusOK || out["client_name"] != "Peer App" {
		t.Fatalf("review: status=%d out=%v", code, out)
	}

	code, out = postFed(t, op, "/api/auth/federate/approve", adminKey, jsonReq)
	if code != http.StatusOK {
		t.Fatalf("approve: status=%d out=%v", code, out)
	}
	ru, _ := out["redirect_url"].(string)
	if !strings.HasPrefix(ru, "https://app.test/api/auth/sso/federate/return?") {
		t.Fatalf("redirect_url = %q", ru)
	}
	u, _ := url.Parse(ru)
	grant := u.Query().Get("grant")
	if grant == "" {
		t.Fatalf("no grant in redirect_url")
	}

	code, out = postFed(t, op, "/api/auth/federate/redeem", "", `{"grant":"`+grant+`"}`)
	if code != http.StatusOK || out["client_id"] == nil || out["client_secret"] == nil {
		t.Fatalf("redeem: status=%d out=%v", code, out)
	}
	// Single-use: second redeem fails.
	code, _ = postFed(t, op, "/api/auth/federate/redeem", "", `{"grant":"`+grant+`"}`)
	if code == http.StatusOK {
		t.Fatalf("grant redeemed twice (should be single-use)")
	}
}

// Approve requires admin auth.
func TestFederateHandshake_ApproveRequiresAdmin(t *testing.T) {
	peer := newPeerIssuer(t)
	op, _ := opServerWithAdmin(t)
	reqJWT := peer.signFederationRequest(t, peer.srv.URL, "https://app.test/return", []string{"https://app.test/cb"})
	code, _ := postFed(t, op, "/api/auth/federate/approve", "", `{"federation_request":"`+reqJWT+`"}`)
	if code == http.StatusOK {
		t.Fatalf("approve without admin returned 200")
	}
}
