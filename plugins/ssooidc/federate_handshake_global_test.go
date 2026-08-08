package ssooidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/ssooidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// rpWithSigner builds an RP with asymjwt + SelfIssuer (handshake-capable) and
// an admin api-key, plus a plain-user api-key for the authz check. The repo is
// returned too so callers can seed extra principals — the must-change-password
// gate tests need cookie sessions, which only exist in the repo.
func rpWithSigner(t *testing.T) (srv *httptest.Server, repo *memrepo.Repo, adminKey, userKey string) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.AllowAdminMachineCallers = true
	cfg.BaseURL = "https://rp.test.example"
	now := time.Now().UTC()

	mkUser := func(email, role string) string {
		id := uuid.NewString()
		if _, err := r.CreateUser(t.Context(), domain.NewUser{ID: id, Email: email, Role: role, EmailVerified: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		gen, err := apikey.GenerateKey("yak")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.CreateAPIKey(t.Context(), domain.NewAPIKey{ID: uuid.NewString(), UserID: &id, KeyPrefix: gen.Prefix, KeyHash: gen.Hash, Name: email, Role: &role, CreatedByUserID: id, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		return gen.Plaintext
	}
	adminKey = mkUser("admin@rp.test", "admin")
	userKey = mkUser("user@rp.test", "user")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	asym, err := asymjwt.New(asymjwt.Config{KeyType: "RS256", KID: "t1", PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM})
	if err != nil {
		t.Fatal(err)
	}

	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	ssoP, err := ssooidc.New(ssooidc.Config{EncryptionKey: key, SelfIssuer: "https://rp.test.example/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(asym).
		WithPlugin(ssoP).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r, adminKey, userKey
}

func getWithKey(t *testing.T, rawURL, key string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-api-key", key)
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // capture the 302, don't follow it
	}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestFederateStartGlobal: omitting org starts an ORG-LESS handshake — install
// admin only, and the signed federation_request carries an initiate_login_uri
// keyed by a pre-minted connection_id (no org slug anywhere).
func TestFederateStartGlobal(t *testing.T) {
	srv, _, adminKey, userKey := rpWithSigner(t)

	// Plain user → 403 (install-wide admin required for global mode).
	res := getWithKey(t, srv.URL+"/api/auth/sso/federate/start?idp=https://idp.test.example", userKey)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin: expected 403, got %d", res.StatusCode)
	}
	res.Body.Close()

	// Admin, no org → 302 to the IdP approval page with a signed request.
	res = getWithKey(t, srv.URL+"/api/auth/sso/federate/start?idp=https://idp.test.example&name=central", adminKey)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start: expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	res.Body.Close()
	if !strings.HasPrefix(loc, "https://idp.test.example/federate/approve?req=") {
		t.Fatalf("location: %s", loc)
	}

	// Decode the JWT payload (signature already covered elsewhere) and assert
	// the org-less shape.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(u.Query().Get("req"), ".")
	if len(parts) != 3 {
		t.Fatalf("req is not a JWT: %q", u.Query().Get("req"))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		OrgID            string `json:"org_id"`
		ConnectionID     string `json:"connection_id"`
		InitiateLoginURI string `json:"initiate_login_uri"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.OrgID != "" {
		t.Fatalf("expected empty org_id, got %q", claims.OrgID)
	}
	if claims.ConnectionID == "" {
		t.Fatal("expected a pre-minted connection_id")
	}
	want := "connection_id=" + claims.ConnectionID
	if !strings.Contains(claims.InitiateLoginURI, want) || strings.Contains(claims.InitiateLoginURI, "org=") {
		t.Fatalf("initiate_login_uri should select by connection_id, got %q", claims.InitiateLoginURI)
	}
}
