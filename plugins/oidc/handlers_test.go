package oidc_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/rand"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/asymjwt"
	"github.com/yackey-labs/yauth-go/plugins/oidc"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

// writeRSAKeys generates a fresh RSA-2048 keypair and writes the PEM
// files into dir, returning the two paths.
func writeRSAKeys(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	privPath = filepath.Join(dir, "rsa.key")
	pubPath = filepath.Join(dir, "rsa.pub")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return privPath, pubPath
}

// newServer builds a YAuth wrapped under /api/auth with asymjwt + oidc.
func newServer(t *testing.T) (*httptest.Server, *gormrepo.Repo) {
	t.Helper()

	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)

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
		WithPlugin(oidc.New(oidc.Config{Issuer: "http://idp.test", BasePath: "/api/auth"})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// seedSession creates a user and an active session, returning the
// raw session cookie value.
func seedSession(t *testing.T, r *gormrepo.Repo, email, name string, verified bool) (userID, cookie string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	displayName := name
	u, err := r.CreateUser(ctx, domain.NewUser{
		ID:            uuid.NewString(),
		Email:         email,
		DisplayName:   &displayName,
		EmailVerified: verified,
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
	return u.ID, raw
}

func TestDiscovery_Document(t *testing.T) {
	srv, _ := newServer(t)

	res, err := http.Get(srv.URL + "/api/auth/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if doc["issuer"] != "http://idp.test" {
		t.Fatalf("issuer mismatch: %v", doc["issuer"])
	}
	if doc["userinfo_endpoint"] != "http://idp.test/api/auth/userinfo" {
		t.Fatalf("userinfo_endpoint mismatch: %v", doc["userinfo_endpoint"])
	}
	if doc["jwks_uri"] != "http://idp.test/api/auth/.well-known/jwks.json" {
		t.Fatalf("jwks_uri mismatch: %v", doc["jwks_uri"])
	}
	algs, ok := doc["id_token_signing_alg_values_supported"].([]any)
	if !ok || len(algs) == 0 || algs[0] != "RS256" {
		t.Fatalf("alg mismatch: %v", doc["id_token_signing_alg_values_supported"])
	}
	// authorization_endpoint must be absent when oauth2-server is not loaded.
	if _, hasAuth := doc["authorization_endpoint"]; hasAuth {
		t.Fatalf("authorization_endpoint should be absent without oauth2-server")
	}
	if _, hasTok := doc["token_endpoint"]; hasTok {
		t.Fatalf("token_endpoint should be absent without oauth2-server")
	}
	// claims_supported is advertised with the default baseline when
	// the operator does not override it.
	rawClaims, ok := doc["claims_supported"].([]any)
	if !ok {
		t.Fatalf("claims_supported missing or wrong type: %v", doc["claims_supported"])
	}
	want := map[string]struct{}{
		"sub": {}, "email": {}, "email_verified": {}, "name": {},
		"aud": {}, "exp": {}, "iat": {}, "iss": {},
	}
	if len(rawClaims) != len(want) {
		t.Fatalf("claims_supported length mismatch: got %d want %d (%v)", len(rawClaims), len(want), rawClaims)
	}
	for _, c := range rawClaims {
		s, _ := c.(string)
		if _, ok := want[s]; !ok {
			t.Fatalf("unexpected claim %q in claims_supported", s)
		}
	}
}

// Operator-supplied ClaimsSupported is reflected verbatim in the
// discovery document.
func TestDiscovery_CustomClaimsSupported(t *testing.T) {
	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)

	dir := t.TempDir()
	priv, pub := writeRSAKeys(t, dir)
	asym, err := asymjwt.New(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPath: priv, PublicKeyPath: pub, KID: "kid",
	})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}

	custom := []string{"sub", "groups", "tenant_id"}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(asym).
		WithPlugin(oidc.New(oidc.Config{
			Issuer:          "http://idp.test",
			BasePath:        "/api/auth",
			ClaimsSupported: custom,
		})).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/auth/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rawClaims, _ := doc["claims_supported"].([]any)
	if len(rawClaims) != len(custom) {
		t.Fatalf("claims_supported length: got %d want %d", len(rawClaims), len(custom))
	}
	for i, want := range custom {
		if rawClaims[i] != want {
			t.Fatalf("claims_supported[%d] = %v want %q", i, rawClaims[i], want)
		}
	}
}

func TestUserInfo_AuthOK(t *testing.T) {
	srv, r := newServer(t)
	uid, cookie := seedSession(t, r, "alice@example.com", "Alice", true)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/userinfo", nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var body struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Sub != uid {
		t.Fatalf("sub mismatch: got %q want %q", body.Sub, uid)
	}
	if body.Email != "alice@example.com" || !body.EmailVerified || body.Name != "Alice" {
		t.Fatalf("claims mismatch: %+v", body)
	}
}

func TestUserInfo_NoAuth401(t *testing.T) {
	srv, _ := newServer(t)
	res, err := http.Get(srv.URL + "/api/auth/userinfo")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestNonce_RecordRejectsReplay(t *testing.T) {
	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)
	ctx := context.Background()

	if err := oidc.RecordNonce(ctx, r, "n-1", "code-1"); err != nil {
		t.Fatalf("first record: %v", err)
	}
	err = oidc.RecordNonce(ctx, r, "n-1", "code-2")
	if err == nil {
		t.Fatalf("expected replay error on second record")
	}
	if err != oidc.ErrNonceReplay {
		t.Fatalf("expected ErrNonceReplay, got %v", err)
	}

	seen, err := oidc.CheckNonce(ctx, r, "n-1")
	if err != nil {
		t.Fatalf("CheckNonce: %v", err)
	}
	if !seen {
		t.Fatalf("expected CheckNonce to report seen")
	}
	seen, err = oidc.CheckNonce(ctx, r, "n-fresh")
	if err != nil {
		t.Fatalf("CheckNonce fresh: %v", err)
	}
	if seen {
		t.Fatalf("expected fresh nonce to be unseen")
	}
}
