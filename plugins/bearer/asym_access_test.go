package bearer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/asymjwt"
)

// newTestSigner builds an in-memory RS256 asymjwt signer for tests.
func newTestSigner(t *testing.T) *asymjwt.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType:       "RS256",
		KID:           "test-key",
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		PublicKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
	})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

// TestResolver_AsymAccessToken_Resolves proves the bearer resolver accepts an
// asymmetric (RS256) access token — the kind the oauth2-server plugin mints —
// when the host exposes an asymmetric signer. Without this, OIDC clients can't
// call /userinfo (and other RequireAuth routes) with the access token returned
// from the token endpoint.
func TestResolver_AsymAccessToken_Resolves(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC()
	const uid = "11111111-1111-1111-1111-111111111111"
	if _, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uid, Email: "u@example.test", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	signer := newTestSigner(t)
	host := newFakeHost(fr, []byte("hs256-secret-secret-secret-secret"))
	host.signer = signer

	// Mint an access token shaped like oauth2-server's: token_use=access.
	token, err := signer.Sign(map[string]any{
		"iss":       "https://idp.test",
		"sub":       uid,
		"aud":       "some-client",
		"iat":       now.Unix(),
		"exp":       now.Add(time.Minute).Unix(),
		"token_use": "access",
		"scope":     "openid email",
	})
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	res := newResolver(host, Config{
		JWTSecret: host.JWTSecret(), AccessTTL: time.Minute, Issuer: "yauth-test",
	})
	r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	au, recognized, err := res.Resolve(r)
	if err != nil {
		t.Fatalf("resolve asym access token: unexpected err %v", err)
	}
	if !recognized {
		t.Fatal("expected recognized=true for a valid asym access token")
	}
	if au == nil || au.User.ID != uid {
		t.Fatalf("expected AuthUser for %s, got %+v", uid, au)
	}
}

// TestResolver_AsymToken_RejectsNonAccess proves tokens signed by the same key
// but NOT marked token_use=access (e.g. id_tokens, DCR registration-access
// tokens) are rejected — closing the token-confusion vector that comes with
// accepting asymmetric tokens at all.
func TestResolver_AsymToken_RejectsNonAccess(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC()
	const uid = "22222222-2222-2222-2222-222222222222"
	if _, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uid, Email: "id@example.test", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	signer := newTestSigner(t)
	host := newFakeHost(fr, []byte("hs256-secret-secret-secret-secret"))
	host.signer = signer

	// An id_token: validly signed, has sub, but no token_use=access marker.
	idToken, err := signer.Sign(map[string]any{
		"iss":   "https://idp.test",
		"sub":   uid,
		"aud":   "some-client",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Minute).Unix(),
		"nonce": "n-1",
		"email": "id@example.test",
	})
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}

	res := newResolver(host, Config{
		JWTSecret: host.JWTSecret(), AccessTTL: time.Minute, Issuer: "yauth-test",
	})
	r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+idToken)

	au, recognized, err := res.Resolve(r)
	if err == nil {
		t.Fatal("expected an id_token (no token_use=access) to be rejected")
	}
	if !recognized {
		t.Fatal("expected recognized=true (a Bearer header was present)")
	}
	if au != nil {
		t.Fatalf("expected no AuthUser for a non-access token, got %+v", au)
	}
}
