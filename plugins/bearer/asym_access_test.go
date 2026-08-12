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

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
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

// TestResolver_AsymAccessToken_ResolvesAsDelegated proves the bearer resolver
// accepts an asymmetric (RS256) access token — the kind the oauth2-server
// plugin mints — when the host exposes an asymmetric signer, AND that it
// records what such a token actually is.
//
// The acceptance half is load-bearing for OIDC: without it, relying parties
// can't call /userinfo (or any other RequireAuth route) with the access token
// from the token endpoint.
//
// The classification half is the fix. This case used to assert only that the
// token resolved, with `aud: "some-client"` and `scope: "openid email"` in the
// claims and read by nothing — which is exactly the bug it was encoding as
// intended behaviour: a token issued to a relying party under a two-scope
// grant was indistinguishable from the user's own session, and could mint
// personal API keys and strip MFA. It now asserts the token is marked
// DELEGATED and carries its audience and scope, so the gates on the
// personal-account routes have something to refuse it on.
func TestResolver_AsymAccessToken_ResolvesAsDelegated(t *testing.T) {
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

	// Mint an access token shaped like oauth2-server's: token_use=access,
	// audienced at the RELYING PARTY, scoped to what the user consented to.
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
	if !au.Principal.IsUser() {
		t.Fatalf("expected a user principal, got kind %q", au.Principal.Kind)
	}
	if !au.Principal.IsDelegated() {
		t.Fatal("expected the token to be marked delegated: its aud is a relying party, " +
			"not a resource identifier this deployment declared")
	}
	if got := au.Principal.Audience; len(got) != 1 || got[0] != "some-client" {
		t.Fatalf("expected audience [some-client], got %v", got)
	}
	if got := au.Principal.Scope; len(got) != 2 || got[0] != "openid" || got[1] != "email" {
		t.Fatalf("expected scope [openid email], got %v", got)
	}
	// The granted scope is now answerable, which it was not before.
	if !au.Principal.HasScope("email") {
		t.Fatal("expected HasScope(email) on a token granted openid+email")
	}
	if au.Principal.HasScope("admin") {
		t.Fatal("HasScope must not report a scope that was never granted")
	}
}

// TestResolver_AsymAccessToken_ConfiguredAudienceIsFirstParty proves the
// escape hatch: a deployment that genuinely issues access tokens FOR ITS OWN
// API names that audience in Config.ResourceIdentifiers, and a token bearing
// it resolves with full authority (Delegated=false) as before.
func TestResolver_AsymAccessToken_ConfiguredAudienceIsFirstParty(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC()
	const uid = "33333333-3333-3333-3333-333333333333"
	if _, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uid, Email: "own@example.test", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	signer := newTestSigner(t)
	host := newFakeHost(fr, []byte("hs256-secret-secret-secret-secret"))
	host.signer = signer

	token, err := signer.Sign(map[string]any{
		"iss":       "https://idp.test",
		"sub":       uid,
		"aud":       "https://api.example.test",
		"iat":       now.Unix(),
		"exp":       now.Add(time.Minute).Unix(),
		"token_use": "access",
		"scope":     "openid email",
	})
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	res := newResolver(host, Config{
		JWTSecret:           host.JWTSecret(),
		AccessTTL:           time.Minute,
		Issuer:              "yauth-test",
		ResourceIdentifiers: []string{"https://api.example.test"},
	})
	r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	au, _, err := res.Resolve(r)
	if err != nil || au == nil {
		t.Fatalf("resolve: au=%+v err=%v", au, err)
	}
	if au.Principal.IsDelegated() {
		t.Fatal("a token audienced at a declared resource identifier must not be delegated")
	}
}

// TestResolver_HS256AccessToken_NotDelegated is the other half of the
// compatibility guarantee: the token pair POST /token issues carries no
// token_use claim, is the user's OWN credential, and must resolve with
// undiminished authority. If this ever flips, every native client loses the
// personal-account routes.
func TestResolver_HS256AccessToken_NotDelegated(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC()
	const uid = "44444444-4444-4444-4444-444444444444"
	if _, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uid, Email: "own@example.test", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	secret := []byte("hs256-secret-secret-secret-secret")
	host := newFakeHost(fr, secret)
	cfg := Config{JWTSecret: secret, AccessTTL: time.Minute, Issuer: "yauth-test"}

	token, _, err := signAccessToken(secret, uid, "jti-1", cfg, now, activeOrgClaims{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api-keys", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	au, _, err := newResolver(host, cfg).Resolve(r)
	if err != nil || au == nil {
		t.Fatalf("resolve: au=%+v err=%v", au, err)
	}
	if au.Principal.IsDelegated() {
		t.Fatal("a first-party /token credential must never be classified as delegated")
	}
	if !au.Principal.HasScope("anything") {
		t.Fatal("a non-delegated credential is unrestricted and must satisfy any scope")
	}
}

// TestResolver_HS256OAuth2AccessToken_IsDelegated closes the HS256 route into
// the same hole. oauth2server.signAccessToken falls back to host.JWTSecret()
// when no asymmetric signer is loaded — the very secret verifyAccessToken
// validates against — and `aud` is only enforced when Config.Audience is set,
// which is not the default. The token_use claim, which this plugin's own
// tokens never carry, is what tells the two apart.
func TestResolver_HS256OAuth2AccessToken_IsDelegated(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC()
	const uid = "55555555-5555-5555-5555-555555555555"
	if _, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uid, Email: "rp@example.test", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	secret := []byte("hs256-secret-secret-secret-secret")
	host := newFakeHost(fr, secret)
	cfg := Config{JWTSecret: secret, AccessTTL: time.Minute, Issuer: "yauth-test"}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "yauth-test",
		"sub":       uid,
		"aud":       "some-client",
		"iat":       now.Unix(),
		"exp":       now.Add(time.Minute).Unix(),
		"token_use": "access",
		"scope":     "openid email",
	}).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api-keys", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	au, _, err := newResolver(host, cfg).Resolve(r)
	if err != nil || au == nil {
		t.Fatalf("resolve: au=%+v err=%v", au, err)
	}
	if !au.Principal.IsDelegated() {
		t.Fatal("an HS256 OAuth2 access token rides the shared secret; it must still be delegated")
	}
	if got := au.Principal.Scope; len(got) != 2 {
		t.Fatalf("expected the granted scope to be carried, got %v", got)
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
