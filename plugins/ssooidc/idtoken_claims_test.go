// idtoken_claims_test.go — two claims the id_token verifier never insists on.
//
// jwksCache.verifyIDToken (jwks.go) is the whole trust boundary for an SSO
// login: everything downstream — resolveOrJITUser, the ExternalIdentity link,
// the session — runs on the claims it returns. It checks the signature, the
// algorithm family, iss, aud, nonce and a non-empty sub. Two OIDC Core
// requirements are missing from that list.
//
//   - exp. jwt.ParseWithClaims only validates an expiry that is PRESENT; a
//     token with no exp claim at all sails through. OIDC Core 2 makes exp
//     REQUIRED in an id_token for the obvious reason: a captured token
//     without one is a bearer credential for that account forever. The
//     back-channel-logout path right below it documents tolerating an absent
//     exp as a deliberate BCL-specific exception, which is precisely the
//     distinction the login path fails to draw.
//
//   - azp. When aud carries more than one value, OIDC Core 3.1.3.7 rule 3
//     requires azp to be present and to equal this client's id. Without the
//     check, an id_token an IdP minted for a DIFFERENT relying party — one
//     that merely lists our client_id among its audiences — is accepted here
//     as though it had been issued to us. The aud loop above is a membership
//     test, not an "issued to us" test, and azp is the claim that tells the
//     two apart.
//
// Each refusal is paired with the same token made well-formed, so the fix
// cannot be "reject more" in general: a single-audience token, and a
// multi-audience token whose azp names us, must still verify.
package ssooidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// idTokenSigner is an IdP's signing key plus the JWKS endpoint that publishes
// its public half — the minimum verifyIDToken needs to do its job.
type idTokenSigner struct {
	key     *rsa.PrivateKey
	kid     string
	jwksURL string
	issuer  string
}

func newIDTokenSigner(t *testing.T) *idTokenSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &idTokenSigner{key: key, kid: "idp-1"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		set := jwk.NewSet()
		k, err := jwk.Import(&key.PublicKey)
		if err != nil {
			t.Error(err)
			return
		}
		_ = k.Set(jwk.KeyIDKey, s.kid)
		_ = k.Set(jwk.AlgorithmKey, jwa.RS256())
		_ = set.AddKey(k)
		buf, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	}))
	t.Cleanup(srv.Close)
	s.jwksURL = srv.URL
	s.issuer = "https://idp.example"
	return s
}

func (s *idTokenSigner) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.kid
	raw, err := tok.SignedString(s.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func verifierCache(t *testing.T) *jwksCache {
	t.Helper()
	return newJWKSCache(time.Minute, time.Nanosecond, time.Hour, &http.Client{Timeout: 5 * time.Second}, nil)
}

func TestVerifyIDToken_RequiresExp(t *testing.T) {
	s := newIDTokenSigner(t)
	cache := verifierCache(t)

	// No exp claim at all.
	raw := s.sign(t, jwt.MapClaims{
		"iss":   s.issuer,
		"aud":   "rp-1",
		"sub":   "user-1",
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"email": "victim@corp.example",
	})
	claims, err := cache.verifyIDToken(context.Background(), s.jwksURL, raw, s.issuer, "rp-1", "")
	if err == nil {
		t.Fatalf("an id_token with no exp verified: sub=%q — captured once, it is a credential for that "+
			"account forever", claims.Subject)
	}
}

// Positive control: the same token with an exp still verifies.
func TestVerifyIDToken_AcceptsTokenWithExp(t *testing.T) {
	s := newIDTokenSigner(t)
	cache := verifierCache(t)

	raw := s.sign(t, jwt.MapClaims{
		"iss": s.issuer,
		"aud": "rp-1",
		"sub": "user-1",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	claims, err := cache.verifyIDToken(context.Background(), s.jwksURL, raw, s.issuer, "rp-1", "")
	if err != nil {
		t.Fatalf("a well-formed id_token was rejected: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("claims lost: %+v", claims)
	}
}

func TestVerifyIDToken_RequiresAzpOnMultiAudience(t *testing.T) {
	s := newIDTokenSigner(t)
	cache := verifierCache(t)

	// Minted for someone else; our client_id merely appears in aud.
	raw := s.sign(t, jwt.MapClaims{
		"iss": s.issuer,
		"aud": []string{"some-other-rp", "rp-1"},
		"azp": "some-other-rp",
		"sub": "user-1",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	if _, err := cache.verifyIDToken(context.Background(), s.jwksURL, raw, s.issuer, "rp-1", ""); err == nil {
		t.Fatal("an id_token authorized to another relying party (azp=some-other-rp) was accepted as ours")
	}
}

// Positive control: multi-audience is legal when azp names us.
func TestVerifyIDToken_AcceptsMultiAudienceWithOurAzp(t *testing.T) {
	s := newIDTokenSigner(t)
	cache := verifierCache(t)

	raw := s.sign(t, jwt.MapClaims{
		"iss": s.issuer,
		"aud": []string{"rp-1", "some-resource-server"},
		"azp": "rp-1",
		"sub": "user-1",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	if _, err := cache.verifyIDToken(context.Background(), s.jwksURL, raw, s.issuer, "rp-1", ""); err != nil {
		t.Fatalf("a multi-audience id_token authorized to us was rejected: %v", err)
	}
}
