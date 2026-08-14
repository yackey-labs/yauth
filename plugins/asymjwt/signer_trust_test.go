package asymjwt_test

// The asymjwt Signer is the root of trust for every asymmetrically signed
// credential yauth mints: OAuth2 access tokens (verified by
// plugins/bearer.verifyAsymAccessToken), id_tokens, DCR registration access
// tokens, back-channel logout tokens, and the JWKS the deployment publishes at
// /.well-known/jwks.json for relying parties to pin. Three properties that a
// signer of that consequence must hold were missing:
//
//  1. NewSigner parsed the private and the public PEM completely
//     independently and never compared them. The private slot signs; the
//     PUBLIC slot both verifies incoming tokens and is what PublicJWKS
//     publishes. Config splits the two on purpose — the private key is meant
//     to live in a Secret while public_key_pem_env (yauthcfg) makes a
//     non-secret ConfigMap/env the intended home of the public half, and
//     cmd/yauth/gen_keys.go writes public.pem mode 0644. So anyone who can
//     write only the NON-SECRET half of the key material could swap in a key
//     they hold the private half of: NewSigner still returned a nil error, and
//     from then on the deployment verified — and published to every relying
//     party — the attacker's key. A JWT signed by the attacker with
//     {"sub":"<victim>","token_use":"access"} sails through
//     bearer.verifyAsymAccessToken and resolves to the victim on every
//     RequireAuth route.
//
//  2. Verify built its parser with jwt.WithValidMethods alone. golang-jwt
//     treats a missing "exp" as "no expiry to check", so a token minted
//     without exp verifies forever — there is no revocation for a bearer JWT,
//     so "forever" means exactly that.
//
//  3. Sign writes a "kid" header and PublicJWKS publishes that kid, but Verify
//     returned the one loaded key for ANY kid, so the kid was decorative.
//     Refusing a kid that is not ours is inert with a single key today and is
//     the precondition for a sound key rotation later.
//
// Each refusal below is paired with a positive control proving the legitimate
// path — a matched pair, a token with a real exp, a token carrying our own kid
// or no kid at all (the HS256->asym migration path and ssooidc's federate
// JWTs) — still works, so a "fix" that simply breaks signing cannot pass.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth/plugins/asymjwt"
)

// rsaPairPEM generates an RSA-2048 keypair and returns its private (PKCS8)
// and public (PKIX) PEM encodings plus the key itself, so a test can mix the
// private half of one pair with the public half of another.
func rsaPairPEM(t *testing.T) (priv *rsa.PrivateKey, privPEM, pubPEM []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return k,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// ecPairPEM is the ES256 equivalent of rsaPairPEM.
func ecPairPEM(t *testing.T) (priv *ecdsa.PrivateKey, privPEM, pubPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return k,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// TestNewSigner_RejectsMismatchedKeypair asserts that a Signer refuses to come
// into existence when the public slot does not hold the public half of the
// private slot's key. A deployment in that state is already broken — its own
// access tokens fail bearer verification — so the only question is whether it
// fails loudly at boot or silently trusts whoever supplied the public half.
func TestNewSigner_RejectsMismatchedKeypair(t *testing.T) {
	t.Run("RS256", func(t *testing.T) {
		_, operatorPriv, _ := rsaPairPEM(t)
		_, _, attackerPub := rsaPairPEM(t)

		_, err := asymjwt.NewSigner(asymjwt.Config{
			KeyType:       "RS256",
			PrivateKeyPEM: operatorPriv,
			PublicKeyPEM:  attackerPub,
			KID:           "yauth-1",
		})
		if err == nil {
			t.Fatal("NewSigner accepted a public key that is not the public half of the configured private key")
		}
		if !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error should name the mismatch, got: %v", err)
		}
	})

	t.Run("ES256", func(t *testing.T) {
		_, operatorPriv, _ := ecPairPEM(t)
		_, _, attackerPub := ecPairPEM(t)

		_, err := asymjwt.NewSigner(asymjwt.Config{
			KeyType:       "ES256",
			PrivateKeyPEM: operatorPriv,
			PublicKeyPEM:  attackerPub,
			KID:           "yauth-1",
		})
		if err == nil {
			t.Fatal("NewSigner accepted a mismatched ES256 public key")
		}
		if !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error should name the mismatch, got: %v", err)
		}
	})

	// POSITIVE CONTROL: the pair an operator actually deploys — both halves of
	// the same key, from a path on disk as well as inline — still constructs,
	// signs, verifies and publishes its own key in the JWKS.
	t.Run("matched pair still works", func(t *testing.T) {
		key, privPEM, pubPEM := rsaPairPEM(t)
		dir := t.TempDir()
		privPath := filepath.Join(dir, "private.pem")
		pubPath := filepath.Join(dir, "public.pem")
		if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
			t.Fatalf("write priv: %v", err)
		}
		if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
			t.Fatalf("write pub: %v", err)
		}

		for name, cfg := range map[string]asymjwt.Config{
			"paths":  {KeyType: "RS256", PrivateKeyPath: privPath, PublicKeyPath: pubPath, KID: "yauth-1"},
			"inline": {KeyType: "RS256", PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM, KID: "yauth-1"},
		} {
			signer, err := asymjwt.NewSigner(cfg)
			if err != nil {
				t.Fatalf("%s: NewSigner on a matched pair: %v", name, err)
			}
			raw, err := signer.Sign(map[string]any{
				"sub":       "user-123",
				"token_use": "access",
				"exp":       time.Now().Add(time.Hour).Unix(),
			})
			if err != nil {
				t.Fatalf("%s: Sign: %v", name, err)
			}
			claims, err := signer.Verify(raw)
			if err != nil {
				t.Fatalf("%s: Verify of our own token: %v", name, err)
			}
			if claims["sub"] != "user-123" {
				t.Fatalf("%s: claims roundtrip mismatch: %#v", name, claims)
			}
			// The published JWKS must be OUR key, i.e. the one that verifies
			// what we sign.
			jwks, err := signer.PublicJWKS()
			if err != nil {
				t.Fatalf("%s: PublicJWKS: %v", name, err)
			}
			if !jwksHasRSAModulus(t, jwks, &key.PublicKey) {
				t.Fatalf("%s: published JWKS does not contain the signing key's public half", name)
			}
		}
	})
}

// TestSigner_MismatchedPair_ForgesVictimAccessToken spells out the damage the
// missing pair check allows, at the exact shape bearer.verifyAsymAccessToken
// accepts: attacker-controlled public material means attacker-minted access
// tokens for any user id, and a /jwks that tells every relying party to trust
// them too.
func TestSigner_MismatchedPair_ForgesVictimAccessToken(t *testing.T) {
	_, operatorPriv, _ := rsaPairPEM(t)
	attackerKey, _, attackerPub := rsaPairPEM(t)

	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType:       "RS256",
		PrivateKeyPEM: operatorPriv,
		PublicKeyPEM:  attackerPub,
		KID:           "yauth-1",
	})
	if err != nil {
		// Construction was refused: the deployment can never reach the state
		// this test describes. That is the fixed behaviour.
		return
	}

	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":       "victim-user-id",
		"token_use": "access",
	})
	forged.Header["kid"] = "not-a-known-kid"
	raw, err := forged.SignedString(attackerKey)
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	claims, err := signer.Verify(raw)
	if err == nil {
		t.Fatalf("the deployment's own signer accepted a token minted by an attacker key: sub=%v token_use=%v",
			claims["sub"], claims["token_use"])
	}

	jwks, err := signer.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if jwksHasRSAModulus(t, jwks, &attackerKey.PublicKey) {
		t.Fatal("/.well-known/jwks.json publishes the attacker's key, so every relying party validates the forgeries too")
	}
}

// TestSigner_Verify_RequiresExp: golang-jwt only checks an exp that is
// present. A yauth-signed JWT is a bearer credential with no revocation path,
// so one minted without exp is a permanent credential.
func TestSigner_Verify_RequiresExp(t *testing.T) {
	_, privPEM, pubPEM := rsaPairPEM(t)
	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM, KID: "yauth-1",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	noExp, err := signer.Sign(map[string]any{"sub": "user-123", "token_use": "access"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if claims, err := signer.Verify(noExp); err == nil {
		t.Fatalf("Verify accepted a token with no exp — it will keep verifying forever: %#v", claims)
	}

	// POSITIVE CONTROL: a normal, unexpired token still verifies, and an
	// expired one is still refused.
	withExp, err := signer.Sign(map[string]any{
		"sub": "user-123", "token_use": "access",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := signer.Verify(withExp)
	if err != nil {
		t.Fatalf("Verify rejected a valid, unexpired token: %v", err)
	}
	if claims["sub"] != "user-123" {
		t.Fatalf("claims mismatch: %#v", claims)
	}

	expired, err := signer.Sign(map[string]any{
		"sub": "user-123", "token_use": "access",
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := signer.Verify(expired); err == nil {
		t.Fatal("Verify accepted an expired token")
	}
}

// TestSigner_Verify_RejectsUnknownKID: Sign writes a kid and PublicJWKS
// publishes it, but Verify handed back the single loaded key whatever kid the
// token claimed. Every token below carries a valid exp so the only variable
// under test is the kid header.
func TestSigner_Verify_RejectsUnknownKID(t *testing.T) {
	key, privPEM, pubPEM := rsaPairPEM(t)
	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM, KID: "yauth-1",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	sign := func(t *testing.T, kid *string) string {
		t.Helper()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":       "user-123",
			"token_use": "access",
			"exp":       time.Now().Add(15 * time.Minute).Unix(),
		})
		if kid != nil {
			tok.Header["kid"] = *kid
		} else {
			delete(tok.Header, "kid")
		}
		raw, err := tok.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return raw
	}

	other := "some-other-key"
	if claims, err := signer.Verify(sign(t, &other)); err == nil {
		t.Fatalf("Verify accepted a token whose kid names a key we do not hold: %#v", claims)
	}

	// POSITIVE CONTROL 1: our own kid verifies.
	ours := "yauth-1"
	if _, err := signer.Verify(sign(t, &ours)); err != nil {
		t.Fatalf("Verify rejected a token carrying our own kid: %v", err)
	}
	// POSITIVE CONTROL 2: no kid header at all still verifies — the local
	// HS256->asymmetric migration path and ssooidc's federate JWTs rely on it.
	if _, err := signer.Verify(sign(t, nil)); err != nil {
		t.Fatalf("Verify rejected a token with no kid header: %v", err)
	}
}

// jwksHasRSAModulus reports whether the published JWKS contains an RSA key
// with pub's modulus, i.e. whether the deployment is telling relying parties
// to trust that key.
func jwksHasRSAModulus(t *testing.T, jwks []byte, pub *rsa.PublicKey) bool {
	t.Helper()
	var doc struct {
		Keys []struct {
			N string `json:"n"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &doc); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	want := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	for _, k := range doc.Keys {
		if k.N == want {
			return true
		}
	}
	return false
}
