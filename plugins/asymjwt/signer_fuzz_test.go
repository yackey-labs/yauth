package asymjwt_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth/plugins/asymjwt"
)

// Standing fuzz coverage for the asymmetric JWT verifier. Neither target below
// found a defect; they exist so a future edit cannot introduce one unnoticed.
//
// Signer.Verify is the trust boundary for every OAuth2 access token,
// id_token and federate JWT this deployment signs: bearer's
// verifyAsymAccessToken calls it on the raw Authorization header before it
// looks at token_use or sub, and oauth2server calls it on tokens presented by
// relying parties. It parses an attacker-controlled string, so:
//
//  1. It must not panic on any input. The header is read before authorization,
//     so a panic is an unauthenticated request-path DoS.
//  2. A nil error must imply a non-nil claim map. verifyAsymAccessToken
//     indexes the returned map immediately (claims["token_use"], claims["sub"]);
//     a nil map read is safe in Go but a nil-with-no-error return would mean a
//     token verified with no claims at all, which the kid/exp gates exist to
//     prevent.
//
// The keyfunc's kid handling is deliberately in scope. It accepts a token with
// NO kid header (the HS256->asymmetric migration path and ssooidc's federate
// JWTs depend on that) but refuses a kid that is not ours — including a kid
// header that is not a string, which is why one seed carries {"kid":1}. A
// regression that dropped the type assertion would panic on that seed rather
// than return an error.
//
// REACHABILITY, stated honestly because it changes what FuzzSignerVerify
// proves. Verify returns a nil error only for a string bearing a valid RS256
// signature under the key generated below, and no coverage-guided mutator is
// going to produce one from a raw string. So invariant 1 (no panic) is under
// real test across the whole pre-signature parse, while invariant 2 is a
// REGRESSION TRIPWIRE for a human editing signer.go — today it is in fact
// structurally guaranteed, since jwt.WithExpirationRequired() rejects a
// `null`, `{}` or array payload before Verify can return. FuzzSignerVerifySigned
// below is the one that gets past the signature and exercises the claim
// validation itself. The legitimate round trip is pinned separately by
// TestSigner_RS256_RoundTrip in signer_test.go, so a change that made Verify
// always error would fail there rather than turn these targets green by
// vacuity — and the setup below asserts it directly as well.

// fuzzKID is the kid both targets configure and sign with.
const fuzzKID = "yauth-fuzz"

// newFuzzSigner builds an RS256 Signer over a freshly generated RSA-2048 key
// and returns the private key too, so a target can hand-build tokens the
// signer will accept. Generated ONCE per target per `go test` invocation, not
// per fuzz input. RS256 is the deployed default, so it is the path worth
// covering.
func newFuzzSigner(tb testing.TB) (*asymjwt.Signer, *rsa.PrivateKey) {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("rsa.GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		tb.Fatalf("marshal pkcs8: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		tb.Fatalf("marshal pkix: %v", err)
	}
	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType:       "RS256",
		KID:           fuzzKID,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		PublicKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
	})
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	return signer, priv
}

func FuzzSignerVerify(f *testing.F) {
	signer, priv := newFuzzSigner(f)

	good, err := signer.Sign(map[string]any{
		"sub":       "user-1",
		"token_use": "access",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	if err != nil {
		f.Fatalf("Sign: %v", err)
	}
	// POSITIVE CONTROL, in setup so it costs one execution rather than one per
	// input. Without it, a change that made Verify return an error
	// unconditionally would leave this target trivially green: every input
	// would take the `err != nil` early return and nothing would be asserted.
	if claims, err := signer.Verify(good); err != nil || claims["sub"] != "user-1" {
		f.Fatalf("positive control: a token from signer.Sign must verify, got (%v, %v)", claims, err)
	}

	// Hand-built token whose kid header is a NUMBER, not a string. Signed with
	// the real key so it reaches the keyfunc rather than dying at the
	// signature check.
	nonStringKid := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = 1
		s, err := tok.SignedString(priv)
		if err != nil {
			f.Fatalf("sign non-string kid: %v", err)
		}
		return s
	}()

	b64 := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}

	seeds := []string{
		good,
		nonStringKid,
		good[:len(good)-6],
		good + "AAAA",
		"",
		".",
		"..",
		"a.b.c",
		// alg:none with an otherwise plausible payload.
		b64(`{"alg":"none","kid":"yauth-fuzz"}`) + "." + b64(`{"sub":"user-1","exp":9999999999}`) + ".",
		// right alg, wrong kid.
		b64(`{"alg":"RS256","kid":"attacker"}`) + "." + b64(`{"sub":"user-1","exp":9999999999}`) + ".AAAA",
		// kid header as an object.
		b64(`{"alg":"RS256","kid":{"a":1}}`) + "." + b64(`{"sub":"user-1","exp":9999999999}`) + ".AAAA",
		// payload is JSON null / an array, not an object.
		b64(`{"alg":"RS256"}`) + "." + b64(`null`) + ".AAAA",
		b64(`{"alg":"RS256"}`) + "." + b64(`[1,2,3]`) + ".AAAA",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		claims, err := signer.Verify(raw)
		if err != nil {
			return
		}
		if claims == nil {
			t.Fatalf("Verify(%q): nil error and nil claims", raw)
		}
	})
}

// FuzzSignerVerifySigned fuzzes the CLAIMS BODY and signs it in-loop with the
// same RSA key, so every input arrives bearing a valid RS256 signature under
// our own kid. That is the only way a mutator gets past the signature check
// and into the claim validation that follows it — the part of Verify that
// makes a decision rather than a parse. RS256 signing is ~1ms, so this runs at
// roughly a thousand execs a second rather than tens of thousands; the seeds
// alone cost a few milliseconds, which is what `go test` without -fuzz pays.
//
// What it pins, beyond "no panic" and "nil error implies non-nil claims":
//
//   - a token Verify accepts always carries an `exp`. jwt.WithExpirationRequired
//     is the only thing stopping a never-expiring asymmetric token, and unlike
//     the raw-string target this input can actually reach that check. A payload
//     that is JSON `null`, an array, or an object with no exp must be refused
//     even though its signature is perfect.
//
// Deliberately NOT asserted: issuer or audience. signer.go leaves both
// unpinned on purpose, because the same Signer verifies oauth2server tokens
// (cfg.Issuer) and ssooidc's federate request (cfg.SelfIssuer); pinning them
// here would encode the opposite of the documented design.
func FuzzSignerVerifySigned(f *testing.F) {
	signer, priv := newFuzzSigner(f)

	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	// Fixed header carrying OUR kid: the point of this target is the payload,
	// and a matching kid keeps every input on the far side of the keyfunc. The
	// wrong-kid and non-string-kid cases stay in FuzzSignerVerify, where the
	// header is what varies.
	header := b64([]byte(`{"alg":"RS256","typ":"JWT","kid":"` + fuzzKID + `"}`))
	sign := func(payload []byte) string {
		signing := header + "." + b64(payload)
		sum := sha256.Sum256([]byte(signing))
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
		if err != nil {
			// Signing our own bytes with our own key cannot fail; if it does,
			// the harness is broken and every later assertion is meaningless.
			panic("fuzz harness: RS256 sign failed: " + err.Error())
		}
		return signing + "." + b64(sig)
	}

	exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)

	// POSITIVE CONTROL: prove the in-loop signing actually produces tokens
	// this signer accepts. If it did not, every input would bounce off the
	// signature check and this target would assert nothing while passing.
	control := []byte(`{"sub":"user-1","token_use":"access","exp":` + exp + `}`)
	if claims, err := signer.Verify(sign(control)); err != nil || claims["sub"] != "user-1" {
		f.Fatalf("positive control: a hand-signed RS256 token must verify, got (%v, %v)", claims, err)
	}

	seeds := [][]byte{
		control,
		[]byte(`{"sub":"user-1","token_use":"id_token","aud":"client-1","exp":` + exp + `}`),
		// No exp at all — must be refused despite a valid signature.
		[]byte(`{"sub":"user-1","token_use":"access"}`),
		// exp of the wrong type, and long expired.
		[]byte(`{"sub":"user-1","exp":"soon"}`),
		[]byte(`{"sub":"user-1","exp":[9999999999]}`),
		[]byte(`{"sub":"user-1","exp":1}`),
		// nbf in the future, iat in the future.
		[]byte(`{"sub":"user-1","exp":` + exp + `,"nbf":9999999999}`),
		[]byte(`{"sub":"user-1","exp":` + exp + `,"iat":9999999999}`),
		// Claim-type confusion on the fields callers index afterwards.
		[]byte(`{"sub":1,"exp":` + exp + `}`),
		[]byte(`{"sub":null,"token_use":{"a":1},"exp":` + exp + `}`),
		[]byte(`{"aud":["a","b"],"sub":"user-1","exp":` + exp + `}`),
		// Duplicate keys; empty object; not an object at all.
		[]byte(`{"sub":"attacker","sub":"user-1","exp":` + exp + `}`),
		[]byte(`{}`),
		[]byte(`null`),
		[]byte(`[1,2,3]`),
		[]byte(``),
		[]byte(`not json`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		claims, err := signer.Verify(sign(payload))
		if err != nil {
			return
		}
		if claims == nil {
			t.Fatalf("Verify accepted signed payload %q with nil claims", payload)
		}
		if _, ok := claims["exp"]; !ok {
			t.Fatalf("Verify accepted signed payload %q with no exp claim", payload)
		}
	})
}
