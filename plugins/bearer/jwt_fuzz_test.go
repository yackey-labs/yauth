package bearer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

// Standing fuzz coverage for the HS256 access-token verifier. Neither target
// below found a defect; they exist so a future edit cannot introduce one
// unnoticed.
//
// verifyAccessToken is the first thing that touches an attacker-controlled
// Authorization header: resolver.go hands it the raw Bearer value before any
// authorization decision has been made, and whatever it returns becomes the
// caller's identity. Two things must hold for every possible input string.
//
//  1. It must not panic. A panic here is a request-path DoS reachable by any
//     unauthenticated client, since the header is read before auth. This is
//     the part the mutator really exercises.
//  2. A nil error must imply a subject. Everything downstream — the resolver,
//     middleware.RequireUserPrincipalHuma, the org-scope checks — treats a
//     successful return as "this is user pt.UserID"; a nil error with an empty
//     UserID would resolve to a principal with no identity.
//
// REACHABILITY, stated honestly because it changes what these targets prove.
// verifyAccessToken returns a nil error only for a string bearing a valid
// HMAC-SHA256 over the secret below. No coverage-guided mutator is going to
// produce one. So FuzzVerifyAccessToken, fed raw strings, fuzzes the
// PRE-signature parse only: invariant 1 is under real test, and invariant 2 is
// a REGRESSION TRIPWIRE for a human editing jwt.go, not something the fuzzer
// can reach.
//
// FuzzVerifyAccessTokenClaims closes that gap. It fuzzes the CLAIMS BODY and
// signs it in-loop with the same secret, so every input arrives correctly
// signed. That is the only way the mutator gets past the signature check and
// into the code that makes the actual authorization decision: the
// `claims.Subject == ""` guard (jwt.go:133) and the token_use switch
// (jwt.go:156-182) that #85 added to stop an id_token, a DCR registration
// token or a back-channel logout token — all signed with this same secret on
// an HS256 deployment — being spent as an API credential.
func FuzzVerifyAccessToken(f *testing.F) {
	secret := []byte("fuzz-hs256-secret-value-0123456789")
	cfg := Config{
		JWTSecret: secret,
		AccessTTL: time.Hour,
		Issuer:    "yauth-fuzz",
	}
	now := time.Now()

	// A genuinely valid token, so the mutator starts from something that
	// reaches the deepest code path rather than bouncing off the parser.
	good, _, err := signAccessToken(secret, "user-1", "jti-1", cfg, now, activeOrgClaims{
		Org:  "org-1",
		Role: "admin",
		Orgs: []string{"org-1", "org-2"},
	})
	if err != nil {
		f.Fatalf("signAccessToken: %v", err)
	}
	// POSITIVE CONTROL, in setup rather than in f.Fuzz so it costs one
	// execution rather than one per input. Without it, a change that made
	// verifyAccessToken return an error unconditionally would leave this
	// target trivially green: every input would take the `err != nil` early
	// return and nothing would ever be asserted.
	if pt, err := verifyAccessToken(secret, good, cfg); err != nil || pt.UserID != "user-1" {
		f.Fatalf("positive control: a token from signAccessToken must verify, got (%+v, %v)", pt, err)
	}

	seeds := []string{
		good,
		good + "==",
		good[:len(good)-4],
		"",
		".",
		"..",
		"a.b.c",
		"Bearer " + good,
		// alg:none header, empty signature segment.
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJ5YXV0aC1mdXp6In0.",
		// header + payload, no signature segment at all.
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ",
		// well-formed base64url segments carrying non-JSON.
		"AAAA.AAAA.AAAA",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		pt, err := verifyAccessToken(secret, raw, cfg)
		if err != nil {
			return
		}
		if pt.UserID == "" {
			t.Fatalf("verifyAccessToken(%q) returned no error and no subject", raw)
		}
	})
}

// FuzzVerifyAccessTokenClaims fuzzes the claims BODY of an otherwise valid
// HS256 token: the fuzzed bytes become the payload segment, and the harness
// signs the result in-loop with the same secret before calling
// verifyAccessToken. HMAC-SHA256 is microseconds, so the exec rate stays in
// the same order as the raw-string target.
//
// This is the target that reaches the authorization logic. What it pins:
//
//   - a nil error still implies a subject (the jwt.go:133 guard);
//   - a nil error implies the token declared a token_use this plugin
//     RECOGNISES. The default arm of the switch must refuse everything else,
//     because on an HS256 deployment the same secret signs oauth2server's
//     id_tokens, DCR registration-access tokens and logout tokens, each of
//     which is deliberately handed to a party that is not the user;
//   - the migration window for a marker-less token stays narrow: a token with
//     no token_use at all is accepted only when it carries NO audience, since
//     every foreign kind always carries a client_id in `aud`.
//
// A signed token whose payload is not a JSON object, or whose claim types are
// wrong, is rejected by the parser before any of this — that is the parser
// robustness half, and it is exercised by the same inputs.
func FuzzVerifyAccessTokenClaims(f *testing.F) {
	secret := []byte("fuzz-hs256-secret-value-0123456789")
	cfg := Config{
		JWTSecret: secret,
		AccessTTL: time.Hour,
		Issuer:    "yauth-fuzz",
	}
	exp := time.Now().Add(time.Hour).Unix()

	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	// Fixed header: the point of this target is the payload, and pinning the
	// header keeps every input on the far side of the signature check.
	header := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	sign := func(payload []byte) string {
		signing := header + "." + b64(payload)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signing))
		return signing + "." + b64(mac.Sum(nil))
	}

	// POSITIVE CONTROL: prove the in-loop signing actually produces tokens
	// that verify. If it did not, every input would bounce off the signature
	// check and this target would assert nothing while still passing.
	control := []byte(`{"iss":"yauth-fuzz","sub":"user-1","token_use":"yauth_access","exp":` + strconv.FormatInt(exp, 10) + `}`)
	if pt, err := verifyAccessToken(secret, sign(control), cfg); err != nil || pt.UserID != "user-1" {
		f.Fatalf("positive control: a self-signed first-party token must verify, got (%+v, %v)", pt, err)
	}

	seeds := [][]byte{
		control,
		// The oauth2server delegated access token: recognised, but classified
		// as delegated rather than full authority.
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","token_use":"access","scope":"read write","aud":"client-1","exp":` + strconv.FormatInt(exp, 10) + `}`),
		// Marker-less migration token, with and without an audience. The
		// second must be refused.
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","exp":` + strconv.FormatInt(exp, 10) + `}`),
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","aud":"client-1","exp":` + strconv.FormatInt(exp, 10) + `}`),
		// Foreign kinds signed with the same secret on an HS256 deployment.
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","token_use":"id_token","aud":"client-1","exp":` + strconv.FormatInt(exp, 10) + `}`),
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","token_use":"registration","exp":` + strconv.FormatInt(exp, 10) + `}`),
		// Subject present but empty; subject absent entirely.
		[]byte(`{"iss":"yauth-fuzz","sub":"","token_use":"yauth_access","exp":` + strconv.FormatInt(exp, 10) + `}`),
		[]byte(`{"iss":"yauth-fuzz","token_use":"yauth_access","exp":` + strconv.FormatInt(exp, 10) + `}`),
		// Claim-type confusion: aud as an array, token_use as a number, orgs
		// as a scalar, exp as a string.
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","aud":["a","b"],"exp":` + strconv.FormatInt(exp, 10) + `}`),
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","token_use":1,"exp":` + strconv.FormatInt(exp, 10) + `}`),
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","orgs":"org-1","exp":` + strconv.FormatInt(exp, 10) + `}`),
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","exp":"soon"}`),
		// Duplicate token_use keys, wrong issuer, no exp at all.
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","token_use":"id_token","token_use":"yauth_access","exp":` + strconv.FormatInt(exp, 10) + `}`),
		[]byte(`{"iss":"attacker","sub":"user-1","token_use":"yauth_access","exp":` + strconv.FormatInt(exp, 10) + `}`),
		[]byte(`{"iss":"yauth-fuzz","sub":"user-1","token_use":"yauth_access"}`),
		// Not an object at all.
		[]byte(`null`),
		[]byte(`[1,2,3]`),
		[]byte(``),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		pt, err := verifyAccessToken(secret, sign(payload), cfg)
		if err != nil {
			return
		}
		if pt.UserID == "" {
			t.Fatalf("verifyAccessToken accepted payload %q with no subject", payload)
		}
		// The payload unmarshalled cleanly into accessClaims inside
		// verifyAccessToken, so it unmarshals here too; a failure means the
		// shapes have diverged and the assertions below would be meaningless.
		var body struct {
			TokenUse string `json:"token_use"`
		}
		if jsonErr := json.Unmarshal(payload, &body); jsonErr != nil {
			t.Fatalf("verifyAccessToken accepted payload %q that does not unmarshal: %v", payload, jsonErr)
		}
		switch body.TokenUse {
		case firstPartyTokenUse, accessTokenUse:
			// Recognised credentials.
		case "":
			// Migration window only. A marker-less token bearing an audience
			// is some other kind of JWT — an id_token, a DCR token — and must
			// not have been accepted as a credential.
			if len(pt.Audience) > 0 {
				t.Fatalf("verifyAccessToken accepted marker-less payload %q carrying aud %v", payload, pt.Audience)
			}
		default:
			t.Fatalf("verifyAccessToken accepted payload %q with unrecognised token_use %q", payload, body.TokenUse)
		}
	})
}
