// Regression suite for HS256 JWT kind confusion.
//
// verifyAsymAccessToken carries a POSITIVE type gate — `token_use` must be
// "access" — and its doc comment says exactly why: id_tokens and DCR
// registration-access tokens are signed by the same key and would otherwise be
// replayable as API credentials. verifyAccessToken, the HS256 twin validating
// against host.JWTSecret(), had no such gate. It read `token_use` only to
// DOWNGRADE the tokens that carried it, so a JWT with no `token_use` at all
// fell through to a full-authority, non-delegated user principal.
//
// Three token families are signed with that same secret on a deployment
// running oauth2server without asymjwt (the supported HS256 fallback):
//
//	signIDToken                 iss/sub/aud/exp/iat/email, no token_use
//	signRegistrationAccessToken iss/sub/aud/scope/client_id/iat/exp/jti, no token_use
//	signLogoutToken             iss/aud/sub/iat/jti/events, no token_use AND no exp
//
// Each is handed to a party that is not the user: the id_token goes to the
// relying party (and through it, the browser), the registration token to
// whoever called DCR, the logout token to every RP's back-channel endpoint. Any
// of them replayed as `Authorization: Bearer ...` used to resolve as the user
// acting in their own right — enough to mint a permanent personal API key or
// strip the user's MFA, which is precisely the hole #85 closed on the
// asymmetric path.
//
// Each case asserts the REFUSAL at the level that matters — no full-authority
// principal — and is paired with a positive control so a future "fix" cannot
// pass by breaking first-party bearer tokens or OAuth2 access tokens outright.
package bearer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth/domain"
)

const (
	kindTestUID    = "66666666-6666-6666-6666-666666666666"
	kindTestIssuer = "https://idp.test"
)

var kindTestSecret = []byte("hs256-secret-secret-secret-secret")

// newKindHarness seeds a user and returns a resolver whose issuer matches the
// one the oauth2-server plugin signs with. Issuer parity is not an exotic
// misconfiguration: it is REQUIRED for the HS256 OAuth2 access-token path that
// verifyAccessToken documents and that security_delegated_token_test.go
// configures, and examples/sso/idp wires both plugins from one shared issuer.
func newKindHarness(t *testing.T) *bearerResolver {
	t.Helper()
	fr := newFakeRepo()
	now := time.Now().UTC()
	if _, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: kindTestUID, Email: "rp@example.test", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	host := newFakeHost(fr, kindTestSecret)
	// No asymmetric signer: this is the HS256 fallback deployment.
	return newResolver(host, Config{
		JWTSecret: kindTestSecret,
		AccessTTL: time.Minute,
		Issuer:    kindTestIssuer,
	})
}

// signHS256 mints a token with the deployment's shared HS256 secret, the way
// every oauth2server fallback path does.
func signHS256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(kindTestSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// resolveBearer presents raw as a Bearer credential on a route that mints
// credentials, which is where the authority distinction bites.
func resolveBearer(t *testing.T, res *bearerResolver, raw string) (*domain.AuthUser, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api-keys", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	au, _, err := res.Resolve(r)
	return au, err
}

// TestResolver_HS256IDToken_IsNotAFirstPartyCredential is the headline case.
// The claim set is copied field for field from oauth2server.signIDToken's
// HS256 fallback.
func TestResolver_HS256IDToken_IsNotAFirstPartyCredential(t *testing.T) {
	res := newKindHarness(t)
	now := time.Now().UTC()

	idToken := signHS256(t, jwt.MapClaims{
		"iss":            kindTestIssuer,
		"sub":            kindTestUID,
		"aud":            "some-relying-party",
		"exp":            now.Add(time.Minute).Unix(),
		"iat":            now.Unix(),
		"email":          "rp@example.test",
		"email_verified": true,
	})

	au, err := resolveBearer(t, res, idToken)
	if err == nil && au != nil && !au.Principal.IsDelegated() {
		t.Fatal("an id_token was accepted as a full-authority first-party credential: " +
			"the holder can mint a permanent personal API key and strip the user's MFA")
	}
}

// TestResolver_HS256RegistrationAccessToken_IsNotAFirstPartyCredential covers
// the DCR management credential, which is handed to whoever registered a
// client — on an anonymous-DCR deployment, any unauthenticated caller.
func TestResolver_HS256RegistrationAccessToken_IsNotAFirstPartyCredential(t *testing.T) {
	res := newKindHarness(t)
	now := time.Now().UTC()

	// sub is a client_id in the real thing, which fails the user lookup. Point
	// it at a real user id so the test exercises the TYPE gate rather than
	// coincidentally passing on a missing-user error.
	regToken := signHS256(t, jwt.MapClaims{
		"iss":       kindTestIssuer,
		"sub":       kindTestUID,
		"aud":       "generated-client-id",
		"scope":     "registration",
		"client_id": "generated-client-id",
		"iat":       now.Unix(),
		"exp":       now.Add(24 * time.Hour).Unix(),
		"jti":       "reg-jti",
	})

	au, err := resolveBearer(t, res, regToken)
	if err == nil && au != nil && !au.Principal.IsDelegated() {
		t.Fatal("a DCR registration-access token was accepted as a full-authority credential")
	}
}

// TestResolver_HS256LogoutToken_IsNotACredential covers the back-channel
// logout token, which is POSTed to every relying party's logout endpoint —
// including one an attacker registered through DCR. It carries no `exp` at
// all, so accepting it would be an immortal credential.
func TestResolver_HS256LogoutToken_IsNotACredential(t *testing.T) {
	res := newKindHarness(t)
	now := time.Now().UTC()

	logoutToken := signHS256(t, jwt.MapClaims{
		"iss": kindTestIssuer,
		"aud": "some-relying-party",
		"sub": kindTestUID,
		"iat": now.Unix(),
		"jti": "logout-jti",
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	})

	au, err := resolveBearer(t, res, logoutToken)
	if err == nil && au != nil {
		t.Fatal("a back-channel logout token authenticated as the user")
	}
}

// --- positive controls -------------------------------------------------
//
// The gate must not be satisfied by refusing everything.

// TestResolver_HS256FirstPartyToken_KeepsFullAuthority proves this plugin's
// OWN /token credential still resolves as the user acting in their own right.
func TestResolver_HS256FirstPartyToken_KeepsFullAuthority(t *testing.T) {
	res := newKindHarness(t)
	now := time.Now().UTC()

	raw, _, err := signAccessToken(kindTestSecret, kindTestUID, "jti-1", Config{
		AccessTTL: time.Minute, Issuer: kindTestIssuer,
	}, now, activeOrgClaims{})
	if err != nil {
		t.Fatalf("sign first-party token: %v", err)
	}

	au, err := resolveBearer(t, res, raw)
	if err != nil {
		t.Fatalf("first-party bearer token must still resolve: %v", err)
	}
	if au == nil || au.User.ID != kindTestUID {
		t.Fatalf("expected AuthUser for %s, got %+v", kindTestUID, au)
	}
	if au.Principal.IsDelegated() {
		t.Fatal("this plugin's own /token credential must keep full authority")
	}
}

// TestResolver_HS256OAuth2AccessToken_StillResolvesAsDelegated proves the
// OAuth2 HS256 access token keeps working — relying parties must still reach
// /userinfo — and keeps being classified as delegated.
func TestResolver_HS256OAuth2AccessToken_StillResolvesAsDelegated(t *testing.T) {
	res := newKindHarness(t)
	now := time.Now().UTC()

	accessToken := signHS256(t, jwt.MapClaims{
		"iss":       kindTestIssuer,
		"sub":       kindTestUID,
		"aud":       "some-relying-party",
		"exp":       now.Add(time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "at-jti",
		"token_use": "access",
		"scope":     "openid email",
	})

	au, err := resolveBearer(t, res, accessToken)
	if err != nil {
		t.Fatalf("an OAuth2 HS256 access token must still resolve: %v", err)
	}
	if au == nil || au.User.ID != kindTestUID {
		t.Fatalf("expected AuthUser for %s, got %+v", kindTestUID, au)
	}
	if !au.Principal.IsDelegated() {
		t.Fatal("an OAuth2 access token audienced at a relying party must stay delegated")
	}
	if !au.Principal.HasScope("email") {
		t.Fatal("expected the granted scope to survive")
	}
}

// TestResolver_HS256LegacyTokenWithoutAudience_StillResolves protects the
// upgrade path. A first-party token minted BEFORE this plugin stamped a
// `token_use` marker carries no marker — and, because Config.Audience is
// unset, no `aud` either. Such a token must keep working for the remainder of
// its TTL rather than logging every active user out on deploy.
func TestResolver_HS256LegacyTokenWithoutAudience_StillResolves(t *testing.T) {
	res := newKindHarness(t)
	now := time.Now().UTC()

	legacy := signHS256(t, jwt.MapClaims{
		"iss": kindTestIssuer,
		"sub": kindTestUID,
		"jti": "legacy-jti",
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})

	au, err := resolveBearer(t, res, legacy)
	if err != nil {
		t.Fatalf("a pre-upgrade first-party token must still resolve: %v", err)
	}
	if au == nil || au.Principal.IsDelegated() {
		t.Fatalf("a pre-upgrade first-party token must keep full authority, got %+v", au)
	}
}
