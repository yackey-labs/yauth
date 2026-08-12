// Regression suite for OAuth2 access tokens carrying full account authority.
//
// An access token minted for a relying party — `aud` its client_id, `scope`
// whatever the user consented to — was accepted by RequireAuth on EVERY route.
// The bearer resolver read `scope` nowhere, checked `aud` against nothing, and
// AuthUser/Principal had no field either claim could have landed in. So a user
// clicking "sign in with yauth" on any registered app handed that app:
//
//   - POST /api-keys                    → 201 and a PERMANENT personal API key
//     secret, a credential that outlives the OAuth grant and is not revoked
//     when the user revokes the app;
//   - DELETE /mfa/totp                  → the user's second factor stripped;
//   - POST /mfa/backup-codes/regenerate → fresh backup codes, i.e. a standing
//     MFA bypass held by the third party.
//
// Each case here asserts the REFUSAL at the level that matters — no key row
// written, no TOTP row deleted, not merely a non-200 status — and pairs it
// with a positive control so a future "fix" cannot pass by breaking bearer
// auth outright.
//
// The compatibility line these cases pin down: a delegated token still
// AUTHENTICATES. It resolves to the user and reaches ordinary application
// routes (the /app/resource stand-in below, protected by middleware.RequireAuth
// exactly as a consumer protects theirs). Only the personal-credential routes
// refuse it. That is what lets the default —
// no configured resource identifier, therefore every OAuth2 access token is
// delegated — close the hole without rejecting anything on upgrade.
package yauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/plugins/passkey"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const (
	// delegatedHS256Secret is the deployment's HS256 secret. oauth2server
	// falls back to exactly this secret when no asymmetric signer is loaded,
	// which is why the HS256 case below is a hole by the same route.
	delegatedHS256Secret = "hs256-secret-secret-secret-secret"
	delegatedIssuer      = "yauth-test"
	// thirdPartyClientID is the `aud` of a token issued to a relying party:
	// the app's client_id, not this API.
	thirdPartyClientID = "third-party-analytics-app"
	// firstPartyResource is an audience the deployment claims as its OWN in
	// bearer.Config.ResourceIdentifiers.
	firstPartyResource = "https://api.example.test"
)

// delegatedEnv is a full yauth.Build() server with the plugins that own the
// personal-credential routes, plus the raw repo so a case can assert on
// STORED STATE rather than on a status code.
type delegatedEnv struct {
	srv    *httptest.Server
	repo   *memrepo.Repo
	signer *delegatedSigner
	userID string
	mfaKey [32]byte
}

func newDelegatedEnv(t *testing.T, resourceIdentifiers ...string) *delegatedEnv {
	t.Helper()

	repo := memrepo.New()
	ctx := context.Background()
	now := time.Now().UTC()

	uid := uuid.NewString()
	if _, err := repo.CreateUser(ctx, domain.NewUser{
		ID: uid, Email: "victim@example.test", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	signer := newDelegatedSigner(t)

	var mfaKey [32]byte
	mfaKey[0] = 1
	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: mfaKey})
	if err != nil {
		t.Fatalf("mfa plugin: %v", err)
	}
	passkeyPlugin, err := passkey.New(passkey.Config{
		RPID:      "localhost",
		RPOrigins: []string{"http://localhost"},
	})
	if err != nil {
		t.Fatalf("passkey plugin: %v", err)
	}
	asymPlugin, err := asymjwt.New(asymjwt.Config{
		KeyType:       "RS256",
		KID:           "test-key",
		PrivateKeyPEM: signer.privPEM,
		PublicKeyPEM:  signer.pubPEM,
	})
	if err != nil {
		t.Fatalf("asymjwt plugin: %v", err)
	}

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(bearer.New(bearer.Config{
			JWTSecret:           []byte(delegatedHS256Secret),
			Issuer:              delegatedIssuer,
			ResourceIdentifiers: resourceIdentifiers,
		})).
		WithPlugin(asymPlugin).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(mfaPlugin).
		WithPlugin(passkeyPlugin).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	// An ORDINARY application route, protected the way a consumer protects
	// theirs: middleware.RequireAuth. The compatibility claim is about routes
	// like this one — a delegated token must still reach them.
	mux := http.NewServeMux()
	mux.Handle("/app/resource", ya.Middleware().RequireAuth(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	))
	mux.Handle("/", ya.Router())

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &delegatedEnv{srv: srv, repo: repo, signer: signer, userID: uid, mfaKey: mfaKey}
}

// delegatedToken mints the token a relying party receives after the user
// consents: signed by the deployment's own asymmetric key, `token_use=access`,
// `aud` the RP's client_id, `scope` what was consented to.
func (e *delegatedEnv) delegatedToken(t *testing.T, aud, scope string) string {
	t.Helper()
	now := time.Now().UTC()
	tok, err := e.signer.s.Sign(map[string]any{
		"iss":       "https://idp.test",
		"sub":       e.userID,
		"aud":       aud,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access",
		"scope":     scope,
	})
	if err != nil {
		t.Fatalf("sign delegated token: %v", err)
	}
	return tok
}

// firstPartyToken mints the token POST /token issues: HS256 on the
// deployment's secret, this plugin's issuer, and — the discriminator — NO
// token_use claim. It is the user's own credential and must keep working
// exactly as it did.
func (e *delegatedEnv) firstPartyToken(t *testing.T) string {
	t.Helper()
	now := time.Now().UTC()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": delegatedIssuer,
		"sub": e.userID,
		"jti": uuid.NewString(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}).SignedString([]byte(delegatedHS256Secret))
	if err != nil {
		t.Fatalf("sign first-party token: %v", err)
	}
	return tok
}

// oauth2HS256Token is the SAME OAuth2 access token as delegatedToken, but
// signed with the HS256 secret — the shape oauth2server.signAccessToken
// produces when no asymmetric signer is loaded, validated by the very secret
// the bearer plugin verifies against.
func (e *delegatedEnv) oauth2HS256Token(t *testing.T, aud, scope string) string {
	t.Helper()
	now := time.Now().UTC()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       delegatedIssuer,
		"sub":       e.userID,
		"jti":       uuid.NewString(),
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
		"token_use": "access",
		"aud":       aud,
		"scope":     scope,
	}).SignedString([]byte(delegatedHS256Secret))
	if err != nil {
		t.Fatalf("sign oauth2 hs256 token: %v", err)
	}
	return tok
}

// do issues a request bearing token and returns status + body.
func (e *delegatedEnv) do(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(raw)
}

// seedVerifiedTOTP writes a VERIFIED secret straight into the repo so a case
// can ask whether the factor SURVIVED. The ciphertext is opaque on purpose:
// these cases are refused by the route gate before anything decrypts it, and
// what they assert is that the ROW is still there afterwards.
func (e *delegatedEnv) seedVerifiedTOTP(t *testing.T) {
	t.Helper()
	if err := e.repo.CreateTOTP(context.Background(), domain.NewTOTPSecret{
		ID:              uuid.NewString(),
		UserID:          e.userID,
		EncryptedSecret: "opaque-ciphertext",
		Verified:        true,
		CreatedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed totp: %v", err)
	}
}

// enrolTOTPOverAPI runs the real setup → confirm enrolment as the holder of
// token, and returns the shared secret. Used by the first-party control, where
// the point is that the whole flow still works end to end.
func (e *delegatedEnv) enrolTOTPOverAPI(t *testing.T, token string) string {
	t.Helper()
	status, body := e.do(t, http.MethodPost, "/mfa/totp/setup", token, "")
	if status != http.StatusOK {
		t.Fatalf("POST /mfa/totp/setup: want 200, got %d (%s)", status, body)
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(body), &setup); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	if setup.Secret == "" {
		t.Fatalf("setup returned no secret")
	}
	// Confirm with the previous step's code (inside the ±1 window) so the
	// CURRENT step is still unspent for the step-up that follows — codes are
	// single-use.
	code, err := totp.GenerateCode(setup.Secret, time.Now().Add(-30*time.Second))
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	status, body = e.do(t, http.MethodPost, "/mfa/totp/confirm", token, `{"code":"`+code+`"}`)
	if status != http.StatusOK {
		t.Fatalf("POST /mfa/totp/confirm: want 200, got %d (%s)", status, body)
	}
	return setup.Secret
}

func (e *delegatedEnv) totpRowExists(t *testing.T) bool {
	t.Helper()
	verified := true
	row, err := e.repo.GetTOTPByUserID(context.Background(), e.userID, &verified)
	return err == nil && row != nil
}

func (e *delegatedEnv) apiKeyCount(t *testing.T) int {
	t.Helper()
	rows, err := e.repo.ListAPIKeysByUserID(context.Background(), e.userID)
	if err != nil {
		t.Fatalf("list api keys: %v", err)
	}
	return len(rows)
}

// --- the cases -----------------------------------------------------------

// POST /api-keys is the worst of the three: it hands the relying party a
// permanent secret that outlives the grant. The refusal is asserted on the
// STORE — no key row — because a 403 that still wrote the row would be no
// better than the 201.
func TestDelegatedToken_CannotMintPersonalAPIKey(t *testing.T) {
	env := newDelegatedEnv(t)
	token := env.delegatedToken(t, thirdPartyClientID, "openid profile")

	status, body := env.do(t, http.MethodPost, "/api-keys", token, `{"name":"exfil"}`)
	if status == http.StatusCreated {
		t.Fatalf("VULNERABLE: a scope=\"openid profile\" access token minted a personal API key: %s", body)
	}
	if status != http.StatusForbidden {
		t.Fatalf("POST /api-keys: want 403, got %d (%s)", status, body)
	}
	var out struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.Secret != "" {
		t.Fatalf("a key secret leaked in the refusal body")
	}
	if n := env.apiKeyCount(t); n != 0 {
		t.Fatalf("refused with %d, but %d key row(s) were written anyway", status, n)
	}
}

// DELETE /mfa/totp: the second factor must still be there afterwards.
func TestDelegatedToken_CannotStripMFA(t *testing.T) {
	env := newDelegatedEnv(t)
	env.seedVerifiedTOTP(t)
	token := env.delegatedToken(t, thirdPartyClientID, "openid profile")

	status, body := env.do(t, http.MethodDelete, "/mfa/totp", token, "")
	if status == http.StatusOK {
		t.Fatalf("VULNERABLE: DELETE /mfa/totp accepted a delegated access token: %s", body)
	}
	if status != http.StatusForbidden {
		t.Fatalf("DELETE /mfa/totp: want 403, got %d (%s)", status, body)
	}
	if !env.totpRowExists(t) {
		t.Fatalf("refused with %d, but the verified TOTP secret was deleted anyway", status)
	}
}

// POST /mfa/backup-codes/regenerate: a fresh set of codes IS a standing MFA
// bypass, and issuing one also invalidates the codes the user holds.
func TestDelegatedToken_CannotRegenerateBackupCodes(t *testing.T) {
	env := newDelegatedEnv(t)
	env.seedVerifiedTOTP(t)
	token := env.delegatedToken(t, thirdPartyClientID, "openid profile")

	status, body := env.do(t, http.MethodPost, "/mfa/backup-codes/regenerate", token, "")
	if status == http.StatusOK {
		t.Fatalf("VULNERABLE: backup codes regenerated for a delegated access token: %s", body)
	}
	if status != http.StatusForbidden {
		t.Fatalf("POST /mfa/backup-codes/regenerate: want 403, got %d (%s)", status, body)
	}
	var out struct {
		BackupCodes []string `json:"backup_codes"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if len(out.BackupCodes) != 0 {
		t.Fatalf("refused with %d, but %d backup codes were handed out", status, len(out.BackupCodes))
	}
}

// POST /mfa/totp/setup enrols a NEW factor. Reachable, it is takeover by
// another name: the relying party enrols an authenticator it controls.
func TestDelegatedToken_CannotEnrolNewFactor(t *testing.T) {
	env := newDelegatedEnv(t)
	token := env.delegatedToken(t, thirdPartyClientID, "openid profile")

	status, body := env.do(t, http.MethodPost, "/mfa/totp/setup", token, "")
	if status != http.StatusForbidden {
		t.Fatalf("POST /mfa/totp/setup: want 403, got %d (%s)", status, body)
	}
	var out struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.Secret != "" {
		t.Fatalf("a TOTP secret leaked in the refusal body")
	}
}

// Passkeys are the same shape of harm as an API key — a permanent credential
// enrolled on the account — so the same gate covers them.
func TestDelegatedToken_CannotBeginPasskeyRegistration(t *testing.T) {
	env := newDelegatedEnv(t)
	token := env.delegatedToken(t, thirdPartyClientID, "openid profile")

	status, body := env.do(t, http.MethodPost, "/passkeys/register/begin", token, "{}")
	if status != http.StatusForbidden {
		t.Fatalf("POST /passkeys/register/begin: want 403, got %d (%s)", status, body)
	}
}

// The HS256 deployment has the hole by another route: oauth2server falls back
// to host.JWTSecret(), the same secret bearer verifies against, and `aud` is
// only enforced when Config.Audience is set — not the default. The
// discriminator is the token_use claim, which the bearer plugin's own tokens
// never carry.
func TestDelegatedToken_HS256OAuth2TokenIsAlsoDelegated(t *testing.T) {
	env := newDelegatedEnv(t)
	env.seedVerifiedTOTP(t)
	token := env.oauth2HS256Token(t, thirdPartyClientID, "openid profile")

	status, body := env.do(t, http.MethodPost, "/api-keys", token, `{"name":"exfil"}`)
	if status != http.StatusForbidden {
		t.Fatalf("POST /api-keys with an HS256 OAuth2 access token: want 403, got %d (%s)", status, body)
	}
	if n := env.apiKeyCount(t); n != 0 {
		t.Fatalf("refused with %d, but %d key row(s) were written anyway", status, n)
	}

	status, body = env.do(t, http.MethodDelete, "/mfa/totp", token, "")
	if status != http.StatusForbidden {
		t.Fatalf("DELETE /mfa/totp with an HS256 OAuth2 access token: want 403, got %d (%s)", status, body)
	}
	if !env.totpRowExists(t) {
		t.Fatalf("the verified TOTP secret was deleted by an HS256 OAuth2 access token")
	}
}

// THE COMPATIBILITY CONTROL. A delegated token is not rejected — it still
// authenticates and reaches ordinary routes. This is what makes the default
// (no resource identifier configured ⇒ every OAuth2 access token delegated)
// safe to ship: OIDC relying parties calling /userinfo and application read
// routes are unaffected, and only the personal-credential routes narrow.
func TestDelegatedToken_StillAuthenticatesOnOrdinaryRoutes(t *testing.T) {
	env := newDelegatedEnv(t)
	token := env.delegatedToken(t, thirdPartyClientID, "openid profile")

	status, body := env.do(t, http.MethodGet, "/app/resource", token, "")
	if status != http.StatusOK {
		t.Fatalf("an ordinary RequireAuth route with a delegated token: want 200, got %d (%s)", status, body)
	}
}

// THE FIRST-PARTY CONTROL. The token pair from POST /token carries no
// token_use claim, is the user's own credential, and must keep FULL authority
// on exactly the routes the delegated token was just refused on. If this
// breaks, the fix was too broad.
func TestFirstPartyBearerToken_KeepsFullAuthority(t *testing.T) {
	env := newDelegatedEnv(t)
	token := env.firstPartyToken(t)

	status, body := env.do(t, http.MethodPost, "/api-keys", token, `{"name":"my-cli"}`)
	if status != http.StatusCreated {
		t.Fatalf("POST /api-keys with a first-party bearer token: want 201, got %d (%s)", status, body)
	}
	if n := env.apiKeyCount(t); n != 1 {
		t.Fatalf("expected the key to be written; got %d rows", n)
	}

	// The whole MFA lifecycle still runs end to end for it: enrol, confirm,
	// and — presenting the factor, which is finding 2's control, not finding
	// 1's — remove.
	secret := env.enrolTOTPOverAPI(t, token)
	if !env.totpRowExists(t) {
		t.Fatalf("enrolment over the API did not install a verified secret")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	req, _ := http.NewRequest(http.MethodDelete, env.srv.URL+"/mfa/totp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(mfa.StepUpHeader, code)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /mfa/totp with a first-party bearer token + step-up: want 200, got %d (%s)",
			res.StatusCode, string(raw))
	}
	if env.totpRowExists(t) {
		t.Fatalf("first-party delete with a valid step-up left the secret in place")
	}
}

// A deployment that genuinely issues access tokens FOR ITSELF names that
// audience in bearer.Config.ResourceIdentifiers, and those tokens behave like
// a session again. This is the escape hatch that keeps the safe default from
// being a dead end — and it is audience-scoped, so the third-party token in
// the SAME deployment stays refused.
func TestDelegatedToken_ConfiguredResourceAudienceIsFirstParty(t *testing.T) {
	env := newDelegatedEnv(t, firstPartyResource)

	ours := env.delegatedToken(t, firstPartyResource, "openid profile")
	status, body := env.do(t, http.MethodPost, "/api-keys", ours, `{"name":"our-spa"}`)
	if status != http.StatusCreated {
		t.Fatalf("token audienced at a declared resource identifier: want 201, got %d (%s)", status, body)
	}

	theirs := env.delegatedToken(t, thirdPartyClientID, "openid profile")
	status, body = env.do(t, http.MethodPost, "/api-keys", theirs, `{"name":"exfil"}`)
	if status != http.StatusForbidden {
		t.Fatalf("third-party audience in the same deployment: want 403, got %d (%s)", status, body)
	}
	if n := env.apiKeyCount(t); n != 1 {
		t.Fatalf("expected exactly the first-party key to exist; got %d rows", n)
	}
}

// --- helpers -------------------------------------------------------------

type delegatedSigner struct {
	s       *asymjwt.Signer
	privPEM []byte
	pubPEM  []byte
}

func newDelegatedSigner(t *testing.T) *delegatedSigner {
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
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	s, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType: "RS256", KID: "test-key",
		PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM,
	})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return &delegatedSigner{s: s, privPEM: privPEM, pubPEM: pubPEM}
}
