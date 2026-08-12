// Regression suite for the refresh-token issuer-confusion bypass, plus the
// shared harness the service-account suite reuses.
//
// Refresh tokens lived in ONE unqualified namespace across TWO issuers. The
// bearer plugin (first-party email+password) and the oauth2server plugin
// (per-client OAuth2/OIDC) both wrote yauth_refresh_tokens and both redeemed
// on the bare token hash, so a token presented at the wrong issuer was
// honoured: a third-party client's "openid" refresh token bought a full
// first-party access token, a first-party token was redeemable by any
// registered public client, and client A's token was redeemable by client B.
//
// Each case asserts the REFUSAL — a 401/403 and, where a credential would
// have been minted, that no credential came back — and pairs it with a
// positive control so a future "fix" cannot pass by breaking the feature.
package yauth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const (
	secJWTSecret = "regression-secret-for-authz-tests-32b"
	secPassword  = "correct horse battery staple 9!Z"
)

type secHarness struct {
	srv  *httptest.Server
	repo *memrepo.Repo
}

func (h *secHarness) url(path string) string { return h.srv.URL + "/api/auth" + path }

type secNullMailer struct{}

func (secNullMailer) SendVerification(context.Context, string, string) error  { return nil }
func (secNullMailer) SendPasswordReset(context.Context, string, string) error { return nil }
func (secNullMailer) SendAccountExists(context.Context, string) error         { return nil }

// newSecHarness boots a server with the plugin set each case needs. The
// builder is passed in so a case only wires what it exercises — the
// service-account cases must NOT load oauth2server, and vice versa, so a
// regression cannot hide behind an unrelated plugin's routes.
func newSecHarness(t *testing.T, with func(*yauth.YAuthBuilder) *yauth.YAuthBuilder) *secHarness {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.RateLimit = yauth.RateLimitConfig{}

	b := yauth.New(r, cfg).
		WithJWTSecret([]byte(secJWTSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 12,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
			Mailer:            secNullMailer{},
		}))
	ya, err := with(b).Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &secHarness{srv: srv, repo: r}
}

func secPostJSON(t *testing.T, u string, body any) (int, []byte) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", u, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

func secPostForm(t *testing.T, u string, form url.Values) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", u, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

// secKeyCall issues a request authenticated with an X-Api-Key.
func secKeyCall(t *testing.T, method, u, key string, body any) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, u, rdr)
	req.Header.Set("X-Api-Key", key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func secRegister(t *testing.T, h *secHarness, email string) string {
	t.Helper()
	code, body := secPostJSON(t, h.url("/register"), map[string]any{
		"email": email, "password": secPassword,
	})
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register %s: %d %s", email, code, body)
	}
	u, err := h.repo.GetUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("lookup %s: %v", email, err)
	}
	return u.ID
}

func secRawJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func secS256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// 1. Refresh-token issuer binding
// ---------------------------------------------------------------------------

func newOAuth2Harness(t *testing.T) *secHarness {
	t.Helper()
	return newSecHarness(t, func(b *yauth.YAuthBuilder) *yauth.YAuthBuilder {
		return b.
			WithPlugin(bearer.New(bearer.Config{
				AccessTTL:  15 * time.Minute,
				RefreshTTL: 24 * time.Hour,
			})).
			WithPlugin(oauth2server.New(oauth2server.Config{
				Issuer:      "http://idp.test",
				BasePath:    "/api/auth",
				AuthCodeTTL: time.Minute,
				AccessTTL:   15 * time.Minute,
				RefreshTTL:  24 * time.Hour,
			}))
	})
}

// secSeedClient registers a PUBLIC oauth2 client — the sort any third-party
// SPA, or a DCR-registered client, would be. A public client authenticates at
// the token endpoint with client_id alone.
func secSeedClient(t *testing.T, h *secHarness, clientID string) {
	t.Helper()
	if err := h.repo.CreateOAuth2Client(context.Background(), domain.NewOAuth2Client{
		ID:           "c-" + clientID,
		ClientID:     clientID,
		RedirectURIs: secRawJSON([]string{"https://third-party.example/cb"}),
		GrantTypes:   secRawJSON([]string{"authorization_code", "refresh_token"}),
		Scopes:       secRawJSON([]string{"openid"}),
		IsPublic:     true,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create client %s: %v", clientID, err)
	}
}

// secClientRefreshToken runs a real authorization_code exchange for clientID,
// seeding the code exactly as /authorize would after the user consented to
// scope "openid", and returns the refresh token handed to that client.
func secClientRefreshToken(t *testing.T, h *secHarness, clientID, userID, codeID string) string {
	t.Helper()
	verifier := "verifier-verifier-verifier-verifier-0123"
	rawCode := "authcode-" + codeID
	if err := h.repo.CreateAuthorizationCode(context.Background(), domain.NewAuthorizationCode{
		ID:                  codeID,
		CodeHash:            auth.HashToken(rawCode),
		ClientID:            clientID,
		UserID:              userID,
		Scopes:              secRawJSON([]string{"openid"}),
		RedirectURI:         "https://third-party.example/cb",
		CodeChallenge:       secS256(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().UTC().Add(time.Minute),
		CreatedAt:           time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed auth code: %v", err)
	}
	code, body := secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {rawCode},
		"redirect_uri":  {"https://third-party.example/cb"},
		"code_verifier": {verifier},
		"client_id":     {clientID},
	})
	if code != http.StatusOK {
		t.Fatalf("authorization_code exchange for %s: %d %s", clientID, code, body)
	}
	var tok struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.RefreshToken == "" {
		t.Fatalf("no refresh token in %s (err=%v)", body, err)
	}
	return tok.RefreshToken
}

// secBearerRefreshToken performs a first-party password login and returns the
// refresh token the bearer plugin issued.
func secBearerRefreshToken(t *testing.T, h *secHarness, email string) string {
	t.Helper()
	code, body := secPostJSON(t, h.url("/token"), map[string]any{
		"email": email, "password": secPassword,
	})
	if code != http.StatusOK {
		t.Fatalf("bearer /token: %d %s", code, body)
	}
	var tok struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.RefreshToken == "" {
		t.Fatalf("no refresh token in %s (err=%v)", body, err)
	}
	return tok.RefreshToken
}

// secAssertNoToken fails when a response body carries any minted credential.
// Checking the status alone is not enough: the point of the finding was that
// a token came back.
func secAssertNoToken(t *testing.T, what string, body []byte) {
	t.Helper()
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	_ = json.Unmarshal(body, &out)
	if out.AccessToken != "" || out.RefreshToken != "" || out.IDToken != "" {
		t.Fatalf("%s: a credential was issued: %s", what, body)
	}
}

// A refresh token issued to a THIRD-PARTY OAuth2 client must not be redeemable
// at the first-party bearer endpoint. It used to be: the third party consented
// to a read-only "openid" identity scope and walked away with a first-party
// access token that every RequireAuth route accepted as the full user.
func TestRefreshIssuerBinding_OAuth2TokenRefusedByBearerRefresh(t *testing.T) {
	h := newOAuth2Harness(t)
	uid := secRegister(t, h, "victim-a@test.local")
	secSeedClient(t, h, "third-party-app")
	rt := secClientRefreshToken(t, h, "third-party-app", uid, "ac-a")

	code, body := secPostJSON(t, h.url("/token/refresh"), map[string]any{"refresh_token": rt})
	if code != http.StatusUnauthorized {
		t.Fatalf("bearer /token/refresh accepted an OAuth2 client's refresh token: %d %s", code, body)
	}
	secAssertNoToken(t, "bearer /token/refresh", body)

	// Positive control: the token still works where it belongs, so the
	// refusal above is issuer binding and not a broken refresh path.
	code, body = secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"third-party-app"},
	})
	if code != http.StatusOK {
		t.Fatalf("the issuing client can no longer refresh its own token: %d %s", code, body)
	}
}

// The mirror image: a first-party (bearer) refresh token must not be
// redeemable at /oauth/token by a registered client. A public client
// authenticates with client_id alone, so ANY registered client could turn a
// leaked first-party token into an access token — and an id_token — scoped to
// itself.
func TestRefreshIssuerBinding_BearerTokenRefusedByOAuth2Refresh(t *testing.T) {
	h := newOAuth2Harness(t)
	secRegister(t, h, "victim-b@test.local")
	secSeedClient(t, h, "attacker-app")
	rt := secBearerRefreshToken(t, h, "victim-b@test.local")

	code, body := secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"attacker-app"},
	})
	if code == http.StatusOK {
		t.Fatalf("/oauth/token accepted a first-party refresh token for an unrelated client: %s", body)
	}
	secAssertNoToken(t, "/oauth/token", body)

	// The rejected attempt must not have disturbed the victim's session:
	// the check runs before rotation and before reuse detection, so the
	// token is still live at its own issuer.
	code, body = secPostJSON(t, h.url("/token/refresh"), map[string]any{"refresh_token": rt})
	if code != http.StatusOK {
		t.Fatalf("the rejected cross-issuer attempt invalidated the user's own token: %d %s", code, body)
	}
}

// Client-to-client confusion: two registered clients, and A's refresh token
// presented by B. Redemption used to compare nothing at all, so B was handed
// A's user's tokens.
func TestRefreshIssuerBinding_ClientAToClientBRefused(t *testing.T) {
	h := newOAuth2Harness(t)
	uid := secRegister(t, h, "victim-c@test.local")
	secSeedClient(t, h, "client-a")
	secSeedClient(t, h, "client-b")
	rtA := secClientRefreshToken(t, h, "client-a", uid, "ac-c")

	code, body := secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rtA},
		"client_id":     {"client-b"},
	})
	if code == http.StatusOK {
		t.Fatalf("client-b redeemed client-a's refresh token: %s", body)
	}
	secAssertNoToken(t, "client-b refresh", body)

	// And client A is unharmed — B could not even revoke A's family by
	// tripping reuse detection.
	code, body = secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rtA},
		"client_id":     {"client-a"},
	})
	if code != http.StatusOK {
		t.Fatalf("client-a lost its own refresh token to client-b's attempt: %d %s", code, body)
	}
}

// Migration compatibility: rows written before the client_id discriminator
// existed carry NULL, which means first-party. A phone holding a refresh token
// issued by the previous release must still be able to refresh after the
// upgrade.
func TestRefreshIssuerBinding_PreMigrationRowStillRefreshes(t *testing.T) {
	h := newOAuth2Harness(t)
	uid := secRegister(t, h, "victim-d@test.local")

	// A row exactly as the old code wrote it: no client, no discriminator.
	raw := "legacy-refresh-token-from-before-the-migration"
	if err := h.repo.CreateRefreshToken(context.Background(), domain.NewRefreshToken{
		ID:        "legacy-rt",
		UserID:    uid,
		TokenHash: auth.HashToken(raw),
		FamilyID:  "legacy-family",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed legacy refresh token: %v", err)
	}

	code, body := secPostJSON(t, h.url("/token/refresh"), map[string]any{"refresh_token": raw})
	if code != http.StatusOK {
		t.Fatalf("a pre-migration refresh token was rejected: %d %s", code, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(body, &out)
	if out.AccessToken == "" {
		t.Fatalf("no access token for a pre-migration refresh: %s", body)
	}
}
