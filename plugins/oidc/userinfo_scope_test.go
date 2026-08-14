package oidc_test

// /userinfo (plugins/oidc/handlers.go, oidcPlugin.userInfo) is the endpoint a
// relying party calls with the access token it just received from
// POST /oauth/token. It reads au.User and emits sub, email, email_verified, name
// and every group name UNCONDITIONALLY — au.Principal is never consulted.
//
// Two things follow, both reachable over HTTP through the routes
// plugins/oidc/plugin.go registers:
//
//  1. Scope means nothing here. An RP that ran the authorization-code flow
//     asking only for `openid` still gets the user's email address, display name
//     and the full list of their group memberships. The very same product
//     withholds groups from the ID TOKEN unless the `groups` scope was granted
//     (oauth2server/token.go) and advertises scopes_supported
//     [openid email profile groups] in its own discovery document — so the
//     consent the user gave is enforced in one place and ignored in the other.
//     domain.Principal.HasScope already implements exactly the right rule
//     (true for every non-delegated credential, membership test for a delegated
//     one) and has zero production callers.
//
//  2. An org-scoped API key gets a HUMAN's identity. plugins/apikey/resolver.go
//     resolves a service-account key to AuthUser{User: *creator} tagged
//     PrincipalKindServiceAccount, so /userinfo answers a machine credential with
//     the key creator's sub, email, name and groups. That credential deliberately
//     outlives its creator's own access — the resolver keeps an org key alive when
//     the creator is banned — so this is the creator's identity leaking through a
//     credential that is not theirs.
//
// The refusals below are paired with positive controls: a cookie session and a
// USER-scoped API key must keep receiving the full claim set (they are the user
// acting directly, and no consent screen ever narrowed them), and a delegated
// token that WAS granted email+groups must still receive email and groups.

import (
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

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// opHarness is a full OP: asymjwt (so oauth2server mints RS256 access tokens the
// bearer resolver can verify), oauth2server (authorize/consent/token), apikey and
// oidc. newServer in handlers_test.go loads only asymjwt+oidc, which cannot reach
// /userinfo with anything but a cookie — hence this extension rather than a
// parallel harness for the parts that already exist.
type opHarness struct {
	srv  *httptest.Server
	repo *memrepo.Repo
}

func newOPHarness(t *testing.T) *opHarness {
	t.Helper()
	r := memrepo.New()
	dir := t.TempDir()
	priv, pub := writeRSAKeys(t, dir)
	asym, err := asymjwt.New(asymjwt.Config{KeyType: "RS256", PrivateKeyPath: priv, PublicKeyPath: pub, KID: "test-kid"})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(asym).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer: "http://idp.test", BasePath: "/api/auth",
			AccessTTL: 5 * time.Minute, AuthCodeTTL: time.Minute,
		})).
		WithPlugin(oidc.New(oidc.Config{Issuer: "http://idp.test", BasePath: "/api/auth"})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &opHarness{srv: srv, repo: r}
}

// seedUserWithRole creates a user and an active session.
func (h *opHarness) seedUserWithRole(t *testing.T, email, name, role string) (userID, cookie string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	dn := name
	u, err := h.repo.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: email, DisplayName: &dn, EmailVerified: true,
		Role: role, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	raw, _, err := auth.IssueSession(ctx, h.repo, u.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return u.ID, raw
}

// addToGroup puts userID in a freshly-created group, so ListGroupNamesForUser
// (the source of the groups claim) has something to return.
func (h *opHarness) addToGroup(t *testing.T, userID, groupName string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	org, err := h.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "O", Slug: "o-" + uuid.NewString()[:8], CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	g, err := h.repo.CreateGroup(ctx, domain.NewGroup{
		ID: uuid.NewString(), OrganizationID: org.ID, Name: groupName, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := h.repo.AddGroupMember(ctx, g.ID, userID, now); err != nil {
		t.Fatalf("add group member: %v", err)
	}
}

// registerRP registers a confidential relying party allowed to ask for the whole
// advertised scope set.
func (h *opHarness) registerRP(t *testing.T, adminCookie string) (clientID, secret string) {
	t.Helper()
	body := `{"name":"rp","redirect_uris":["https://rp.example/cb"],"grant_types":["authorization_code"],` +
		`"scopes":["openid","email","profile","groups"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create client: status=%d", res.StatusCode)
	}
	var out struct {
		Client       map[string]any `json:"client"`
		ClientSecret *string        `json:"client_secret"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode client: %v", err)
	}
	cid, _ := out.Client["client_id"].(string)
	return cid, *out.ClientSecret
}

// delegatedAccessToken runs the full authorization-code flow for scope and
// returns the RP's access token — a DELEGATED credential carrying exactly the
// scope the user consented to.
func (h *opHarness) delegatedAccessToken(t *testing.T, userCookie, clientID, secret, scope string) string {
	t.Helper()
	const verifier = "this-is-a-43-character-pkce-verifier-string-x"
	challenge := pkceChallenge(verifier)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://rp.example/cb")
	q.Set("scope", scope)
	q.Set("state", "s")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	var p struct {
		CSRFToken string `json:"csrf_token"`
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil || p.RequestID == "" {
		t.Fatalf("authorize: status=%d decode err=%v payload=%+v", res.StatusCode, err, p)
	}

	cb, _ := json.Marshal(map[string]any{"request_id": p.RequestID, "csrf_token": p.CSRFToken, "approved": true})
	creq, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/consent", strings.NewReader(string(cb)))
	creq.Header.Set("Content-Type", "application/json")
	creq.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	cres, err := http.DefaultClient.Do(creq)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	defer cres.Body.Close() //nolint:errcheck
	var rd struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.NewDecoder(cres.Body).Decode(&rd); err != nil {
		t.Fatalf("decode consent: %v", err)
	}
	parsed, err := url.Parse(rd.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", rd.RedirectURL)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://rp.example/cb")
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	form.Set("code_verifier", verifier)
	treq, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth/token", strings.NewReader(form.Encode()))
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tres, err := http.DefaultClient.Do(treq)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tres.Body.Close() //nolint:errcheck
	var tb map[string]any
	_ = json.NewDecoder(tres.Body).Decode(&tb)
	at, _ := tb["access_token"].(string)
	if at == "" {
		t.Fatalf("token: status=%d body=%v", tres.StatusCode, tb)
	}
	return at
}

// pkceChallenge is the S256 code_challenge for verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// userInfoRaw calls GET /userinfo with the given headers/cookies and returns the
// status, the decoded body as a generic map (so a test can assert a claim KEY is
// absent, not merely empty), and the raw bytes.
func (h *opHarness) userInfoRaw(t *testing.T, bearerToken, apiKey, cookie string) (int, map[string]any, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/userinfo", nil)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read userinfo body: %v", err)
	}
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	return res.StatusCode, body, string(b)
}

// TestUserInfo_OpenIDOnlyTokenGetsNoEmailNameOrGroups: consent was for `openid`
// and nothing else, so the RP must receive sub and nothing else.
func TestUserInfo_OpenIDOnlyTokenGetsNoEmailNameOrGroups(t *testing.T) {
	h := newOPHarness(t)
	_, adminCookie := h.seedUserWithRole(t, "admin@idp.test", "Admin", "admin")
	uid, userCookie := h.seedUserWithRole(t, "alice@idp.test", "Alice", "user")
	h.addToGroup(t, uid, "Engineering")
	clientID, secret := h.registerRP(t, adminCookie)

	at := h.delegatedAccessToken(t, userCookie, clientID, secret, "openid")
	status, body, raw := h.userInfoRaw(t, at, "", "")
	if status != http.StatusOK {
		t.Fatalf("an openid-scoped access token must still reach /userinfo: status=%d body=%s", status, raw)
	}
	if body["sub"] != uid {
		t.Fatalf("sub mismatch: got %v want %q", body["sub"], uid)
	}
	for _, claim := range []string{"email", "email_verified", "name", "groups"} {
		if _, present := body[claim]; present {
			t.Fatalf("scope=openid granted no %q, but /userinfo returned it: %s", claim, raw)
		}
	}
}

// TestUserInfo_ScopedTokenGetsGrantedClaims is the positive control for the gate:
// what WAS granted must still be delivered, and only that.
func TestUserInfo_ScopedTokenGetsGrantedClaims(t *testing.T) {
	h := newOPHarness(t)
	_, adminCookie := h.seedUserWithRole(t, "admin@idp.test", "Admin", "admin")
	uid, userCookie := h.seedUserWithRole(t, "alice@idp.test", "Alice", "user")
	h.addToGroup(t, uid, "Engineering")
	clientID, secret := h.registerRP(t, adminCookie)

	at := h.delegatedAccessToken(t, userCookie, clientID, secret, "openid email groups")
	status, body, raw := h.userInfoRaw(t, at, "", "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, raw)
	}
	if body["email"] != "alice@idp.test" {
		t.Fatalf("scope included email; expected it in the response: %s", raw)
	}
	groups, _ := body["groups"].([]any)
	if len(groups) == 0 || groups[0] != "Engineering" {
		t.Fatalf("scope included groups; expected Engineering: %s", raw)
	}
	if _, present := body["name"]; present {
		t.Fatalf("scope did NOT include profile, but /userinfo returned name: %s", raw)
	}
}

// TestUserInfo_CookieUnchanged is the contract guard for first-party callers: a
// session cookie is the user acting directly and must keep receiving everything.
func TestUserInfo_CookieUnchanged(t *testing.T) {
	h := newOPHarness(t)
	uid, userCookie := h.seedUserWithRole(t, "alice@idp.test", "Alice", "user")
	h.addToGroup(t, uid, "Engineering")

	status, body, raw := h.userInfoRaw(t, "", "", userCookie)
	if status != http.StatusOK {
		t.Fatalf("cookie /userinfo status=%d body=%s", status, raw)
	}
	if body["sub"] != uid || body["email"] != "alice@idp.test" || body["name"] != "Alice" {
		t.Fatalf("cookie caller lost claims: %s", raw)
	}
	groups, _ := body["groups"].([]any)
	if len(groups) == 0 || groups[0] != "Engineering" {
		t.Fatalf("cookie caller lost the groups claim: %s", raw)
	}
}

// seedAPIKey mints an API key row. When orgID is non-nil the key is org-scoped
// (a service account whose Principal is PrincipalKindServiceAccount); otherwise
// it is the user's own key.
func (h *opHarness) seedAPIKey(t *testing.T, ownerUserID string, orgID *string) string {
	t.Helper()
	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	role := "admin"
	nk := domain.NewAPIKey{
		ID: uuid.NewString(), KeyPrefix: gen.Prefix, KeyHash: gen.Hash, Name: "k",
		Role: &role, CreatedByUserID: ownerUserID, CreatedAt: time.Now().UTC(),
	}
	if orgID != nil {
		nk.OrganizationID = orgID
	} else {
		nk.UserID = &ownerUserID
	}
	if err := h.repo.CreateAPIKey(context.Background(), nk); err != nil {
		t.Fatalf("create api key: %v", err)
	}
	return gen.Plaintext
}

// TestUserInfo_ServiceAccountKeyRefused: a machine credential has no user
// identity, so /userinfo must not answer it with the key creator's person.
func TestUserInfo_ServiceAccountKeyRefused(t *testing.T) {
	h := newOPHarness(t)
	creatorID, _ := h.seedUserWithRole(t, "creator@idp.test", "Creator", "admin")
	h.addToGroup(t, creatorID, "Engineering")

	ctx := context.Background()
	now := time.Now().UTC()
	org, err := h.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	key := h.seedAPIKey(t, creatorID, &org.ID)

	status, _, raw := h.userInfoRaw(t, "", key, "")
	if strings.Contains(raw, "creator@idp.test") || strings.Contains(raw, creatorID) {
		t.Fatalf("an org-scoped service-account key received its creator's identity from /userinfo: status=%d body=%s", status, raw)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for a service-account key at /userinfo, got status=%d body=%s", status, raw)
	}
}

// TestUserInfo_UserScopedKeyStillWorks is the paired control: a USER-scoped key
// legitimately identifies its owner and must keep working — the refusal above
// must not be implemented by dropping the apiKey security scheme.
func TestUserInfo_UserScopedKeyStillWorks(t *testing.T) {
	h := newOPHarness(t)
	uid, _ := h.seedUserWithRole(t, "alice@idp.test", "Alice", "user")
	h.addToGroup(t, uid, "Engineering")
	key := h.seedAPIKey(t, uid, nil)

	status, body, raw := h.userInfoRaw(t, "", key, "")
	if status != http.StatusOK {
		t.Fatalf("a user-scoped API key must still reach /userinfo: status=%d body=%s", status, raw)
	}
	if body["sub"] != uid || body["email"] != "alice@idp.test" {
		t.Fatalf("user-scoped key lost its owner's claims: %s", raw)
	}
}
