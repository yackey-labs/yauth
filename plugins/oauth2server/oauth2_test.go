package oauth2server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/bearer"
	"github.com/yackey-labs/yauth-go/plugins/oauth2server"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

// --- harness -----------------------------------------------------------

type harness struct {
	srv  *httptest.Server
	repo *gormrepo.Repo
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)

	jwtSecret := []byte("test-only-jwt-secret-please-change-32b")

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret(jwtSecret).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:      "http://idp.test",
			BasePath:    "/api/auth",
			AccessTTL:   5 * time.Minute,
			AuthCodeTTL: 1 * time.Minute,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &harness{srv: srv, repo: r}
}

func (h *harness) seedUser(t *testing.T, email, role string) (id, cookie string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	dn := strings.Split(email, "@")[0]
	u, err := h.repo.CreateUser(ctx, domain.NewUser{
		ID:            uuid.NewString(),
		Email:         email,
		DisplayName:   &dn,
		EmailVerified: true,
		Role:          role,
		CreatedAt:     now,
		UpdatedAt:     now,
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

// createClient creates an OAuth2 client via the admin endpoint.
func (h *harness) createClient(t *testing.T, adminCookie string, body string) (clientID, clientSecret string, raw map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create client: status=%d", res.StatusCode)
	}
	var out struct {
		Client       map[string]any `json:"client"`
		ClientSecret *string        `json:"client_secret"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cid, _ := out.Client["client_id"].(string)
	cs := ""
	if out.ClientSecret != nil {
		cs = *out.ClientSecret
	}
	return cid, cs, out.Client
}

// authorizeAndConsent runs GET /authorize → POST /consent and returns
// the resulting authorization code (extracted from the redirect URL).
func (h *harness) authorizeAndConsent(t *testing.T, cookie, clientID, redirectURI, scope, challenge, state, nonce string) string {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if nonce != "" {
		q.Set("nonce", nonce)
	}

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authorize: status=%d", res.StatusCode)
	}
	var p struct {
		CSRFToken string `json:"csrf_token"`
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		t.Fatalf("decode authorize: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"request_id": p.RequestID,
		"csrf_token": p.CSRFToken,
		"approved":   true,
	})
	creq, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/consent", strings.NewReader(string(body)))
	creq.Header.Set("Content-Type", "application/json")
	creq.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	cres, err := http.DefaultClient.Do(creq)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	defer cres.Body.Close()
	if cres.StatusCode != http.StatusOK {
		t.Fatalf("consent: status=%d", cres.StatusCode)
	}
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
		t.Fatalf("no code in redirect: %s", rd.RedirectURL)
	}
	return code
}

// postForm POSTs form-urlencoded values to path and returns the
// response body as a map and status.
func (h *harness) postForm(t *testing.T, path string, form url.Values, basicID, basicSecret string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

// --- tests -------------------------------------------------------------

func TestAuthorizationCodeGrant_PKCE_HappyPath(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"demo","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code","refresh_token"],"scopes":["openid","read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	verifier := "this-is-a-43-character-pkce-verifier-string-x"
	challenge := pkceS256(verifier)

	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "openid read", challenge, "xyz", "n-1")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	status, body2 := h.postForm(t, "/api/auth/oauth2/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("token: status=%d body=%v", status, body2)
	}
	if _, ok := body2["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", body2)
	}
	if _, ok := body2["refresh_token"]; !ok {
		t.Fatalf("missing refresh_token: %v", body2)
	}
	if _, ok := body2["id_token"]; !ok {
		t.Fatalf("missing id_token (openid scope was requested): %v", body2)
	}
}

func TestAuthorizationCodeGrant_PKCEMismatch(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"demo","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	verifier := "the-correct-verifier-is-a-secret-43-chars-yo"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "read", challenge, "s1", "")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", "the-WRONG-verifier-but-also-43-chars-long-okay")

	status, b := h.postForm(t, "/api/auth/oauth2/token", form, "", "")
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%v", status, b)
	}
	if b["error"] != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %v", b["error"])
	}
}

func TestRefreshTokenGrant_RotatesAndOldRevoked(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"demo","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code","refresh_token"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	verifier := "another-43-char-verifier-here-stuff-yes-okay-x"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "read", challenge, "abc", "")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	status, body1 := h.postForm(t, "/api/auth/oauth2/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("first token: %d %v", status, body1)
	}
	first := body1["refresh_token"].(string)

	// Rotate.
	rform := url.Values{}
	rform.Set("grant_type", "refresh_token")
	rform.Set("refresh_token", first)
	rform.Set("client_id", clientID)
	rform.Set("client_secret", clientSecret)
	status, body2 := h.postForm(t, "/api/auth/oauth2/token", rform, "", "")
	if status != http.StatusOK {
		t.Fatalf("rotate: %d %v", status, body2)
	}
	second := body2["refresh_token"].(string)
	if second == "" || second == first {
		t.Fatalf("rotation did not produce a new refresh token")
	}

	// Reuse the OLD refresh — should fail invalid_grant.
	status, body3 := h.postForm(t, "/api/auth/oauth2/token", rform, "", "")
	if status == http.StatusOK {
		t.Fatalf("expected reuse to fail, got 200 %v", body3)
	}
}

func TestClientCredentialsGrant_BasicAuth(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	body := `{"name":"m2m","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_basic"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")

	status, b := h.postForm(t, "/api/auth/oauth2/token", form, clientID, clientSecret)
	if status != http.StatusOK {
		t.Fatalf("client_credentials: %d %v", status, b)
	}
	if _, ok := b["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", b)
	}
	if _, ok := b["refresh_token"]; ok {
		t.Fatalf("client_credentials must not return refresh_token: %v", b)
	}
}

func TestDeviceCodeGrant_EndToEnd(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"tv","redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"scopes":["read"],"is_public":true,"token_endpoint_auth_method":"none"}`
	clientID, _, _ := h.createClient(t, adminCookie, body)

	// /device_authorization
	df := url.Values{}
	df.Set("client_id", clientID)
	df.Set("scope", "read")
	status, da := h.postForm(t, "/api/auth/oauth2/device_authorization", df, "", "")
	if status != http.StatusOK {
		t.Fatalf("device_authorization: %d %v", status, da)
	}
	deviceCode := da["device_code"].(string)
	userCode := da["user_code"].(string)

	// Poll while pending → authorization_pending
	pf := url.Values{}
	pf.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	pf.Set("device_code", deviceCode)
	pf.Set("client_id", clientID)
	status, pb := h.postForm(t, "/api/auth/oauth2/token", pf, "", "")
	if status != http.StatusBadRequest || pb["error"] != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %d %v", status, pb)
	}

	// User approves.
	body2, _ := json.Marshal(map[string]any{"user_code": userCode})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/device", strings.NewReader(string(body2)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("device approve: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("device approve status=%d", res.StatusCode)
	}
	res.Body.Close()

	// Poll again → tokens.
	status, fb := h.postForm(t, "/api/auth/oauth2/token", pf, "", "")
	if status != http.StatusOK {
		t.Fatalf("device exchange: %d %v", status, fb)
	}
	if _, ok := fb["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", fb)
	}

	// Second poll on consumed code → invalid_grant.
	status, db := h.postForm(t, "/api/auth/oauth2/token", pf, "", "")
	if status == http.StatusOK {
		t.Fatalf("consumed device_code should not re-issue: %v", db)
	}
}

func TestRevokeAndIntrospect(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"introspecting","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code","refresh_token"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	verifier := "introspect-test-verifier-43-chars-here-okay-yo"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "read", challenge, "s2", "")
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	status, tok := h.postForm(t, "/api/auth/oauth2/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, tok)
	}
	access := tok["access_token"].(string)
	refresh := tok["refresh_token"].(string)

	// Introspect access — should be active.
	iform := url.Values{}
	iform.Set("token", access)
	iform.Set("client_id", clientID)
	iform.Set("client_secret", clientSecret)
	status, ib := h.postForm(t, "/api/auth/oauth2/introspect", iform, "", "")
	if status != http.StatusOK {
		t.Fatalf("introspect: %d %v", status, ib)
	}
	if active, _ := ib["active"].(bool); !active {
		t.Fatalf("expected active=true, got %v", ib)
	}

	// Revoke refresh.
	rform := url.Values{}
	rform.Set("token", refresh)
	rform.Set("client_id", clientID)
	rform.Set("client_secret", clientSecret)
	status, _ = h.postForm(t, "/api/auth/oauth2/revoke", rform, "", "")
	if status != http.StatusOK {
		t.Fatalf("revoke status=%d", status)
	}

	// Introspect refresh — should be inactive.
	iform2 := url.Values{}
	iform2.Set("token", refresh)
	iform2.Set("client_id", clientID)
	iform2.Set("client_secret", clientSecret)
	status, ib2 := h.postForm(t, "/api/auth/oauth2/introspect", iform2, "", "")
	if status != http.StatusOK {
		t.Fatalf("introspect refresh: %d %v", status, ib2)
	}
	if active, _ := ib2["active"].(bool); active {
		t.Fatalf("expected active=false post-revoke, got %v", ib2)
	}
}

func TestConsentStorage_SkipsPromptOnSecondAuth(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"consent","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, _, _ := h.createClient(t, adminCookie, body)

	verifier := "consent-storage-verifier-43-chars-here-okay-x"
	challenge := pkceS256(verifier)

	// First /authorize → returns consent payload.
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://app.example/callback")
	q.Set("scope", "read")
	q.Set("state", "s1")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res, _ := http.DefaultClient.Do(req)
	var p1 map[string]any
	_ = json.NewDecoder(res.Body).Decode(&p1)
	res.Body.Close()
	if _, hasReq := p1["request_id"]; !hasReq {
		t.Fatalf("expected request_id in first /authorize: %v", p1)
	}

	// Approve via /consent.
	cb, _ := json.Marshal(map[string]any{
		"request_id": p1["request_id"],
		"csrf_token": p1["csrf_token"],
		"approved":   true,
	})
	creq, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/consent", strings.NewReader(string(cb)))
	creq.Header.Set("Content-Type", "application/json")
	creq.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	cres, _ := http.DefaultClient.Do(creq)
	cres.Body.Close()

	// Second /authorize for same scopes → redirect_url, no consent prompt.
	req2, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
	req2.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res2, err2 := http.DefaultClient.Do(req2)
	if err2 != nil {
		t.Fatalf("second authorize: %v", err2)
	}
	defer res2.Body.Close()
	var p2 map[string]any
	_ = json.NewDecoder(res2.Body).Decode(&p2)
	if _, hasReq := p2["request_id"]; hasReq {
		t.Fatalf("expected immediate redirect on second authorize, got consent payload: %v", p2)
	}
	if _, ok := p2["redirect_url"]; !ok {
		t.Fatalf("expected redirect_url, got %v", p2)
	}
}

// pkceS256 mirrors the package-private helper for use in tests.
func pkceS256(verifier string) string {
	return oauth2server.PKCEChallengeForTest(verifier)
}
