package oauth2server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/asymjwt"
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

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/authorize?"+q.Encode(), nil)
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

	status, body2 := h.postForm(t, "/api/auth/oauth/token", form, "", "")
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

	status, b := h.postForm(t, "/api/auth/oauth/token", form, "", "")
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
	status, body1 := h.postForm(t, "/api/auth/oauth/token", form, "", "")
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
	status, body2 := h.postForm(t, "/api/auth/oauth/token", rform, "", "")
	if status != http.StatusOK {
		t.Fatalf("rotate: %d %v", status, body2)
	}
	second := body2["refresh_token"].(string)
	if second == "" || second == first {
		t.Fatalf("rotation did not produce a new refresh token")
	}

	// Reuse the OLD refresh — should fail invalid_grant.
	status, body3 := h.postForm(t, "/api/auth/oauth/token", rform, "", "")
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

	status, b := h.postForm(t, "/api/auth/oauth/token", form, clientID, clientSecret)
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
	status, da := h.postForm(t, "/api/auth/oauth/device/code", df, "", "")
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
	status, pb := h.postForm(t, "/api/auth/oauth/token", pf, "", "")
	if status != http.StatusBadRequest || pb["error"] != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %d %v", status, pb)
	}

	// User approves.
	body2, _ := json.Marshal(map[string]any{"user_code": userCode})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth/device", strings.NewReader(string(body2)))
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
	status, fb := h.postForm(t, "/api/auth/oauth/token", pf, "", "")
	if status != http.StatusOK {
		t.Fatalf("device exchange: %d %v", status, fb)
	}
	if _, ok := fb["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", fb)
	}

	// Second poll on consumed code → invalid_grant.
	status, db := h.postForm(t, "/api/auth/oauth/token", pf, "", "")
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
	status, tok := h.postForm(t, "/api/auth/oauth/token", form, "", "")
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
	status, ib := h.postForm(t, "/api/auth/oauth/introspect", iform, "", "")
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
	status, _ = h.postForm(t, "/api/auth/oauth/revoke", rform, "", "")
	if status != http.StatusOK {
		t.Fatalf("revoke status=%d", status)
	}

	// Introspect refresh — should be inactive.
	iform2 := url.Values{}
	iform2.Set("token", refresh)
	iform2.Set("client_id", clientID)
	iform2.Set("client_secret", clientSecret)
	status, ib2 := h.postForm(t, "/api/auth/oauth/introspect", iform2, "", "")
	if status != http.StatusOK {
		t.Fatalf("introspect refresh: %d %v", status, ib2)
	}
	if active, _ := ib2["active"].(bool); active {
		t.Fatalf("expected active=false post-revoke, got %v", ib2)
	}
}

// TestIntrospect_SuspendedUser_ReflectsInactive proves lifecycle-aware
// introspection: once a user is suspended (offboarded), introspecting their
// otherwise-valid access token returns active:false. This is the per-request
// instant-termination path for RPs that introspect.
func TestIntrospect_SuspendedUser_ReflectsInactive(t *testing.T) {
	h := newHarness(t)
	adminID, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_ = adminID
	userID, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"introspect-suspend","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code","refresh_token"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	verifier := "introspect-suspend-verifier-43-chars-here-okay"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "read", challenge, "s3", "")
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	status, tok := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, tok)
	}
	access := tok["access_token"].(string)

	// Active before suspension.
	iform := url.Values{}
	iform.Set("token", access)
	iform.Set("client_id", clientID)
	iform.Set("client_secret", clientSecret)
	status, ib := h.postForm(t, "/api/auth/oauth/introspect", iform, "", "")
	if status != http.StatusOK || !ib["active"].(bool) {
		t.Fatalf("expected active=true pre-suspend, got %d %v", status, ib)
	}

	// Suspend the user globally.
	now := time.Now().UTC()
	nowPtr := &now
	reason := "offboarded"
	reasonPtr := &reason
	if _, err := h.repo.UpdateUser(context.Background(), userID, domain.UpdateUser{
		SuspendedAt:     &nowPtr,
		SuspendedReason: &reasonPtr,
		UpdatedAt:       &now,
	}); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	// Same valid JWT, now introspects inactive.
	status, ib2 := h.postForm(t, "/api/auth/oauth/introspect", iform, "", "")
	if status != http.StatusOK {
		t.Fatalf("introspect post-suspend: %d", status)
	}
	if active, _ := ib2["active"].(bool); active {
		t.Fatalf("expected active=false for suspended user's token, got %v", ib2)
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
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/authorize?"+q.Encode(), nil)
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
	req2, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/authorize?"+q.Encode(), nil)
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

// getAuthorize performs GET /authorize and returns (status, body).
func (h *harness) getAuthorize(t *testing.T, cookie, clientID, challenge string) (int, map[string]any) {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://app.example/callback")
	q.Set("scope", "openid read")
	q.Set("state", "s")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

// TestIDToken_GroupsClaim proves the IdP emits the user's group names in the
// id_token when the "groups" scope is granted — the claim RPs (e.g. yauth-go's
// ssooidc plugin) map to local roles.
func TestIDToken_GroupsClaim(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, adminCookie := h.seedUser(t, "gc-admin@idp.test", "admin")
	uid, userCookie := h.seedUser(t, "gc-user@idp.test", "user")

	org, err := h.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "O", Slug: "o-" + uuid.NewString()[:8], CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	g, err := h.repo.CreateGroup(ctx, domain.NewGroup{
		ID: uuid.NewString(), OrganizationID: org.ID, Name: "Engineering", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := h.repo.AddGroupMember(ctx, g.ID, uid, now); err != nil {
		t.Fatalf("add member: %v", err)
	}

	clientID, secret, _ := h.createClient(t, adminCookie, `{"name":"gc","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["openid","groups"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`)
	verifier := "this-is-a-43-character-pkce-verifier-string-x"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "openid groups", challenge, "s", "n")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	form.Set("code_verifier", verifier)
	status, body := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%v", status, body)
	}
	idt, _ := body["id_token"].(string)
	parsed, _, err := jwt.NewParser().ParseUnverified(idt, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse id_token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	groups, _ := claims["groups"].([]any)
	found := false
	for _, gg := range groups {
		if gg == "Engineering" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected groups claim to contain Engineering, got %v", claims["groups"])
	}
}

// TestIDToken_ClientRoles proves per-app (client) roles: a role assigned to a
// user directly and via a group shows up in app1's token, while app2 (no
// assignment) gets none — the "owner of app1 but not app2" case.
func TestIDToken_ClientRoles(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, adminCookie := h.seedUser(t, "cr-admin@idp.test", "admin")
	uid, userCookie := h.seedUser(t, "cr-user@idp.test", "user")

	org, _ := h.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "O", Slug: "o-" + uuid.NewString()[:8], CreatedAt: now, UpdatedAt: now,
	})
	g, _ := h.repo.CreateGroup(ctx, domain.NewGroup{
		ID: uuid.NewString(), OrganizationID: org.ID, Name: "devops", CreatedAt: now, UpdatedAt: now,
	})
	_ = h.repo.AddGroupMember(ctx, g.ID, uid, now)

	app1, secret1, _ := h.createClient(t, adminCookie, `{"name":"app1","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["openid"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`)
	app2, secret2, _ := h.createClient(t, adminCookie, `{"name":"app2","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["openid"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`)

	gid := g.ID
	// app1: "owner" to the individual, "admin" to the devops group.
	if err := h.repo.AssignClientRole(ctx, domain.NewClientRoleAssignment{ID: uuid.NewString(), ClientID: app1, Role: "owner", UserID: &uid, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.repo.AssignClientRole(ctx, domain.NewClientRoleAssignment{ID: uuid.NewString(), ClientID: app1, Role: "admin", GroupID: &gid, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	rolesFor := func(clientID, secret string) []string {
		verifier := "this-is-a-43-character-pkce-verifier-string-x"
		challenge := pkceS256(verifier)
		code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "openid", challenge, "s", "")
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", "https://app.example/callback")
		form.Set("client_id", clientID)
		form.Set("client_secret", secret)
		form.Set("code_verifier", verifier)
		status, body := h.postForm(t, "/api/auth/oauth/token", form, "", "")
		if status != http.StatusOK {
			t.Fatalf("token status=%d body=%v", status, body)
		}
		parsed, _, err := jwt.NewParser().ParseUnverified(body["id_token"].(string), jwt.MapClaims{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		var out []string
		if rc, ok := parsed.Claims.(jwt.MapClaims)["roles"].([]any); ok {
			for _, r := range rc {
				out = append(out, r.(string))
			}
		}
		return out
	}

	r1 := rolesFor(app1, secret1)
	if len(r1) != 2 || !contains(r1, "owner") || !contains(r1, "admin") {
		t.Fatalf("app1 roles: want [admin owner], got %v", r1)
	}
	r2 := rolesFor(app2, secret2)
	if len(r2) != 0 {
		t.Fatalf("app2 roles: want none (per-app scoping), got %v", r2)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestAuthorize_GroupAssignmentEnforced is the discriminating test for the
// application-group-assignment feature: a client with enforcement on rejects a
// user who is not a member of any assigned group, and admits them once added.
func TestAuthorize_GroupAssignmentEnforced(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, adminCookie := h.seedUser(t, "gadmin@idp.test", "admin")
	uid, userCookie := h.seedUser(t, "guser@idp.test", "user")

	// Public client with the access gate enabled.
	clientID, _, _ := h.createClient(t, adminCookie, `{
		"name":"gated",
		"redirect_uris":["https://app.example/callback"],
		"grant_types":["authorization_code"],
		"scopes":["openid","read"],
		"is_public":true,
		"token_endpoint_auth_method":"none",
		"enforce_group_assignment":true
	}`)

	// An org + group, with the group assigned to the client.
	org, err := h.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	g, err := h.repo.CreateGroup(ctx, domain.NewGroup{
		ID: uuid.NewString(), OrganizationID: org.ID, Name: "eng", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := h.repo.AssignClientGroup(ctx, clientID, g.ID, now); err != nil {
		t.Fatalf("assign group: %v", err)
	}

	verifier := "this-is-a-43-character-pkce-verifier-string-x"
	challenge := pkceS256(verifier)

	// 1) User is NOT in the assigned group → access_denied.
	status, body := h.getAuthorize(t, userCookie, clientID, challenge)
	if body["error"] != "access_denied" {
		t.Fatalf("expected access_denied for unassigned user, got status=%d body=%v", status, body)
	}

	// 2) Add the user to the assigned group → the flow proceeds and issues a code.
	if err := h.repo.AddGroupMember(ctx, g.ID, uid, now); err != nil {
		t.Fatalf("add group member: %v", err)
	}
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "openid read", challenge, "s", "")
	if code == "" {
		t.Fatal("expected an authorization code once the user is in an assigned group")
	}
}

// --- Gap 9 + RFC 8414 tests --------------------------------------------

// adminPost sends an admin-authenticated POST with optional JSON body.
func (h *harness) adminPost(t *testing.T, path, adminCookie, body string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestClientBan_RejectsTokenMint_AndUnbanRestores(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	body := `{"name":"banner","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_basic"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	// Sanity: token mint succeeds before the ban.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")
	status, b := h.postForm(t, "/api/auth/oauth/token", form, clientID, clientSecret)
	if status != http.StatusOK {
		t.Fatalf("pre-ban token: %d %v", status, b)
	}

	// Ban.
	banBody := `{"reason":"abuse"}`
	st, _ := h.adminPost(t, "/api/auth/oauth2/clients/"+clientID+"/ban", adminCookie, banBody)
	if st != http.StatusOK {
		t.Fatalf("ban: status=%d", st)
	}

	// Token mint must now fail invalid_client.
	status, b = h.postForm(t, "/api/auth/oauth/token", form, clientID, clientSecret)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 after ban, got %d %v", status, b)
	}
	if b["error"] != "invalid_client" {
		t.Fatalf("expected invalid_client, got %v", b["error"])
	}

	// Audit log should record the ban event.
	logs, err := h.repo.ListAuditLog(context.Background(), domain.ListAuditFilters{
		EventType: stringPtr("oauth2.client.banned"),
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(logs) == 0 {
		t.Fatalf("expected an oauth2.client.banned audit log row")
	}

	// Unban.
	st, _ = h.adminPost(t, "/api/auth/oauth2/clients/"+clientID+"/unban", adminCookie, "")
	if st != http.StatusOK {
		t.Fatalf("unban: status=%d", st)
	}

	// Token mint succeeds again.
	status, b = h.postForm(t, "/api/auth/oauth/token", form, clientID, clientSecret)
	if status != http.StatusOK {
		t.Fatalf("post-unban token: %d %v", status, b)
	}
}

func TestAuthServerMetadata_RFC8414(t *testing.T) {
	h := newHarness(t)

	res, err := http.Get(h.srv.URL + "/api/auth/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := map[string]string{
		"issuer":                        "http://idp.test",
		"authorization_endpoint":        "http://idp.test/api/auth/oauth/authorize",
		"token_endpoint":                "http://idp.test/api/auth/oauth/token",
		"revocation_endpoint":           "http://idp.test/api/auth/oauth/revoke",
		"introspection_endpoint":        "http://idp.test/api/auth/oauth/introspect",
		"device_authorization_endpoint": "http://idp.test/api/auth/oauth/device/code",
	}
	for k, v := range want {
		got, _ := doc[k].(string)
		if got != v {
			t.Fatalf("%s: got %q want %q", k, got, v)
		}
	}

	// jwks_uri is omitted when no asymjwt signer is loaded.
	if _, ok := doc["jwks_uri"]; ok {
		t.Fatalf("jwks_uri should be omitted without asymjwt: %v", doc["jwks_uri"])
	}

	// response_types_supported = ["code"]
	rts, _ := doc["response_types_supported"].([]any)
	if len(rts) != 1 || rts[0] != "code" {
		t.Fatalf("response_types_supported: %v", rts)
	}

	gts, _ := doc["grant_types_supported"].([]any)
	wantGrants := map[string]bool{
		"authorization_code": true,
		"refresh_token":      true,
		"client_credentials": true,
		"urn:ietf:params:oauth:grant-type:device_code": true,
	}
	for _, g := range gts {
		delete(wantGrants, g.(string))
	}
	if len(wantGrants) != 0 {
		t.Fatalf("missing grant types: %v", wantGrants)
	}

	pkce, _ := doc["code_challenge_methods_supported"].([]any)
	if len(pkce) != 1 || pkce[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported: %v", pkce)
	}

	// Without asymjwt loaded, private_key_jwt must not be advertised.
	authMethods, _ := doc["token_endpoint_auth_methods_supported"].([]any)
	wantMethods := map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"none":                true,
	}
	for _, m := range authMethods {
		s := m.(string)
		if s == "private_key_jwt" {
			t.Fatalf("private_key_jwt must not be advertised without asymjwt signer")
		}
		delete(wantMethods, s)
	}
	if len(wantMethods) != 0 {
		t.Fatalf("missing auth methods: %v", wantMethods)
	}
}

// --- Rotate-public-key + private_key_jwt test --------------------------

// pkjwtHarness wraps a harness configured with asymjwt loaded so the
// private_key_jwt path is enabled.
type pkjwtHarness struct {
	*harness
}

func newPKJWTHarness(t *testing.T) *pkjwtHarness {
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

	dir := t.TempDir()
	priv, pub := writeServerRSAKeys(t, dir)
	asym, err := asymjwt.New(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPath: priv, PublicKeyPath: pub, KID: "test-kid",
	})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}

	jwtSecret := []byte("test-only-jwt-secret-please-change-32b")
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret(jwtSecret).
		WithPlugin(asym).
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
	return &pkjwtHarness{harness: &harness{srv: srv, repo: r}}
}

// writeServerRSAKeys generates an RSA-2048 keypair to disk for asymjwt.
func writeServerRSAKeys(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	privPath = filepath.Join(dir, "rsa.key")
	pubPath = filepath.Join(dir, "rsa.pub")
	_ = os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600)
	_ = os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644)
	return privPath, pubPath
}

// makeClientRSA generates a fresh RSA client keypair and returns the
// private key + the PEM-encoded public key.
func makeClientRSA(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen client rsa: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return k, string(pemBytes)
}

// signPKJWTAssertion builds an RFC 7523 client_assertion signed with
// the given RSA private key.
func signPKJWTAssertion(t *testing.T, k *rsa.PrivateKey, clientID, audience string) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"jti": uuid.NewString(),
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(k)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signed
}

func TestRotatePublicKey_OldAssertionRejected_NewAccepted(t *testing.T) {
	h := newPKJWTHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	// Original keypair the client will sign assertions with.
	oldKey, oldPEM := makeClientRSA(t)

	body := map[string]any{
		"name":                       "pkjwt-client",
		"redirect_uris":              []string{},
		"grant_types":                []string{"client_credentials"},
		"scopes":                     []string{"read"},
		"is_public":                  false,
		"token_endpoint_auth_method": "private_key_jwt",
		"public_key_pem":             oldPEM,
	}
	bb, _ := json.Marshal(body)
	clientID, _, _ := h.createClient(t, adminCookie, string(bb))

	audience := h.srv.URL + "/api/auth/oauth/token"

	// Sanity: the old key works before rotation.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", signPKJWTAssertion(t, oldKey, clientID, audience))
	form.Set("scope", "read")
	status, b := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("pre-rotation: %d %v", status, b)
	}

	// Rotate: generate a new client keypair and POST the new public PEM.
	newKey, newPEM := makeClientRSA(t)
	rb, _ := json.Marshal(map[string]string{"public_key_pem": newPEM})
	st, _ := h.adminPost(t, "/api/auth/oauth2/clients/"+clientID+"/rotate-public-key", adminCookie, string(rb))
	if st != http.StatusOK {
		t.Fatalf("rotate: %d", st)
	}

	// OLD-key assertion must now fail.
	form2 := url.Values{}
	form2.Set("grant_type", "client_credentials")
	form2.Set("client_id", clientID)
	form2.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form2.Set("client_assertion", signPKJWTAssertion(t, oldKey, clientID, audience))
	form2.Set("scope", "read")
	status, b = h.postForm(t, "/api/auth/oauth/token", form2, "", "")
	if status == http.StatusOK {
		t.Fatalf("expected old assertion to fail post-rotation, got %v", b)
	}
	if b["error"] != "invalid_client" {
		t.Fatalf("expected invalid_client, got %v", b)
	}

	// NEW-key assertion succeeds.
	form3 := url.Values{}
	form3.Set("grant_type", "client_credentials")
	form3.Set("client_id", clientID)
	form3.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form3.Set("client_assertion", signPKJWTAssertion(t, newKey, clientID, audience))
	form3.Set("scope", "read")
	status, b = h.postForm(t, "/api/auth/oauth/token", form3, "", "")
	if status != http.StatusOK {
		t.Fatalf("new key: %d %v", status, b)
	}
	if _, ok := b["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", b)
	}
}

func TestRotatePublicKey_RejectsInvalidPEM(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	body := `{"name":"x","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_basic"}`
	clientID, _, _ := h.createClient(t, adminCookie, body)

	bad := `{"public_key_pem":"-----BEGIN PUBLIC KEY-----\nbm90LXJlYWxseS1hLWtleQ==\n-----END PUBLIC KEY-----\n"}`
	st, b := h.adminPost(t, "/api/auth/oauth2/clients/"+clientID+"/rotate-public-key", adminCookie, bad)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid PEM, got %d %v", st, b)
	}
	if b["error"] != "invalid_request" {
		t.Fatalf("expected invalid_request, got %v", b["error"])
	}
}

// stringPtr is a small helper used by the audit-log test.
func stringPtr(s string) *string { return &s }
