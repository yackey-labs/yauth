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

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/bearer"
	"github.com/yackey-labs/yauth-go/plugins/oauth2server"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

// dcrHarness wires up a yauth instance with the oauth2server plugin
// configured for the dynamic-client-registration tests.
type dcrHarness struct {
	srv       *httptest.Server
	repo      *gormrepo.Repo
	jwtSecret []byte
}

// newDCRHarness builds a yauth + oauth2server stack with DCR enabled
// according to the supplied opts. requireToken=nil keeps the secure
// default (Bearer required). requireToken pointing at false enables
// completely-open registration.
func newDCRHarness(t *testing.T, dcrEnabled bool, requireToken *bool) *dcrHarness {
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
	cfg := oauth2server.Config{
		Issuer:                       "http://idp.test",
		BasePath:                     "/api/auth",
		AccessTTL:                    5 * time.Minute,
		AuthCodeTTL:                  1 * time.Minute,
		DCREnabled:                   dcrEnabled,
		DCRRequireInitialAccessToken: requireToken,
	}

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret(jwtSecret).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(cfg)).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &dcrHarness{srv: srv, repo: r, jwtSecret: jwtSecret}
}

// seedUser creates a user row + an active session cookie for use as
// the resource-owner during the authorization-code flow.
func (h *dcrHarness) seedUser(t *testing.T, email, role string) (id, cookie string) {
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

// signInitialAccessToken returns a Bearer JWT signed with the host
// HS256 secret, suitable as an initial access token for POST
// /oauth2/register when DCRRequireInitialAccessToken is true.
func (h *dcrHarness) signInitialAccessToken(t *testing.T) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub": "admin",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(h.jwtSecret)
	if err != nil {
		t.Fatalf("sign initial access token: %v", err)
	}
	return signed
}

// register performs POST /oauth2/register and returns the raw response
// status + decoded JSON body. bearer is the Authorization: Bearer
// credential to send (empty → omit the header).
func (h *dcrHarness) register(t *testing.T, body string, bearer string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// authzAndConsent runs GET /authorize → POST /consent for the given
// session cookie and returns the issued authorization code.
func (h *dcrHarness) authzAndConsent(t *testing.T, cookie, clientID, redirectURI, scope, challenge, state string) string {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

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

// postForm posts form-urlencoded values to path with optional Basic auth.
func (h *dcrHarness) postForm(t *testing.T, path string, form url.Values, basicID, basicSecret string) (int, map[string]any) {
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

func TestDCR_Disabled_Returns404(t *testing.T) {
	h := newDCRHarness(t, false, nil)
	body := `{"redirect_uris":["https://app.example/callback"]}`
	status, _ := h.register(t, body, "")
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 when DCREnabled=false, got %d", status)
	}
}

func TestDCR_RequireInitialAccessToken_NoBearer_401(t *testing.T) {
	h := newDCRHarness(t, true, nil) // default: require token
	body := `{"redirect_uris":["https://app.example/callback"]}`
	status, b := h.register(t, body, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no Bearer present, got %d body=%v", status, b)
	}
	if b["error"] != "invalid_token" {
		t.Fatalf("expected invalid_token, got %v", b["error"])
	}
}

func TestDCR_RegisterPublicClient_Then_AuthCodePKCE_EndToEnd(t *testing.T) {
	h := newDCRHarness(t, true, nil) // default: initial access token required
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	// Register a public client (token_endpoint_auth_method=none).
	regBody := `{
		"redirect_uris":["https://app.example/cb"],
		"client_name":"my-public-client",
		"grant_types":["authorization_code"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"scope":"read"
	}`
	status, b := h.register(t, regBody, h.signInitialAccessToken(t))
	if status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, b)
	}
	clientID, _ := b["client_id"].(string)
	if clientID == "" {
		t.Fatalf("missing client_id: %v", b)
	}
	if _, hasSecret := b["client_secret"]; hasSecret {
		t.Fatalf("public client must not receive a client_secret: %v", b)
	}
	if rat, _ := b["registration_access_token"].(string); rat == "" {
		t.Fatalf("missing registration_access_token: %v", b)
	}
	if uri, _ := b["registration_client_uri"].(string); uri == "" || !strings.HasSuffix(uri, "/oauth2/register/"+clientID) {
		t.Fatalf("unexpected registration_client_uri: %v", b["registration_client_uri"])
	}
	if got, _ := b["token_endpoint_auth_method"].(string); got != "none" {
		t.Fatalf("token_endpoint_auth_method round-trip: got %q", got)
	}

	// End-to-end auth-code + PKCE flow with no client_secret.
	verifier := "dcr-public-client-verifier-43-chars-long-ok-yo"
	challenge := oauth2server.PKCEChallengeForTest(verifier)
	code := h.authzAndConsent(t, userCookie, clientID, "https://app.example/cb", "read", challenge, "s1")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	st, tb := h.postForm(t, "/api/auth/oauth2/token", form, "", "")
	if st != http.StatusOK {
		t.Fatalf("token: %d %v", st, tb)
	}
	if _, ok := tb["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", tb)
	}
}

func TestDCR_RegisterConfidentialClient_BasicAuth_TokenEndpoint(t *testing.T) {
	h := newDCRHarness(t, true, nil)

	regBody := `{
		"redirect_uris":["https://app.example/cb"],
		"client_name":"my-confidential-client",
		"grant_types":["client_credentials"],
		"scope":"read",
		"token_endpoint_auth_method":"client_secret_basic"
	}`
	status, b := h.register(t, regBody, h.signInitialAccessToken(t))
	if status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, b)
	}
	clientID, _ := b["client_id"].(string)
	clientSecret, _ := b["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		t.Fatalf("expected both client_id and client_secret, got %v", b)
	}
	// 32 bytes hex = 64 hex chars.
	if len(clientSecret) != 64 {
		t.Fatalf("expected 64-char hex secret (32 bytes), got len=%d", len(clientSecret))
	}
	if got, _ := b["token_endpoint_auth_method"].(string); got != "client_secret_basic" {
		t.Fatalf("auth method round-trip: %q", got)
	}

	// Use Basic auth on /token to get an access token.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")
	st, tb := h.postForm(t, "/api/auth/oauth2/token", form, clientID, clientSecret)
	if st != http.StatusOK {
		t.Fatalf("client_credentials: %d %v", st, tb)
	}
	if _, ok := tb["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", tb)
	}
}

func TestDCR_OpenRegistration_Allowed_When_RequireInitialAccessToken_False(t *testing.T) {
	open := false
	h := newDCRHarness(t, true, &open)

	regBody := `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"none"}`
	status, b := h.register(t, regBody, "") // no Bearer
	if status != http.StatusCreated {
		t.Fatalf("expected 201 in open mode, got %d body=%v", status, b)
	}
	if _, ok := b["client_id"].(string); !ok {
		t.Fatalf("missing client_id: %v", b)
	}
}

func TestDCR_MissingRedirectURIs_400(t *testing.T) {
	h := newDCRHarness(t, true, nil)
	regBody := `{"client_name":"no-uris"}`
	status, b := h.register(t, regBody, h.signInitialAccessToken(t))
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%v", status, b)
	}
	if b["error"] != "invalid_redirect_uri" {
		t.Fatalf("expected invalid_redirect_uri, got %v", b["error"])
	}
}

func TestDCR_DefaultsApplied(t *testing.T) {
	h := newDCRHarness(t, true, nil)
	// No grant_types / response_types / auth method supplied — should
	// default per RFC 7591 §2.
	regBody := `{"redirect_uris":["https://app.example/cb"]}`
	status, b := h.register(t, regBody, h.signInitialAccessToken(t))
	if status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, b)
	}
	gts, _ := b["grant_types"].([]any)
	if len(gts) != 1 || gts[0] != "authorization_code" {
		t.Fatalf("grant_types default: %v", gts)
	}
	rts, _ := b["response_types"].([]any)
	if len(rts) != 1 || rts[0] != "code" {
		t.Fatalf("response_types default: %v", rts)
	}
	if m, _ := b["token_endpoint_auth_method"].(string); m != "client_secret_basic" {
		t.Fatalf("token_endpoint_auth_method default: %q", m)
	}
}
