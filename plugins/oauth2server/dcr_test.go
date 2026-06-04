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

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// dcrHarness wires up a yauth instance with the oauth2server plugin
// configured for the dynamic-client-registration tests.
type dcrHarness struct {
	srv       *httptest.Server
	repo      *memrepo.Repo
	jwtSecret []byte
}

// newDCRHarness builds a yauth + oauth2server stack with DCR enabled.
// Under the default policy a public, loopback-only client may register
// anonymously; other shapes need adminCookie(). Pass dcrEnabled=false to
// exercise the disabled (404) path.
func newDCRHarness(t *testing.T, dcrEnabled bool) *dcrHarness {
	return newDCRHarnessFull(t, dcrEnabled, false)
}

func newDCRHarnessFull(t *testing.T, dcrEnabled bool, allowConfidential bool) *dcrHarness {
	return newDCRHarnessCustom(t, dcrEnabled, allowConfidential, false)
}

// newDCRHarnessCustom additionally sets DCRRequireAdminForLoopback, which
// disables anonymous loopback registration so every POST /oauth/register
// requires an admin.
func newDCRHarnessCustom(t *testing.T, dcrEnabled, allowConfidential, requireAdminForLoopback bool) *dcrHarness {
	t.Helper()
	r := memrepo.New()

	jwtSecret := []byte("test-only-jwt-secret-please-change-32b")
	cfg := oauth2server.Config{
		Issuer:                      "http://idp.test",
		BasePath:                    "/api/auth",
		AccessTTL:                   5 * time.Minute,
		AuthCodeTTL:                 1 * time.Minute,
		DCREnabled:                  dcrEnabled,
		DCRAllowConfidentialClients: allowConfidential,
		DCRRequireAdminForLoopback:  requireAdminForLoopback,
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

// adminCookie seeds an admin user and returns their raw session cookie.
func (h *dcrHarness) adminCookie(t *testing.T) string {
	t.Helper()
	_, cookie := h.seedUser(t, "dcr-admin-"+uuid.NewString()[:8]+"@idp.test", "admin")
	return cookie
}

// register performs POST /oauth/register and returns the raw response
// status + decoded JSON body. adminCookie is the session cookie of an
// admin user (empty → send no credentials, expect 401).
func (h *dcrHarness) register(t *testing.T, body string, adminCookie string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if adminCookie != "" {
		req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminCookie})
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
	h := newDCRHarness(t, false)
	body := `{"redirect_uris":["https://app.example/callback"]}`
	status, _ := h.register(t, body, "")
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 when DCREnabled=false, got %d", status)
	}
}

func TestDCR_RequiresAdminSession_NoAuth_Returns401(t *testing.T) {
	h := newDCRHarness(t, true)
	body := `{"redirect_uris":["https://app.example/callback"]}`
	status, b := h.register(t, body, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no session present, got %d body=%v", status, b)
	}
}

func TestDCR_RequiresAdminRole_UserGets403(t *testing.T) {
	h := newDCRHarness(t, true)
	_, userCookie := h.seedUser(t, "regular@idp.test", "user")
	body := `{"redirect_uris":["https://app.example/callback"]}`
	status, b := h.register(t, body, userCookie)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin user, got %d body=%v", status, b)
	}
}

func TestDCR_RegisterPublicClient_Then_AuthCodePKCE_EndToEnd(t *testing.T) {
	h := newDCRHarness(t, true)
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
	status, b := h.register(t, regBody, h.adminCookie(t))
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
	if uri, _ := b["registration_client_uri"].(string); uri == "" || !strings.HasSuffix(uri, "/oauth/register/"+clientID) {
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
	st, tb := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if st != http.StatusOK {
		t.Fatalf("token: %d %v", st, tb)
	}
	if _, ok := tb["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", tb)
	}
}

func TestDCR_RegisterConfidentialClient_BasicAuth_TokenEndpoint(t *testing.T) {
	// Confidential DCR is opt-in (public-only by default).
	h := newDCRHarnessFull(t, true, true)

	regBody := `{
		"redirect_uris":["https://app.example/cb"],
		"client_name":"my-confidential-client",
		"grant_types":["client_credentials"],
		"scope":"read",
		"token_endpoint_auth_method":"client_secret_basic"
	}`
	status, b := h.register(t, regBody, h.adminCookie(t))
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
	st, tb := h.postForm(t, "/api/auth/oauth/token", form, clientID, clientSecret)
	if st != http.StatusOK {
		t.Fatalf("client_credentials: %d %v", st, tb)
	}
	if _, ok := tb["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", tb)
	}
}

func TestDCR_DangerousRedirectScheme_Rejected(t *testing.T) {
	h := newDCRHarness(t, true)
	ac := h.adminCookie(t)
	for _, uri := range []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"http://evil.example/cb", // non-loopback plaintext http
	} {
		regBody := `{"redirect_uris":["` + uri + `"],"token_endpoint_auth_method":"none"}`
		status, b := h.register(t, regBody, ac)
		if status != http.StatusBadRequest {
			t.Fatalf("uri %q: expected 400, got %d body=%v", uri, status, b)
		}
		if b["error"] != "invalid_redirect_uri" {
			t.Fatalf("uri %q: expected invalid_redirect_uri, got %v", uri, b["error"])
		}
	}
}

func TestDCR_LoopbackHTTPRedirect_Allowed(t *testing.T) {
	h := newDCRHarness(t, true)
	// http is permitted for loopback (RFC 8252) — MCP clients use it.
	regBody := `{"redirect_uris":["http://127.0.0.1:9999/cb","http://localhost:8080/cb"],"token_endpoint_auth_method":"none"}`
	status, b := h.register(t, regBody, h.adminCookie(t))
	if status != http.StatusCreated {
		t.Fatalf("expected 201 for loopback http, got %d body=%v", status, b)
	}
}

func TestDCR_AnonymousLoopbackPublic_Allowed(t *testing.T) {
	h := newDCRHarness(t, true)
	// Public client, loopback-only redirect, NO credentials — the safe
	// subset that local MCP / native-app clients (e.g. Claude Code) rely on
	// to self-register with an ephemeral callback port.
	body := `{"redirect_uris":["http://127.0.0.1:53517/callback"],"token_endpoint_auth_method":"none"}`
	status, b := h.register(t, body, "")
	if status != http.StatusCreated {
		t.Fatalf("expected 201 for anonymous loopback public client, got %d body=%v", status, b)
	}
	if _, hasSecret := b["client_secret"]; hasSecret {
		t.Fatalf("public client must not receive a client_secret: %v", b)
	}
}

func TestDCR_AnonymousNonLoopback_Returns401_WithJSONError(t *testing.T) {
	h := newDCRHarness(t, true)
	// A non-loopback redirect without credentials must be rejected — and the
	// body must be a JSON OAuth error (not RequireAdmin's plain text) so MCP
	// SDKs can parse it as an OAuth error response.
	body := `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"none"}`
	status, b := h.register(t, body, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for anonymous non-loopback, got %d body=%v", status, b)
	}
	if b["error"] != "invalid_token" {
		t.Fatalf("expected JSON error invalid_token, got %v body=%v", b["error"], b)
	}
}

func TestDCR_AnonymousMixedLoopbackAndRemote_Returns401(t *testing.T) {
	h := newDCRHarness(t, true)
	// One loopback + one non-loopback redirect → not all-loopback → the
	// conservative path requires an admin.
	body := `{"redirect_uris":["http://127.0.0.1:9000/cb","https://app.example/cb"],"token_endpoint_auth_method":"none"}`
	status, b := h.register(t, body, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for mixed loopback+remote redirects, got %d body=%v", status, b)
	}
}

func TestDCR_AnonymousLoopbackConfidential_RequiresAdmin(t *testing.T) {
	// Even where confidential DCR is allowed, a confidential client is never
	// in the anonymous subset: loopback or not, it needs an admin.
	h := newDCRHarnessFull(t, true, true)
	body := `{"redirect_uris":["http://127.0.0.1:9000/cb"],"token_endpoint_auth_method":"client_secret_basic"}`
	status, b := h.register(t, body, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for anonymous confidential client, got %d body=%v", status, b)
	}
	status, b = h.register(t, body, h.adminCookie(t))
	if status != http.StatusCreated {
		t.Fatalf("expected 201 for admin-registered confidential client, got %d body=%v", status, b)
	}
}

func TestDCR_RequireAdminForLoopback_RestoresStrictGate(t *testing.T) {
	h := newDCRHarnessCustom(t, true, false, true) // requireAdminForLoopback=true
	body := `{"redirect_uris":["http://127.0.0.1:9000/cb"],"token_endpoint_auth_method":"none"}`
	status, b := h.register(t, body, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 with DCRRequireAdminForLoopback, got %d body=%v", status, b)
	}
	status, b = h.register(t, body, h.adminCookie(t))
	if status != http.StatusCreated {
		t.Fatalf("expected 201 for admin loopback register, got %d body=%v", status, b)
	}
}

func TestDCR_AnonymousLoopback_Then_AuthCodePKCE_EndToEnd(t *testing.T) {
	h := newDCRHarness(t, true)
	_, userCookie := h.seedUser(t, "mcp-user@idp.test", "user")
	const redirect = "http://127.0.0.1:53517/callback"

	// Register anonymously (no admin) — the Claude-Code-style flow — then
	// complete authorization-code + PKCE with the resulting public client.
	regBody := `{"redirect_uris":["` + redirect + `"],"token_endpoint_auth_method":"none","scope":"read"}`
	status, b := h.register(t, regBody, "")
	if status != http.StatusCreated {
		t.Fatalf("anonymous register: %d %v", status, b)
	}
	clientID, _ := b["client_id"].(string)
	if clientID == "" {
		t.Fatalf("missing client_id: %v", b)
	}

	verifier := "dcr-anon-loopback-verifier-43-chars-long-ok-yo"
	challenge := oauth2server.PKCEChallengeForTest(verifier)
	code := h.authzAndConsent(t, userCookie, clientID, redirect, "read", challenge, "s1")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	st, tb := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if st != http.StatusOK {
		t.Fatalf("token: %d %v", st, tb)
	}
	if _, ok := tb["access_token"]; !ok {
		t.Fatalf("missing access_token: %v", tb)
	}
}

func TestDCR_ConfidentialClient_RejectedByDefault(t *testing.T) {
	h := newDCRHarness(t, true) // public-only by default
	ac := h.adminCookie(t)
	for _, m := range []string{"client_secret_basic", "client_secret_post"} {
		regBody := `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"` + m + `"}`
		status, b := h.register(t, regBody, ac)
		if status != http.StatusBadRequest {
			t.Fatalf("method %q: expected 400 (public-only), got %d %v", m, status, b)
		}
	}
	// A public client (none) is accepted.
	status, b := h.register(t, `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"none"}`, ac)
	if status != http.StatusCreated {
		t.Fatalf("public client should be accepted, got %d %v", status, b)
	}
}

func TestDCR_MissingRedirectURIs_400(t *testing.T) {
	h := newDCRHarness(t, true)
	regBody := `{"client_name":"no-uris"}`
	status, b := h.register(t, regBody, h.adminCookie(t))
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%v", status, b)
	}
	if b["error"] != "invalid_redirect_uri" {
		t.Fatalf("expected invalid_redirect_uri, got %v", b["error"])
	}
}

func TestDCR_DefaultsApplied(t *testing.T) {
	h := newDCRHarness(t, true)
	// No grant_types / response_types / auth method supplied. grant/response
	// types default per RFC 7591 §2; token_endpoint_auth_method defaults to the
	// secure "none" (public client) rather than RFC 7591's client_secret_basic.
	regBody := `{"redirect_uris":["https://app.example/cb"]}`
	status, b := h.register(t, regBody, h.adminCookie(t))
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
	if m, _ := b["token_endpoint_auth_method"].(string); m != "none" {
		t.Fatalf("token_endpoint_auth_method default: %q (want secure default none)", m)
	}
}

func TestDCR_RedirectURI_NewlineSanitized(t *testing.T) {
	h := newDCRHarness(t, true)
	// A redirect_uri that a terminal (tmux) line-wrapped on copy/paste: the
	// JSON carries an escaped newline inside the URI string. It should be
	// stripped and the client registered, not rejected for "whitespace".
	body := "{\"redirect_uris\":[\"http://127.0.0.1:53517/\\ncallback\"],\"token_endpoint_auth_method\":\"none\"}"
	status, b := h.register(t, body, "")
	if status != http.StatusCreated {
		t.Fatalf("expected 201 for a line-wrapped redirect_uri, got %d body=%v", status, b)
	}
	uris, _ := b["redirect_uris"].([]any)
	if len(uris) != 1 || uris[0] != "http://127.0.0.1:53517/callback" {
		t.Fatalf("redirect_uri should be sanitized to a single line, got %v", b["redirect_uris"])
	}
}
