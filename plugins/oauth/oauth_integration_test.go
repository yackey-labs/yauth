package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/oauth"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// fakeProvider is a Provider that talks to a local httptest server which
// canned-responds for /authorize and /token. FetchUserInfo skips HTTP
// entirely and returns a struct directly — there is no need to put the
// userinfo step over the wire to validate the plugin's behaviour.
type fakeProvider struct {
	name  string
	cfg   *oauth2.Config
	info  oauth.UserInfo
	calls atomic.Int32 // FetchUserInfo invocations
	fail  atomic.Bool
}

func (f *fakeProvider) Name() string           { return f.name }
func (f *fakeProvider) Config() *oauth2.Config { return f.cfg }
func (f *fakeProvider) FetchUserInfo(_ context.Context, _ *oauth2.Token) (*oauth.UserInfo, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return nil, errors.New("forced failure")
	}
	cp := f.info
	return &cp, nil
}

// newProviderServer returns a live httptest server that mimics the
// upstream provider's authorization and token endpoints.
func newProviderServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		redirect := r.URL.Query().Get("redirect_uri")
		if state == "" || redirect == "" {
			http.Error(w, "missing state/redirect_uri", http.StatusBadRequest)
			return
		}
		u, err := url.Parse(redirect)
		if err != nil {
			http.Error(w, "bad redirect", http.StatusBadRequest)
			return
		}
		q := u.Query()
		q.Set("code", "fake-code-OK")
		q.Set("state", state)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		body := map[string]any{
			"access_token":  "fake-access-" + r.FormValue("code"),
			"refresh_token": "fake-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// stack bundles the bits each test needs.
type stack struct {
	srv      *httptest.Server
	client   *http.Client
	provider *fakeProvider
	repo     repo.Repository
}

func newStack(t *testing.T, info oauth.UserInfo) *stack {
	return newStackWithRedirects(t, info, nil)
}

// newStackWithRedirects is newStack with an explicit AllowedRedirectURLs
// allow-list, so tests can assert the post-callback redirect is honored.
func newStackWithRedirects(t *testing.T, info oauth.UserInfo, allowed []string) *stack {
	t.Helper()

	provServer := newProviderServer(t)

	// The yauth server's URL is needed for RedirectURL, which we don't
	// know until httptest.NewServer is called. Solution: build the
	// fakeProvider with an empty RedirectURL, build the yauth server,
	// then patch RedirectURL — the provider only reads it from
	// cfg.RedirectURL each time AuthCodeURL/Exchange runs, so the
	// patch is safe.
	prov := &fakeProvider{
		name: "fake",
		cfg: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Scopes:       []string{"email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  provServer.URL + "/oauth/authorize",
				TokenURL: provServer.URL + "/oauth/token",
			},
		},
		info: info,
	}

	repo := memrepo.New()

	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	op, err := oauth.New(oauth.Config{
		EncryptionKey:       key,
		Providers:           []oauth.Provider{prov},
		StateTTL:            5 * time.Minute,
		AllowedRedirectURLs: allowed,
	})
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		WithPlugin(op).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	prov.cfg.RedirectURL = srv.URL + "/api/auth/oauth/fake/callback"

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	cl := &http.Client{
		Jar:           jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &stack{srv: srv, client: cl, provider: prov, repo: repo}
}

func drainBody(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

// followAuthorizeAndExtractCallback walks the /authorize redirect to the
// provider, then the provider's redirect back to /callback. It returns
// the URL of the /callback request the test is supposed to make next, and
// the state value the plugin minted.
func followAuthorizeAndExtractCallback(t *testing.T, s *stack, redirect string) (callbackURL, state string) {
	t.Helper()
	authzURL := s.srv.URL + "/api/auth/oauth/fake/authorize"
	if redirect != "" {
		authzURL += "?redirect_url=" + url.QueryEscape(redirect)
	}
	res, err := s.client.Get(authzURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d (%s)", res.StatusCode, drainBody(res))
	}
	loc, err := res.Location()
	if err != nil {
		t.Fatalf("authorize location: %v", err)
	}
	res.Body.Close()
	state = loc.Query().Get("state")
	if state == "" {
		t.Fatalf("authorize: missing state")
	}

	// Drive provider authorize → callback URL.
	res2, err := s.client.Get(loc.String())
	if err != nil {
		t.Fatalf("provider authorize: %v", err)
	}
	if res2.StatusCode != http.StatusFound {
		t.Fatalf("provider authorize: expected 302, got %d (%s)", res2.StatusCode, drainBody(res2))
	}
	cbLoc, err := res2.Location()
	if err != nil {
		t.Fatalf("provider redirect location: %v", err)
	}
	res2.Body.Close()
	return cbLoc.String(), state
}

// --- /authorize → /callback happy path ---------------------------------

func TestOAuthEndToEnd_NewUser(t *testing.T) {
	s := newStack(t, oauth.UserInfo{
		ProviderUserID: "remote-1",
		Email:          "dora@example.com",
		EmailVerified:  true,
		Name:           "Dora Explorer",
	})

	cbURL, _ := followAuthorizeAndExtractCallback(t, s, "/welcome")

	res, err := s.client.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d (%s)", res.StatusCode, drainBody(res))
	}
	if got := res.Header.Get("Location"); got != "/welcome" {
		t.Fatalf("callback: expected /welcome, got %q", got)
	}
	hasSession := false
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Fatalf("callback: missing session cookie")
	}
	res.Body.Close()

	// /session reflects the new user.
	res2, err := s.client.Get(s.srv.URL + "/api/auth/session")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("session: expected 200, got %d (%s)", res2.StatusCode, drainBody(res2))
	}
	var sess struct {
		User struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"user"`
	}
	_ = json.NewDecoder(res2.Body).Decode(&sess)
	res2.Body.Close()
	if sess.User.Email != "dora@example.com" {
		t.Fatalf("session email: %q", sess.User.Email)
	}
	if !sess.User.EmailVerified {
		t.Fatalf("session: email_verified=false; provider said true")
	}

	// /accounts lists the link.
	res3, err := s.client.Get(s.srv.URL + "/api/auth/oauth/accounts")
	if err != nil {
		t.Fatalf("accounts: %v", err)
	}
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("accounts: %d (%s)", res3.StatusCode, drainBody(res3))
	}
	var ar struct {
		Items []struct {
			Provider       string `json:"provider"`
			ProviderUserID string `json:"provider_user_id"`
		} `json:"items"`
	}
	_ = json.NewDecoder(res3.Body).Decode(&ar)
	res3.Body.Close()
	if len(ar.Items) != 1 || ar.Items[0].Provider != "fake" || ar.Items[0].ProviderUserID != "remote-1" {
		t.Fatalf("accounts: %+v", ar)
	}

	// Unlink with no other auth method must fail with 409.
	req, _ := http.NewRequest(http.MethodDelete, s.srv.URL+"/api/auth/oauth/fake", nil)
	res4, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if res4.StatusCode != http.StatusConflict {
		t.Fatalf("unlink no-other-auth: expected 409, got %d (%s)", res4.StatusCode, drainBody(res4))
	}
	res4.Body.Close()
}

// --- state validation --------------------------------------------------

func TestOAuthCallback_RejectsBadState(t *testing.T) {
	s := newStack(t, oauth.UserInfo{ProviderUserID: "x", Email: "x@example.com"})
	res, err := s.client.Get(s.srv.URL + "/api/auth/oauth/fake/callback?code=abc&state=never-issued")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", res.StatusCode, drainBody(res))
	}
	res.Body.Close()
}

func TestOAuthState_ConsumedAtomically(t *testing.T) {
	s := newStack(t, oauth.UserInfo{
		ProviderUserID: "remote-3",
		Email:          "frank@example.com",
		EmailVerified:  true,
	})

	cbURL, state := followAuthorizeAndExtractCallback(t, s, "")
	res1, _ := s.client.Get(cbURL)
	res1.Body.Close()

	// Replay with the exact same state — must fail because the row was
	// consumed by the first callback.
	res2, err := s.client.Get(s.srv.URL + "/api/auth/oauth/fake/callback?code=fake-code-OK&state=" + state)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if res2.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay: expected 400, got %d (%s)", res2.StatusCode, drainBody(res2))
	}
	res2.Body.Close()
}

// --- existing-user attach by email -------------------------------------

func TestOAuthFlow_LinksToExistingUserByEmail(t *testing.T) {
	s := newStack(t, oauth.UserInfo{
		ProviderUserID: "remote-4",
		Email:          "georgia@example.com",
		EmailVerified:  true,
	})

	// Register via email/password.
	body := strings.NewReader(`{"email":"georgia@example.com","password":"correct horse battery staple"}`)
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register: %d (%s)", res.StatusCode, drainBody(res))
	}
	res.Body.Close()

	// Logout so the OAuth flow runs as anonymous. /register no longer issues a
	// session at all, so this is belt-and-braces.
	logoutReq, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/logout", nil)
	res2, _ := s.client.Do(logoutReq)
	res2.Body.Close()

	// OAuth flow.
	cbURL, _ := followAuthorizeAndExtractCallback(t, s, "")
	res3, err := s.client.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("callback: expected 200, got %d (%s)", res3.StatusCode, drainBody(res3))
	}
	res3.Body.Close()

	// /session matches the original user.
	res4, _ := s.client.Get(s.srv.URL + "/api/auth/session")
	var sess struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.NewDecoder(res4.Body).Decode(&sess)
	res4.Body.Close()
	if sess.User.Email != "georgia@example.com" {
		t.Fatalf("session email: %q", sess.User.Email)
	}

	// Unlink succeeds because the user still has a password.
	req3, _ := http.NewRequest(http.MethodDelete, s.srv.URL+"/api/auth/oauth/fake", nil)
	res5, err := s.client.Do(req3)
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if res5.StatusCode != http.StatusNoContent {
		t.Fatalf("unlink: expected 204, got %d (%s)", res5.StatusCode, drainBody(res5))
	}
	res5.Body.Close()
}

// --- POST /link native typed Body --------------------------------------

// registerAndLogin registers a fresh email/password user; the cookie jar
// retains the session so subsequent requests on s.client are authenticated.
func registerAndLogin(t *testing.T, s *stack, email string) {
	t.Helper()
	const password = "correct horse battery staple"
	body := strings.NewReader(`{"email":"` + email + `","password":"` + password + `"}`)
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d (%s)", res.StatusCode, drainBody(res))
	}
	res.Body.Close()

	// /register is enumeration-neutral: it answers 200 with the same body
	// whether or not the address was free and issues NO session (see
	// emailpassword.Config.RevealRegistrationOutcome), so sign in afterwards.
	loginBody := strings.NewReader(`{"email":"` + email + `","password":"` + password + `"}`)
	loginReq, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	lres, err := s.client.Do(loginReq)
	if err != nil {
		t.Fatalf("login after register: %v", err)
	}
	defer lres.Body.Close()
	if lres.StatusCode != http.StatusOK {
		t.Fatalf("login after register: %d (%s)", lres.StatusCode, drainBody(lres))
	}
}

// postLink POSTs to /oauth/fake/link with the given raw request body
// (rawBody==nil means "no body at all"), returning the response.
func postLink(t *testing.T, s *stack, rawBody []byte) *http.Response {
	t.Helper()
	var rdr io.Reader
	if rawBody != nil {
		rdr = strings.NewReader(string(rawBody))
	}
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/oauth/fake/link", rdr)
	if rawBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	return res
}

// TestOAuthLink_NativeBody exercises the native typed Body conversion of
// POST /oauth/{provider}/link:
//
//   - a no-body POST succeeds (redirect_url has always been optional, so the
//     Body is a pointer and a nil body is accepted);
//   - a valid body POST succeeds — the redirect_url now arrives in the typed
//     body (was a query param) and still flows through safeRedirect unchanged;
//   - an unknown field is rejected with 422 (additionalProperties:false — the
//     RFC-standard validation status that replaces the old strict-decode 400,
//     matching the apikey conversion);
//   - a syntactically-malformed JSON body is rejected by huma's parser with 400
//     (huma returns 400 for an unparseable body and 422 only for schema
//     validation — we assert both statuses to pin the contract).
func TestOAuthLink_NativeBody(t *testing.T) {
	s := newStackWithRedirects(t, oauth.UserInfo{
		ProviderUserID: "link-remote-1",
		Email:          "linker@example.com",
		EmailVerified:  true,
	}, nil)
	registerAndLogin(t, s, "linker@example.com")

	// 1) No body at all → 200 with an auth_url (optional pointer Body).
	res := postLink(t, s, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("link no-body: expected 200, got %d (%s)", res.StatusCode, drainBody(res))
	}
	var lr struct {
		AuthURL string `json:"auth_url"`
	}
	_ = json.NewDecoder(res.Body).Decode(&lr)
	res.Body.Close()
	if lr.AuthURL == "" {
		t.Fatalf("link no-body: empty auth_url")
	}

	// 2) Valid body with a host-relative redirect_url (always allowed by
	//    safeRedirect) → 200. The provider account is not yet linked (the user
	//    registered via email/password), so /link starts a fresh flow.
	res = postLink(t, s, []byte(`{"redirect_url":"/after-link"}`))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("link valid-body: expected 200, got %d (%s)", res.StatusCode, drainBody(res))
	}
	lr.AuthURL = ""
	_ = json.NewDecoder(res.Body).Decode(&lr)
	res.Body.Close()
	if lr.AuthURL == "" {
		t.Fatalf("link valid-body: empty auth_url")
	}

	// The body's redirect_url must actually be READ and persisted (this is the
	// whole point of the query→body move): the minted state row carries the
	// redirect in its RedirectURL payload. Pull the state token out of auth_url
	// and consume the row to assert it round-tripped through safeRedirect.
	authU, err := url.Parse(lr.AuthURL)
	if err != nil {
		t.Fatalf("parse auth_url: %v", err)
	}
	stateTok := authU.Query().Get("state")
	if stateTok == "" {
		t.Fatalf("auth_url missing state: %s", lr.AuthURL)
	}
	st, err := s.repo.ConsumeOAuthState(context.Background(), stateTok)
	if err != nil || st == nil {
		t.Fatalf("consume state: %v (st=%v)", err, st)
	}
	if st.RedirectURL == nil || !strings.Contains(*st.RedirectURL, "/after-link") {
		t.Fatalf("state RedirectURL did not capture body redirect_url: %v", st.RedirectURL)
	}

	// 3) Unknown field → 422 (additionalProperties:false).
	res = postLink(t, s, []byte(`{"redirect_url":"/x","bogus":true}`))
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("link unknown-field: expected 422, got %d (%s)", res.StatusCode, drainBody(res))
	}
	res.Body.Close()

	// 4) Syntactically-malformed JSON → 400 (huma's parser; 422 is reserved for
	//    schema validation). The point is the body is now huma-validated at all,
	//    which it was not under the StashHTTPHuma bridge.
	res = postLink(t, s, []byte(`{"redirect_url":`))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("link malformed-body: expected 400, got %d (%s)", res.StatusCode, drainBody(res))
	}
	res.Body.Close()
}

// --- construction validation ------------------------------------------

func TestOAuthBuild_RejectsInvalidConfig(t *testing.T) {
	if _, err := oauth.New(oauth.Config{}); err == nil {
		t.Fatalf("zero key: expected error, got nil")
	}
	var k [32]byte
	k[0] = 1
	if _, err := oauth.New(oauth.Config{EncryptionKey: k}); err == nil {
		t.Fatalf("no providers: expected error, got nil")
	}
}
