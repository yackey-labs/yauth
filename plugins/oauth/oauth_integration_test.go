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

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/plugins/oauth"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
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
}

func newStack(t *testing.T, info oauth.UserInfo) *stack {
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

	db, err := gormrepo.OpenSQLite("file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := gormrepo.New(db)

	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	op, err := oauth.New(oauth.Config{
		EncryptionKey: key,
		Providers:     []oauth.Provider{prov},
		StateTTL:      5 * time.Minute,
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
	return &stack{srv: srv, client: cl, provider: prov}
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
		Accounts []struct {
			Provider       string `json:"provider"`
			ProviderUserID string `json:"provider_user_id"`
		} `json:"accounts"`
	}
	_ = json.NewDecoder(res3.Body).Decode(&ar)
	res3.Body.Close()
	if len(ar.Accounts) != 1 || ar.Accounts[0].Provider != "fake" || ar.Accounts[0].ProviderUserID != "remote-1" {
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
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d (%s)", res.StatusCode, drainBody(res))
	}
	res.Body.Close()

	// Logout so the OAuth flow runs as anonymous.
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
