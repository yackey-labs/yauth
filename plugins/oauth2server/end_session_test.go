package oauth2server_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth-go/domain"
)

// idTokenFor runs the full auth-code flow and returns the id_token for a client
// that registers postLogoutURI as a post_logout_redirect_uri.
func (h *harness) idTokenFor(t *testing.T, adminCookie, userCookie, redirectURI, postLogoutURI string) (clientID, idToken string) {
	t.Helper()
	body := `{"name":"logout-app","redirect_uris":["` + redirectURI + `"],"grant_types":["authorization_code","refresh_token"],"scopes":["openid","read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post","post_logout_redirect_uris":["` + postLogoutURI + `"]}`
	cid, secret, _ := h.createClient(t, adminCookie, body)

	verifier := "end-session-pkce-verifier-43-characters-long-x"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, cid, redirectURI, "openid read", challenge, "s1", "n1")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", cid)
	form.Set("client_secret", secret)
	form.Set("code_verifier", verifier)
	status, tok := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, tok)
	}
	idt, _ := tok["id_token"].(string)
	if idt == "" {
		t.Fatalf("no id_token in token response: %v", tok)
	}
	return cid, idt
}

func (h *harness) userHasSession(t *testing.T, userID string) bool {
	t.Helper()
	rows, _, err := h.repo.ListSessions(context.Background(), domain.ListSessionsFilters{Limit: 200})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	for _, s := range rows {
		if s.UserID == userID {
			return true
		}
	}
	return false
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// TestEndSession_RedirectsToRegisteredURI proves the happy path: a valid
// id_token_hint + registered post_logout_redirect_uri yields a 302 back to the
// RP with state echoed, and the browser session is terminated.
func TestEndSession_RedirectsToRegisteredURI(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	userID, userCookie := h.seedUser(t, "alice@idp.test", "user")

	postLogout := "https://app.example/after-logout"
	_, idt := h.idTokenFor(t, adminCookie, userCookie, "https://app.example/callback", postLogout)

	q := url.Values{}
	q.Set("id_token_hint", idt)
	q.Set("post_logout_redirect_uri", postLogout)
	q.Set("state", "xyz123")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/end_session?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})

	res, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, postLogout) {
		t.Fatalf("expected redirect to %s, got %s", postLogout, loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") != "xyz123" {
		t.Fatalf("expected state echoed, got %s", loc)
	}

	// The browser session must be gone.
	if h.userHasSession(t, userID) {
		t.Fatalf("expected session terminated after end_session")
	}
	// And the clearing cookie must be set.
	var cleared bool
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("expected session cookie cleared")
	}
}

// TestEndSession_RejectsUnregisteredRedirect is the open-redirect guard: a
// post_logout_redirect_uri not registered for the client is refused (no 302).
func TestEndSession_RejectsUnregisteredRedirect(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	_, idt := h.idTokenFor(t, adminCookie, userCookie, "https://app.example/callback", "https://app.example/after-logout")

	q := url.Values{}
	q.Set("id_token_hint", idt)
	q.Set("post_logout_redirect_uri", "https://evil.example/steal")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/end_session?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})

	res, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusFound {
		t.Fatalf("open redirect! got 302 to %s", res.Header.Get("Location"))
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unregistered uri, got %d", res.StatusCode)
	}
}

// TestEndSession_InvalidHintNoRedirect proves a forged/invalid id_token_hint is
// not trusted to authorize a redirect (RP-Initiated Logout 1.0 §2).
func TestEndSession_InvalidHintNoRedirect(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	// Register the client/URI so the only failing factor is the bad hint.
	_, _ = h.idTokenFor(t, adminCookie, userCookie, "https://app.example/callback", "https://app.example/after-logout")

	q := url.Values{}
	q.Set("id_token_hint", "not.a.valid.jwt")
	q.Set("post_logout_redirect_uri", "https://app.example/after-logout")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/end_session?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})

	res, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusFound {
		t.Fatalf("redirected on invalid hint to %s", res.Header.Get("Location"))
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid hint, got %d", res.StatusCode)
	}
}

// TestEndSession_NoRedirectLogsOut proves end_session with no redirect target
// still terminates the session and returns a 200 logged-out page.
func TestEndSession_NoRedirectLogsOut(t *testing.T) {
	h := newHarness(t)
	userID, userCookie := h.seedUser(t, "alice@idp.test", "user")

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/end_session", nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})

	res, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if h.userHasSession(t, userID) {
		t.Fatalf("expected session terminated")
	}
}
