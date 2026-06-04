package emailpassword_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// findCookie returns the named cookie from a Set-Cookie response or nil.
func findCookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func newRememberServer(t *testing.T, rememberTTL time.Duration) *httptest.Server {
	t.Helper()
	r := memrepo.New()

	cfg := yauth.NewDefaultConfig()
	// Force a session TTL distinct from the remember-me TTL so we can tell them
	// apart in the resulting cookie MaxAge.
	cfg.SessionTTL = 1 * time.Hour

	ya, err := yauth.New(r, cfg).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			RememberMeTTL:     rememberTTL,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	return httptest.NewServer(mux)
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

// TestLogin_RememberMe verifies that remember_me=true on login produces a
// session cookie whose MaxAge corresponds to the configured RememberMeTTL,
// while remember_me=false (or absent) yields the host's SessionTTL.
func TestLogin_RememberMe(t *testing.T) {
	rememberTTL := 7 * 24 * time.Hour
	srv := newRememberServer(t, rememberTTL)
	defer srv.Close()

	const email = "alice@example.com"
	const password = "correct horse battery staple"

	// Register so the user exists. The register response also sets a cookie,
	// but we ignore it and exercise login below.
	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email":    email,
		"password": password,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", res.StatusCode)
	}

	// Login without remember_me — cookie MaxAge should match SessionTTL (1h).
	res = postJSON(t, srv.URL+"/api/auth/login", map[string]any{
		"email":    email,
		"password": password,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", res.StatusCode)
	}
	c := findCookie(res, "yauth_session")
	if c == nil {
		t.Fatalf("no session cookie")
	}
	if c.MaxAge != int((1 * time.Hour).Seconds()) {
		t.Fatalf("expected MaxAge=%d (1h), got %d", int((1 * time.Hour).Seconds()), c.MaxAge)
	}

	// Login with remember_me=true — MaxAge should be the configured RememberMeTTL.
	res = postJSON(t, srv.URL+"/api/auth/login", map[string]any{
		"email":       email,
		"password":    password,
		"remember_me": true,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login remember_me: %d", res.StatusCode)
	}
	c = findCookie(res, "yauth_session")
	if c == nil {
		t.Fatalf("no session cookie on remember_me login")
	}
	if c.MaxAge != int(rememberTTL.Seconds()) {
		t.Fatalf("expected MaxAge=%d (remember_me), got %d", int(rememberTTL.Seconds()), c.MaxAge)
	}
}
