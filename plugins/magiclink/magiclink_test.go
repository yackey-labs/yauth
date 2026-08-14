package magiclink_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/magiclink"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// captureMailer records (email, link) pairs in order so tests can assert
// what was sent without spinning up an SMTP server.
type captureMailer struct {
	mu    sync.Mutex
	calls []struct{ Email, Link string }
}

func (m *captureMailer) SendMagicLink(_ context.Context, email, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, struct{ Email, Link string }{email, link})
	return nil
}

func (m *captureMailer) last() (string, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return "", "", false
	}
	c := m.calls[len(m.calls)-1]
	return c.Email, c.Link, true
}

func (m *captureMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// waitForMails polls until the mailer has recorded at least n sends.
//
// registerSend now dispatches the mail OFF the request goroutine — a send that
// blocks the response makes the response time an account-existence oracle — so
// "read the mailer on the line after the response" became a race. These tests
// pin correct behaviour (a link is mailed, and it signs in), so they are made
// to wait for the send rather than weakened to stop looking for it.
func (m *captureMailer) waitForMails(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.count() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d magic-link mail(s); the mailer recorded %d", n, m.count())
}

// waitLink polls for at least one send and returns the most recent link.
func (m *captureMailer) waitLink(t *testing.T) string {
	t.Helper()
	m.waitForMails(t, 1)
	_, link, _ := m.last()
	return link
}

// settle waits until the send count stops moving, which is what an UPPER-bound
// assertion needs: there is no condition to poll for, only quiescence. Polling
// for a stable count beats a fixed sleep — it is both faster in the normal case
// and does not silently under-count on a loaded machine.
func (m *captureMailer) settle() {
	deadline := time.Now().Add(2 * time.Second)
	prev := -1
	for time.Now().Before(deadline) {
		n := m.count()
		if n == prev {
			return
		}
		prev = n
		time.Sleep(50 * time.Millisecond)
	}
}

func newServer(t *testing.T, cfg magiclink.Config) (*httptest.Server, *captureMailer, func()) {
	t.Helper()

	repo := memrepo.New()

	mailer := &captureMailer{}
	cfg.Mailer = mailer
	if cfg.LinkBaseURL == "" {
		cfg.LinkBaseURL = "https://example.test/magic"
	}

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(magiclink.New(cfg)).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, mailer, func() { srv.Close() }
}

func postJSON(t *testing.T, c *http.Client, url string, body any) *http.Response {
	t.Helper()
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func drain(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func tokenFromLink(link string) string {
	const marker = "token="
	idx := strings.Index(link, marker)
	if idx < 0 {
		return ""
	}
	return link[idx+len(marker):]
}

// Send-with-no-user-and-no-signup must still 200 and must NOT email.
func TestSend_NoUser_SignupDisabled_ReturnsOKAndDoesNotEmail(t *testing.T) {
	srv, mailer, stop := newServer(t, magiclink.Config{SignupEnabled: false})
	defer stop()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	res := postJSON(t, c, srv.URL+"/api/auth/magic-link/send", map[string]string{
		"email": "ghost@example.com",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	if mailer.count() != 0 {
		t.Fatalf("expected no emails sent, got %d", mailer.count())
	}
}

// /send for an unknown email with signup ENABLED still 200 AND emails (so
// the requester can complete account creation).
func TestSend_NoUser_SignupEnabled_EmailsLink(t *testing.T) {
	srv, mailer, stop := newServer(t, magiclink.Config{SignupEnabled: true})
	defer stop()

	c := &http.Client{}
	res := postJSON(t, c, srv.URL+"/api/auth/magic-link/send", map[string]string{
		"email": "newuser@example.com",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	res.Body.Close()
	mailer.waitForMails(t, 1)
	mailer.settle()
	if mailer.count() != 1 {
		t.Fatalf("expected 1 email, got %d", mailer.count())
	}
}

// Verify with signup enabled creates the user and returns a session cookie.
func TestVerify_SignupEnabled_CreatesUserAndIssuesSession(t *testing.T) {
	srv, mailer, stop := newServer(t, magiclink.Config{SignupEnabled: true})
	defer stop()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	const email = "alice@example.com"
	res := postJSON(t, c, srv.URL+"/api/auth/magic-link/send", map[string]string{
		"email": email,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("send: %d", res.StatusCode)
	}
	link := mailer.waitLink(t)
	tok := tokenFromLink(link)
	if tok == "" {
		t.Fatalf("no token in link %q", link)
	}

	res = postJSON(t, c, srv.URL+"/api/auth/magic-link/verify", map[string]string{
		"token": tok,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var body struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if body.User.Email != email {
		t.Fatalf("verify returned email %q, want %q", body.User.Email, email)
	}

	// Cookie should be set on the jar.
	u, _ := url.Parse(srv.URL)
	if cs := jar.Cookies(u); len(cs) == 0 {
		t.Fatalf("expected session cookie to be set")
	}
}

// Verify with signup disabled and unknown email rejects with 401.
func TestVerify_SignupDisabled_UnknownToken_401(t *testing.T) {
	srv, _, stop := newServer(t, magiclink.Config{SignupEnabled: false})
	defer stop()

	c := &http.Client{}
	res := postJSON(t, c, srv.URL+"/api/auth/magic-link/verify", map[string]string{
		"token": "not-a-real-token",
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// A token cannot be consumed twice.
func TestVerify_TokenSingleUse(t *testing.T) {
	srv, mailer, stop := newServer(t, magiclink.Config{SignupEnabled: true})
	defer stop()

	c := &http.Client{}
	res := postJSON(t, c, srv.URL+"/api/auth/magic-link/send", map[string]string{
		"email": "bob@example.com",
	})
	res.Body.Close()
	link := mailer.waitLink(t)
	tok := tokenFromLink(link)

	res = postJSON(t, c, srv.URL+"/api/auth/magic-link/verify", map[string]string{
		"token": tok,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first verify: %d", res.StatusCode)
	}
	res.Body.Close()

	res = postJSON(t, c, srv.URL+"/api/auth/magic-link/verify", map[string]string{
		"token": tok,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second verify: expected 401, got %d", res.StatusCode)
	}
	res.Body.Close()
}

// Expired token rejects (driven by passing a 1ns TTL — the token is
// already expired at the moment of insertion).
func TestVerify_ExpiredToken_401(t *testing.T) {
	srv, mailer, stop := newServer(t, magiclink.Config{
		SignupEnabled: true,
		TokenTTL:      1 * time.Nanosecond,
	})
	defer stop()

	c := &http.Client{}
	res := postJSON(t, c, srv.URL+"/api/auth/magic-link/send", map[string]string{
		"email": "carol@example.com",
	})
	res.Body.Close()
	link := mailer.waitLink(t)
	tok := tokenFromLink(link)

	// Sleep a hair to let the TTL elapse cross-platform.
	time.Sleep(5 * time.Millisecond)

	res = postJSON(t, c, srv.URL+"/api/auth/magic-link/verify", map[string]string{
		"token": tok,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
	res.Body.Close()
}
