package lockout_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/plugins/lockout"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

type captureMailer struct {
	mu    sync.Mutex
	calls []struct{ Email, Link string }
}

func (m *captureMailer) SendUnlockToken(_ context.Context, email, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, struct{ Email, Link string }{email, link})
	return nil
}

func (m *captureMailer) lastLink() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return ""
	}
	return m.calls[len(m.calls)-1].Link
}

func tokenFromLink(link string) string {
	const marker = "token="
	idx := strings.Index(link, marker)
	if idx < 0 {
		return ""
	}
	return link[idx+len(marker):]
}

func newServer(t *testing.T, cfg lockout.Config) (*httptest.Server, *captureMailer, func()) {
	t.Helper()
	db, err := gormrepo.OpenSQLite("file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)

	mailer := &captureMailer{}
	cfg.Mailer = mailer
	if cfg.LinkBaseURL == "" {
		cfg.LinkBaseURL = "https://example.test/unlock"
	}

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		WithPlugin(lockout.New(cfg)).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
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

func register(t *testing.T, srv *httptest.Server, c *http.Client, email, pw string) {
	t.Helper()
	res := postJSON(t, c, srv.URL+"/api/auth/register", map[string]string{
		"email":    email,
		"password": pw,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// Verify the lock kicks in after MaxAttempts failed logins, and unlocks
// after the cooldown elapses.
func TestLockout_ThresholdAndCooldown(t *testing.T) {
	srv, _, stop := newServer(t, lockout.Config{
		MaxAttempts:      3,
		LockoutDurations: []time.Duration{50 * time.Millisecond},
	})
	defer stop()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	const email = "alice@example.com"
	const pw = "correct horse battery staple"
	register(t, srv, c, email, pw)
	// log out to start clean
	res := postJSON(t, c, srv.URL+"/api/auth/logout", struct{}{})
	res.Body.Close()

	// 3 wrong-password attempts; the third should succeed at HTTP layer
	// (handled within emailpassword as 401 but the lock gets armed
	// because the threshold-check uses `>= MaxAttempts`).
	for i := 0; i < 3; i++ {
		res := postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
			"email":    email,
			"password": "wrong",
		})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d (%s)", i+1, res.StatusCode, drain(res))
		}
		res.Body.Close()
	}

	// 4th attempt — even with the correct password — must be blocked 429.
	res = postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": pw,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("post-threshold attempt: expected 429, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Wait for the cooldown to elapse, then a correct login should
	// succeed and reset the counter.
	time.Sleep(80 * time.Millisecond)
	res = postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": pw,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("post-cooldown login: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// /unlock with a valid token clears the lock.
func TestUnlock_TokenClearsLock(t *testing.T) {
	srv, mailer, stop := newServer(t, lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{1 * time.Hour},
	})
	defer stop()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	const email = "bob@example.com"
	const pw = "correct horse battery staple"
	register(t, srv, c, email, pw)
	res := postJSON(t, c, srv.URL+"/api/auth/logout", struct{}{})
	res.Body.Close()

	// Trip the lock.
	for i := 0; i < 2; i++ {
		res := postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
			"email":    email,
			"password": "wrong",
		})
		res.Body.Close()
	}
	// Confirm locked.
	res = postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": pw,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected lock 429, got %d", res.StatusCode)
	}
	res.Body.Close()

	// Request an unlock token.
	res = postJSON(t, c, srv.URL+"/api/auth/account/request-unlock", map[string]string{
		"email": email,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unlock/request: %d", res.StatusCode)
	}
	res.Body.Close()
	tok := tokenFromLink(mailer.lastLink())
	if tok == "" {
		t.Fatalf("no token in unlock email")
	}

	res = postJSON(t, c, srv.URL+"/api/auth/account/unlock", map[string]string{
		"token": tok,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unlock: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Now login should work again.
	res = postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": pw,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("post-unlock login: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// Unlock-request for an unknown email returns 200 (enumeration prevention)
// and emails nothing.
func TestUnlockRequest_UnknownEmail_200_NoSend(t *testing.T) {
	srv, mailer, stop := newServer(t, lockout.Config{})
	defer stop()
	c := &http.Client{}
	res := postJSON(t, c, srv.URL+"/api/auth/account/request-unlock", map[string]string{
		"email": "ghost@example.com",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	res.Body.Close()
	mailer.mu.Lock()
	defer mailer.mu.Unlock()
	if len(mailer.calls) != 0 {
		t.Fatalf("expected no email, got %d", len(mailer.calls))
	}
}

// MaxLockoutDuration caps the per-step lockout window even when
// LockoutDurations is configured larger.
func TestLockout_MaxLockoutDurationCapsStep(t *testing.T) {
	srv, _, stop := newIsolatedServer(t, lockout.Config{
		MaxAttempts: 2,
		// 1h step requested, but cap is 50ms — the cooldown should
		// elapse fast enough that the next login wins.
		LockoutDurations:   []time.Duration{1 * time.Hour},
		MaxLockoutDuration: 50 * time.Millisecond,
	})
	defer stop()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	const email = "cap@example.com"
	const pw = "correct horse battery staple"
	register(t, srv, c, email, pw)
	res := postJSON(t, c, srv.URL+"/api/auth/logout", struct{}{})
	res.Body.Close()

	for i := 0; i < 2; i++ {
		res := postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
			"email": email, "password": "wrong",
		})
		res.Body.Close()
	}

	// Cap=50ms — wait it out and the correct login should succeed,
	// proving the 1h step was truncated to the cap.
	time.Sleep(120 * time.Millisecond)
	res = postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
		"email": email, "password": pw,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected post-cap login 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// AutoUnlock=false suppresses the lazy timer-based clear; only an
// explicit /unlock can free the account.
func TestLockout_AutoUnlockFalseRequiresExplicitUnlock(t *testing.T) {
	off := false
	srv, mailer, stop := newIsolatedServer(t, lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{20 * time.Millisecond},
		AutoUnlock:       &off,
	})
	defer stop()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	const email = "noauto@example.com"
	const pw = "correct horse battery staple"
	register(t, srv, c, email, pw)
	res := postJSON(t, c, srv.URL+"/api/auth/logout", struct{}{})
	res.Body.Close()

	for i := 0; i < 2; i++ {
		res := postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
			"email": email, "password": "wrong",
		})
		res.Body.Close()
	}

	// Wait long past the cooldown — with AutoUnlock=false this must NOT
	// re-open the account; the lock stays armed.
	time.Sleep(80 * time.Millisecond)
	res = postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
		"email": email, "password": pw,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected still-locked 429, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Explicit /unlock token clears the lock.
	res = postJSON(t, c, srv.URL+"/api/auth/account/request-unlock", map[string]string{"email": email})
	res.Body.Close()
	tok := tokenFromLink(mailer.lastLink())
	if tok == "" {
		t.Fatalf("no unlock token issued")
	}
	res = postJSON(t, c, srv.URL+"/api/auth/account/unlock", map[string]string{"token": tok})
	res.Body.Close()

	res = postJSON(t, c, srv.URL+"/api/auth/login", map[string]string{
		"email": email, "password": pw,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected post-unlock 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// newIsolatedServer is a sibling of newServer that uses a unique
// in-memory SQLite instance per test, so the shared rate-limit table
// from neighbouring tests cannot bleed in and exhaust login budgets.
func newIsolatedServer(t *testing.T, cfg lockout.Config) (*httptest.Server, *captureMailer, func()) {
	t.Helper()
	dsn := "file:lockout_" + t.Name() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)

	mailer := &captureMailer{}
	cfg.Mailer = mailer
	if cfg.LinkBaseURL == "" {
		cfg.LinkBaseURL = "https://example.test/unlock"
	}

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		WithPlugin(lockout.New(cfg)).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, mailer, func() { srv.Close() }
}

// /lockout/state requires admin.
func TestLockoutState_RequiresAdmin(t *testing.T) {
	srv, _, stop := newServer(t, lockout.Config{})
	defer stop()
	c := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/lockout/state", nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 (no auth), got %d", res.StatusCode)
	}
	res.Body.Close()
}
