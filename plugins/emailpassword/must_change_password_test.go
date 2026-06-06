package emailpassword_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newMCPServer builds a yauth server with the email-password plugin and
// returns both the test server and the underlying repo so the test can set
// and assert the must_change_password flag directly.
func newMCPServer(t *testing.T) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.SessionTTL = 1 * time.Hour

	ya, err := yauth.New(r, cfg).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	return httptest.NewServer(mux), r
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// mustNewPostJSON builds (but does not send) a POST request with a JSON body
// so the caller can attach cookies before sending.
func mustNewPostJSON(t *testing.T, url string, body any) *http.Request {
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
	return req
}

// TestChangePassword_ClearsMustChangeFlag verifies that a successful
// authenticated change-password clears must_change_password.
func TestChangePassword_ClearsMustChangeFlag(t *testing.T) {
	srv, r := newMCPServer(t)
	defer srv.Close()

	const email = "alice@example.com"
	const password = "correct horse battery staple"
	const newPassword = "another correct horse staple"

	// Register, then mark the account as must-change (admin/seed path).
	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email": email, "password": password,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", res.StatusCode)
	}
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if err := r.SetUserMustChangePassword(context.Background(), u.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}

	// Log in to obtain a session cookie.
	res = postJSON(t, srv.URL+"/api/auth/login", map[string]any{
		"email": email, "password": password,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", res.StatusCode)
	}
	cookie := findCookie(res, "yauth_session")
	if cookie == nil {
		t.Fatalf("no session cookie")
	}

	// The /session response (what a SPA reads after login) must surface the
	// flag so the app can gate/redirect. yauth itself does not block.
	sreq, err := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/session", nil)
	if err != nil {
		t.Fatalf("new session req: %v", err)
	}
	sreq.AddCookie(cookie)
	sres, err := http.DefaultClient.Do(sreq)
	if err != nil {
		t.Fatalf("session do: %v", err)
	}
	var sbody struct {
		User struct {
			MustChangePassword bool `json:"must_change_password"`
		} `json:"user"`
	}
	if err := json.NewDecoder(sres.Body).Decode(&sbody); err != nil {
		sres.Body.Close()
		t.Fatalf("decode session: %v", err)
	}
	sres.Body.Close()
	if sres.StatusCode != http.StatusOK {
		t.Fatalf("session: %d", sres.StatusCode)
	}
	if !sbody.User.MustChangePassword {
		t.Fatalf("expected /session to surface must_change_password=true")
	}

	// Change password with the session cookie attached.
	req := mustNewPostJSON(t, srv.URL+"/api/auth/change-password", map[string]any{
		"current_password": password,
		"new_password":     newPassword,
	})
	req.AddCookie(cookie)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("change-password do: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("change-password: %d", res.StatusCode)
	}

	got, err := r.GetUserByID(context.Background(), u.ID)
	if err != nil || got == nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.MustChangePassword {
		t.Fatalf("expected must_change_password cleared after change-password")
	}
}

// TestLogin_MustChange_GatesUntilChanged verifies the server-side enforcement:
// a must_change_password user logs in and gets a session cookie, but every
// non-exempt route is 403-gated (PATCH /me here) until they rotate the
// password via the exempt /change-password route — after which the gate lifts.
func TestLogin_MustChange_GatesUntilChanged(t *testing.T) {
	srv, r := newMCPServer(t)
	defer srv.Close()

	const email = "carol@example.com"
	const password = "correct horse battery staple"
	const newPassword = "another correct horse staple"

	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{"email": email, "password": password})
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", res.StatusCode)
	}
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if err := r.SetUserMustChangePassword(context.Background(), u.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}

	// Login still succeeds and yields a cookie (response shape unchanged).
	res = postJSON(t, srv.URL+"/api/auth/login", map[string]any{"email": email, "password": password})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", res.StatusCode)
	}
	cookie := findCookie(res, "yauth_session")
	if cookie == nil {
		t.Fatalf("no session cookie")
	}

	// A gated route (PATCH /me) is forbidden while must_change is set.
	gated := func() int {
		body, _ := json.Marshal(map[string]any{"display_name": "Carol"})
		req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/me", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("patch me: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := gated(); got != http.StatusForbidden {
		t.Fatalf("PATCH /me before change = %d, want 403", got)
	}

	// The exempt /change-password route works and clears the flag.
	creq := mustNewPostJSON(t, srv.URL+"/api/auth/change-password", map[string]any{
		"current_password": password, "new_password": newPassword,
	})
	creq.AddCookie(cookie)
	cres, err := http.DefaultClient.Do(creq)
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	// change-password re-issues the session; use the fresh cookie.
	newCookie := findCookie(cres, "yauth_session")
	cres.Body.Close()
	if cres.StatusCode != http.StatusOK {
		t.Fatalf("change-password: %d", cres.StatusCode)
	}
	if newCookie != nil {
		cookie = newCookie
	}

	if got := gated(); got != http.StatusOK {
		t.Fatalf("PATCH /me after change = %d, want 200", got)
	}
}

// TestResetPassword_ClearsMustChangeFlag verifies that a successful
// reset-password clears must_change_password (the admin-forced-reset flow).
func TestResetPassword_ClearsMustChangeFlag(t *testing.T) {
	srv, r := newMCPServer(t)
	defer srv.Close()

	const email = "bob@example.com"
	const password = "correct horse battery staple"
	const newPassword = "another correct horse staple"
	const rawToken = "reset-token-raw-value-1234567890"

	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email": email, "password": password,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", res.StatusCode)
	}
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if err := r.SetUserMustChangePassword(context.Background(), u.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}

	// Provision a reset token directly (mirrors the forgot-password mailer
	// having delivered the raw token to the user).
	now := time.Now().UTC()
	if err := r.CreatePasswordReset(context.Background(), domain.NewPasswordReset{
		ID:        "pr1",
		UserID:    u.ID,
		TokenHash: sha256hex(rawToken),
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreatePasswordReset: %v", err)
	}

	res = postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": rawToken, "password": newPassword,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reset-password: %d", res.StatusCode)
	}

	got, err := r.GetUserByID(context.Background(), u.ID)
	if err != nil || got == nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.MustChangePassword {
		t.Fatalf("expected must_change_password cleared after reset-password")
	}
}
