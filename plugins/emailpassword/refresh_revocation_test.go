package emailpassword_test

// Password rotation must terminate BEARER credentials as well as cookie
// sessions. Both handlers used to call DeleteUserSessions alone, so an
// attacker who had signed in at /token with a stolen password kept a
// 30-day refresh token that rolled forward indefinitely after the victim
// changed the password — the one control a user reaches for after a
// compromise was the only termination path that left refresh tokens alive.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const revokeTestJWTSecret = "test-secret-min-32-bytes-long-yes-yes"

// newBearerServer wires email-password AND bearer against one memrepo, so a
// test can hold a real refresh token issued by /token while driving the
// cookie-side password handlers.
func newBearerServer(t *testing.T) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.SessionTTL = time.Hour

	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte(revokeTestJWTSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
		})).
		WithPlugin(bearer.New(bearer.Config{})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// issueRefreshToken registers the account (if needed) and signs in at
// /token, returning the refresh token a native client would keep.
func issueRefreshToken(t *testing.T, srv *httptest.Server, email, password string) string {
	t.Helper()
	res := postJSON(t, srv.URL+"/api/auth/token", map[string]any{
		"email": email, "password": password,
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: %d", res.StatusCode)
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if body.RefreshToken == "" {
		t.Fatalf("token: no refresh token issued")
	}
	return body.RefreshToken
}

// assertRefreshRefused asserts the refusal itself: a non-200 from
// /token/refresh AND no token of either kind in the body.
func assertRefreshRefused(t *testing.T, srv *httptest.Server, refresh string) {
	t.Helper()
	res := postJSON(t, srv.URL+"/api/auth/token/refresh", map[string]any{
		"refresh_token": refresh,
	})
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatalf("refresh after password rotation: expected refusal, got 200")
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&body)
	if body.AccessToken != "" || body.RefreshToken != "" {
		t.Fatalf("refusal still handed out tokens: access=%q refresh=%q", body.AccessToken, body.RefreshToken)
	}
}

func registerUser(t *testing.T, srv *httptest.Server, email, password string) {
	t.Helper()
	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email": email, "password": password,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", res.StatusCode)
	}
}

// TestChangePassword_RevokesRefreshTokens is the attacker scenario: the
// attacker holds a refresh token minted with the stolen password, the victim
// changes the password, and the refresh token must die with the sessions.
// The victim's OWN device must survive — the cookie handed back by
// change-password is issued after the revocation and is a session, not a
// refresh token, so it still resolves.
func TestChangePassword_RevokesRefreshTokens(t *testing.T) {
	srv, r := newBearerServer(t)

	const email = "alice@example.com"
	const password = "correct horse battery staple"
	const newPassword = "another correct horse staple"

	registerUser(t, srv, email, password)
	attackerRefresh := issueRefreshToken(t, srv, email, password)

	// Victim logs in on their own device and rotates the password.
	res := postJSON(t, srv.URL+"/api/auth/login", map[string]any{
		"email": email, "password": password,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", res.StatusCode)
	}
	cookie := findCookie(res, "yauth_session")
	if cookie == nil {
		t.Fatalf("login: no session cookie")
	}

	req := mustNewPostJSON(t, srv.URL+"/api/auth/change-password", map[string]any{
		"current_password": password, "new_password": newPassword,
	})
	req.AddCookie(cookie)
	cres, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	cres.Body.Close()
	if cres.StatusCode != http.StatusOK {
		t.Fatalf("change-password: %d", cres.StatusCode)
	}
	rotated := findCookie(cres, "yauth_session")
	if rotated == nil || rotated.Value == "" {
		t.Fatalf("change-password: expected a re-issued session cookie")
	}

	// The attacker's pre-rotation refresh token is dead.
	assertRefreshRefused(t, srv, attackerRefresh)

	// ...and revoked in the store, not merely rejected at the edge.
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if n, err := r.RevokeAllUserRefreshTokens(context.Background(), u.ID); err != nil || n != 0 {
		t.Fatalf("expected no live refresh tokens left, revoked %d more (err %v)", n, err)
	}

	// Ordering check: the caller's re-issued session still authenticates.
	sreq, err := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/session", nil)
	if err != nil {
		t.Fatalf("new session req: %v", err)
	}
	sreq.AddCookie(rotated)
	sres, err := http.DefaultClient.Do(sreq)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	sres.Body.Close()
	if sres.StatusCode != http.StatusOK {
		t.Fatalf("re-issued session rejected: %d", sres.StatusCode)
	}
}

// TestResetPassword_RevokesRefreshTokens covers the unauthenticated recovery
// path: a reset is what a user who has LOST control of the account performs,
// so nothing minted before it may survive it.
func TestResetPassword_RevokesRefreshTokens(t *testing.T) {
	srv, r := newBearerServer(t)
	ctx := context.Background()

	const email = "bob@example.com"
	const password = "correct horse battery staple"
	const newPassword = "another correct horse staple"

	registerUser(t, srv, email, password)
	attackerRefresh := issueRefreshToken(t, srv, email, password)

	u, err := r.GetUserByEmail(ctx, email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}

	// Mint a reset token directly — the mail leg is not what is under test.
	const rawToken = "reset-token-known-to-the-test"
	if err := r.CreatePasswordReset(ctx, domain.NewPasswordReset{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		TokenHash: sha256hex(rawToken),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreatePasswordReset: %v", err)
	}

	res := postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": rawToken, "password": newPassword,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reset-password: %d", res.StatusCode)
	}

	assertRefreshRefused(t, srv, attackerRefresh)

	if n, err := r.RevokeAllUserRefreshTokens(ctx, u.ID); err != nil || n != 0 {
		t.Fatalf("expected no live refresh tokens left, revoked %d more (err %v)", n, err)
	}
}
