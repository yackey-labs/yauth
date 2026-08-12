package emailpassword_test

// Rotating a password must also retire the recovery credentials sitting in the
// user's inbox. #81 made change-password and reset-password delete sessions and
// revoke refresh tokens; neither touched the outstanding password-reset links,
// magic links or unlock tokens, each of which authenticates on its own without
// the new password. A leaked reset link outlived the rotation meant to close it.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/plugins/magiclink"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newRecoveryServer wires email-password alongside magic-link and lockout, so
// all three recovery-token families exist against one repo and can be redeemed
// over real HTTP.
func newRecoveryServer(t *testing.T) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.SessionTTL = time.Hour

	ya, err := yauth.New(r, cfg).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
		})).
		WithPlugin(magiclink.New(magiclink.Config{})).
		WithPlugin(lockout.New(lockout.Config{})).
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

// mintRawToken returns (raw, sha256hex) the same way every plugin's token
// issuer does. Writing the rows directly rather than driving /forgot-password
// keeps the test independent of the mailer wiring — the row and its hash are
// byte-identical either way, and the tokens are still REDEEMED over HTTP.
func mintRawToken(t *testing.T) (string, string) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	raw := hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

// plantRecoveryTokens creates one live token of each family for the user and
// returns the raw values an attacker would be holding.
func plantRecoveryTokens(t *testing.T, r repo.Repository, userID, email string) (reset, magic, unlock string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	rawReset, hashReset := mintRawToken(t)
	if err := r.CreatePasswordReset(ctx, domain.NewPasswordReset{
		ID: uuid.NewString(), UserID: userID, TokenHash: hashReset, ExpiresAt: exp, CreatedAt: now,
	}); err != nil {
		t.Fatalf("plant password reset: %v", err)
	}
	rawMagic, hashMagic := mintRawToken(t)
	if err := r.CreateMagicLink(ctx, domain.NewMagicLink{
		ID: uuid.NewString(), Email: email, TokenHash: hashMagic, ExpiresAt: exp, CreatedAt: now,
	}); err != nil {
		t.Fatalf("plant magic link: %v", err)
	}
	rawUnlock, hashUnlock := mintRawToken(t)
	if err := r.CreateUnlockToken(ctx, domain.NewUnlockToken{
		ID: uuid.NewString(), UserID: userID, TokenHash: hashUnlock, ExpiresAt: exp, CreatedAt: now,
	}); err != nil {
		t.Fatalf("plant unlock token: %v", err)
	}
	return rawReset, rawMagic, rawUnlock
}

// assertRecoveryTokensDead redeems all three over HTTP and requires each to be
// refused, and — for the two that mint credentials — that nothing came back.
func assertRecoveryTokensDead(t *testing.T, srv *httptest.Server, reset, magic, unlock string) {
	t.Helper()

	// A live reset link SETS A NEW PASSWORD. This is the one that matters most.
	res := postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": reset, "password": "attacker-chosen-pw-1",
	})
	body := drain(res)
	if res.StatusCode == http.StatusOK {
		t.Errorf("outstanding password-reset link still set a new password after rotation (200: %s)", body)
	}

	// A live magic link SIGNS IN.
	res = postJSON(t, srv.URL+"/api/auth/magic-link/verify", map[string]any{"token": magic})
	body = drain(res)
	if res.StatusCode == http.StatusOK {
		t.Errorf("outstanding magic link still signed in after rotation (200: %s)", body)
	}
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Errorf("refused magic link still set a session cookie")
		}
	}

	// A live unlock token CLEARS A LOCKOUT — the trace of the attack in
	// progress.
	res = postJSON(t, srv.URL+"/api/auth/account/unlock", map[string]any{"token": unlock})
	body = drain(res)
	if res.StatusCode == http.StatusOK {
		t.Errorf("outstanding unlock token still cleared the lock after rotation (200: %s)", body)
	}
}

func drain(res *http.Response) string {
	defer res.Body.Close() //nolint:errcheck
	var sb strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := res.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}

// TestChangePassword_InvalidatesOutstandingRecoveryTokens is the authenticated
// rotation: the user changes their password and every recovery credential
// already in flight has to die with it.
func TestChangePassword_InvalidatesOutstandingRecoveryTokens(t *testing.T) {
	srv, r := newRecoveryServer(t)
	const email, oldPW, newPW = "victim@example.com", "old-password-123", "new-password-456"

	registerUser(t, srv, email, oldPW)
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("lookup user: %v", err)
	}
	reset, magic, unlock := plantRecoveryTokens(t, r, u.ID, email)

	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar}
	login(t, cl, srv, email, oldPW)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/change-password",
		strings.NewReader(`{"current_password":"`+oldPW+`","new_password":"`+newPW+`"}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("change-password: %d (%s)", res.StatusCode, body)
	}

	assertRecoveryTokensDead(t, srv, reset, magic, unlock)
}

// TestResetPassword_InvalidatesOtherOutstandingRecoveryTokens is the
// unauthenticated recovery path. ConsumePasswordReset burns the link that was
// used; a SECOND reset link from an earlier /forgot-password, plus any magic
// link and unlock token, all survived it.
func TestResetPassword_InvalidatesOtherOutstandingRecoveryTokens(t *testing.T) {
	srv, r := newRecoveryServer(t)
	const email, oldPW = "victim2@example.com", "old-password-123"

	registerUser(t, srv, email, oldPW)
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("lookup user: %v", err)
	}
	// The attacker's stash...
	reset, magic, unlock := plantRecoveryTokens(t, r, u.ID, email)
	// ...and the link the real user is about to click.
	rawUsed, hashUsed := mintRawToken(t)
	if err := r.CreatePasswordReset(context.Background(), domain.NewPasswordReset{
		ID: uuid.NewString(), UserID: u.ID, TokenHash: hashUsed,
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("plant used reset: %v", err)
	}

	res := postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": rawUsed, "password": "chosen-by-the-owner-1",
	})
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("reset-password: %d (%s)", res.StatusCode, body)
	}

	assertRecoveryTokensDead(t, srv, reset, magic, unlock)
}

// TestForgotPassword_RetiresPriorResetLinks pins the second half of the
// finding: /forgot-password minted a token per call and invalidated none, so a
// link captured once kept working no matter how many fresh ones the real user
// requested. At most one reset link may be live per account.
func TestForgotPassword_RetiresPriorResetLinks(t *testing.T) {
	srv, r := newRecoveryServer(t)
	const email, pw = "victim3@example.com", "old-password-123"
	registerUser(t, srv, email, pw)
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("lookup user: %v", err)
	}

	// The captured link.
	stolen, hashStolen := mintRawToken(t)
	if err := r.CreatePasswordReset(context.Background(), domain.NewPasswordReset{
		ID: uuid.NewString(), UserID: u.ID, TokenHash: hashStolen,
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("plant stolen reset: %v", err)
	}

	// The user asks for a new one.
	res := postJSON(t, srv.URL+"/api/auth/forgot-password", map[string]any{"email": email})
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password: %d (%s)", res.StatusCode, body)
	}

	res = postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": stolen, "password": "attacker-chosen-pw-1",
	})
	if body := drain(res); res.StatusCode == http.StatusOK {
		t.Fatalf("a prior reset link survived a fresh /forgot-password (200: %s)", body)
	}
}

// login signs in with the cookie flow and fails the test if it does not stick.
func login(t *testing.T, cl *http.Client, srv *httptest.Server, email, password string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"email": email, "password": password})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/login", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d (%s)", res.StatusCode, body)
	}
}
