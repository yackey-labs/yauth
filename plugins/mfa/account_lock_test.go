// The account lock does not reach the second factor.
//
// Three separate holes, all on the MFA legs of a login:
//
//  1. UNTHROTTLED. mfaPlugin.Routes builds authMw as exactly
//     {RequireAuthHuma, RequireUserPrincipalHuma}. Only POST /mfa/verify is
//     wrapped in middleware.RateLimitHuma; the management routes — DELETE
//     /mfa/totp, POST /mfa/totp/setup, POST /mfa/backup-codes/regenerate — carry
//     no limiter at all. requireStepUp answers a wrong X-MFA-Code with a flat
//     403 and DISCARDS the events.Decision emitMFAFailed hands back, so nothing
//     in the loop can ever return a 429. Anyone holding a session (a stolen
//     cookie, an XSS payload) can walk 000000..999999 against a six-digit
//     secret; validateTOTPStep accepts three of those million per window.
//
//  2. LOCK-BLIND. lockout only refuses on events.EventLoginAttempt
//     (handler.go onAttempt); login.failed merely increments the counter. None
//     of the MFA paths emits login.attempt, so once the guessing has locked the
//     victim out of /login, the attacker's loop carries on answering 403 while
//     the owner's own logins answer 429 — the step-up route becomes a way to
//     hold someone out of their account for free.
//
//  3. BANKABLE. /login short-circuits into {require_mfa, pending_session_id}
//     without touching the counter, so an attacker who knows the password can
//     collect pending sessions first, get the account locked afterwards, and
//     then spend a banked challenge at /mfa/verify. That handler never asks
//     login.attempt, so it mints a session for a locked account — and the
//     login.succeeded it emits runs lockout's onSucceeded, which CLEARS the
//     lock.
//
// Each refusal test here is paired with the same flow on an unlocked account,
// so a fix cannot pass by making MFA management or MFA login fail outright.
package mfa_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newLockoutEnv is newTestEnvWithRepo plus the lockout plugin, registered
// BEFORE mfa — the order yauth.NewFromConfig uses. Without lockout in the
// stack there is no account lock to honour, and these tests are about what the
// MFA routes do when one exists.
func newLockoutEnv(t *testing.T) (*testEnv, repo.Repository) {
	t.Helper()
	r := memrepo.New()

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: "yauth-test"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{HIBPCheck: false, HIBPCheckSet: true})).
		WithPlugin(lockout.New(lockout.Config{
			MaxAttempts:      5,
			LockoutDurations: []time.Duration{time.Hour},
			LinkBaseURL:      "https://example.test/unlock",
		})).
		WithPlugin(mfaPlugin).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	return &testEnv{srv: srv, cl: &http.Client{Jar: jar}}, r
}

// lockAccount writes the same lock row the lockout plugin writes when the
// failure threshold is crossed: locked_until an hour out, lock_count 1.
func lockAccount(t *testing.T, r repo.Repository, userID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	created, err := r.CreateAccountLock(ctx, domain.NewAccountLock{
		ID:          uuid.NewString(),
		UserID:      userID,
		FailedCount: 5,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("CreateAccountLock: %v", err)
	}
	until := now.Add(time.Hour)
	reason := "too many failed login attempts"
	if err := r.SetAccountLockState(ctx, created.ID, domain.LockState{
		LockedUntil:  &until,
		LockedReason: &reason,
		LockCount:    1,
	}, now); err != nil {
		t.Fatalf("SetAccountLockState: %v", err)
	}
}

func userID(t *testing.T, r repo.Repository) string {
	t.Helper()
	u, err := r.GetUserByEmail(context.Background(), testEmail)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	return u.ID
}

// stillLocked reports whether the account lock is intact.
func stillLocked(t *testing.T, r repo.Repository, uid string) bool {
	t.Helper()
	lock, err := r.GetAccountLockByUserID(context.Background(), uid)
	if err != nil || lock == nil {
		return false
	}
	return lock.LockedUntil != nil && lock.LockedUntil.UTC().After(time.Now().UTC())
}

// assertLoginRefused proves the seeded lock is real on the path that DOES
// honour it, so a failure below cannot be blamed on a lock that was never
// applied.
func assertLoginRefused(t *testing.T, cl *http.Client, url string) {
	t.Helper()
	res := postJSONWith(t, cl, url+"/api/auth/login", map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("precondition: /login on the locked account got %d, want 429 (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestStepUp_IsRateLimited: the MFA management routes are an unmetered oracle
// for a six-digit secret. Twenty consecutive wrong codes, and not one of them
// is throttled.
func TestStepUp_IsRateLimited(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	env.setupAndConfirmMFA(t)

	const guesses = 20
	codes := make([]int, 0, guesses)
	throttledAt := -1
	for i := range guesses {
		res := env.deleteStepUp(t, "/api/auth/mfa/totp", "000000")
		codes = append(codes, res.StatusCode)
		res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests && throttledAt < 0 {
			throttledAt = i
		}
	}

	// The shared mfa_verify bucket defaults to 10 per minute, so the 11th
	// guess is the first that must be refused.
	if throttledAt < 0 || throttledAt > 10 {
		t.Fatalf("%d wrong X-MFA-Code guesses against DELETE /mfa/totp were never throttled (statuses %v) — a stolen session can enumerate the second factor at full speed",
			guesses, codes)
	}
}

// TestStepUp_LegitimateChangeStillWorks is the POSITIVE CONTROL for the
// limiter: one honest code must still remove the factor.
func TestStepUp_LegitimateChangeStillWorks(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)

	res := env.deleteStepUp(t, "/api/auth/mfa/totp", currentStepCode(t, secret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a correct step-up code must still disable TOTP: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestStepUp_HonoursAccountLock: with the account already locked, the guessing
// loop must be stopped by the lock, not answered with the same 403 it was
// getting before. Today requireStepUp never asks whether the account may
// authenticate at all, so the attacker keeps guessing while the owner is shut
// out of /login.
func TestStepUp_HonoursAccountLock(t *testing.T) {
	env, r := newLockoutEnv(t)

	env.register(t)
	env.setupAndConfirmMFA(t)
	uid := userID(t, r)
	lockAccount(t, r, uid)

	assertLoginRefused(t, env.cl, env.srv.URL)

	res := env.deleteStepUp(t, "/api/auth/mfa/totp", "000000")
	got := res.StatusCode
	body := drain(res)
	if got != http.StatusTooManyRequests {
		t.Fatalf("DELETE /mfa/totp with a wrong code on a LOCKED account got %d (%s), want 429 — the lock does not reach the step-up route, so the guessing loop outlives the lock it caused",
			got, body)
	}
}

// TestStepUp_UnlockedAccountIsNotBlocked is the POSITIVE CONTROL for the lock
// check: with lockout loaded but no lock standing, MFA management is
// unaffected — a wrong code is the ordinary 403 and a right one still works.
func TestStepUp_UnlockedAccountIsNotBlocked(t *testing.T) {
	env, _ := newLockoutEnv(t)

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)

	res := env.deleteStepUp(t, "/api/auth/mfa/totp", "000000")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong code on an UNLOCKED account: got %d, want the ordinary 403 (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	res = env.deleteStepUp(t, "/api/auth/mfa/totp", currentStepCode(t, secret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an unlocked account must still be able to disable TOTP: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestMFAVerify_HonoursAccountLock is the banked-challenge bypass. The pending
// session is opened BEFORE the lock — /login hands it out without moving the
// counter — and spent AFTER. /mfa/verify never asks login.attempt, so it
// completes the login for a locked account, sets the cookie, and then clears
// the lock on its way out.
func TestMFAVerify_HonoursAccountLock(t *testing.T) {
	env, r := newLockoutEnv(t)

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)
	env.logout(t)
	uid := userID(t, r)

	// Bank a challenge while the account is still healthy.
	cl := env.noCookieClient(t)
	pending := env.loginExpectMFAWith(t, cl)

	lockAccount(t, r, uid)
	assertLoginRefused(t, cl, env.srv.URL)

	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pending,
		"code":               currentStepCode(t, secret),
	})
	status := res.StatusCode
	setCookie := res.Header.Get("Set-Cookie")
	body := drain(res)

	if setCookie != "" {
		t.Fatalf("a locked account was issued a session cookie by /mfa/verify (%q) — the banked pending session walked straight past the lock", setCookie)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("/mfa/verify on a locked account got %d (%s), want 429", status, body)
	}
	if !stillLocked(t, r, uid) {
		t.Fatalf("completing the banked challenge CLEARED the lock (lockout.onSucceeded ran) — the attacker not only got in, they reset the counter")
	}
}

// TestMFAVerify_UnlockedAccountStillCompletes is the POSITIVE CONTROL: with
// lockout in the stack and no lock standing, a correct code must still finish
// the login and set the session cookie.
func TestMFAVerify_UnlockedAccountStillCompletes(t *testing.T) {
	env, _ := newLockoutEnv(t)

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)
	env.logout(t)

	cl := env.noCookieClient(t)
	pending := env.loginExpectMFAWith(t, cl)

	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pending,
		"code":               currentStepCode(t, secret),
	})
	status := res.StatusCode
	setCookie := res.Header.Get("Set-Cookie")
	body := drain(res)
	if status != http.StatusOK {
		t.Fatalf("an unlocked account must still complete its MFA login: %d (%s)", status, body)
	}
	if setCookie == "" {
		t.Fatalf("a completed MFA login issued no session cookie")
	}
}
