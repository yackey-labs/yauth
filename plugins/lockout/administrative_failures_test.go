// Who is allowed to move the account-lockout counter.
//
// lockout's loginEventHandler.onFailed increments the failure counter for ANY
// login.failed that resolves to a user, and plugins/emailpassword's /login
// handler emits login.failed for outcomes that have nothing to do with a
// presented credential: "banned", "suspended", "staged", "no-password" and
// "email-unverified" all run p.emitLoginFailed before the password is ever
// compared (handlers.go around the GetUserByEmail / GetPasswordByUserID
// branches).
//
// Two consequences, both reachable UNAUTHENTICATED and against a NAMED victim:
//
//   - An account provisioned by SCIM / SSO / passkey / magic-link has no
//     yauth_passwords row, so every /login for it falls into the
//     GetPasswordByUserID ErrNotFound branch and counts. Five requests with a
//     junk password lock the account, and the lock is keyed on the USER, not on
//     the password path: plugin.RunFederatedLogin and passkey's completeLogin
//     both emit login.attempt, which lockout answers with a Block. The victim
//     has no password, so /forgot-password is not a way back either.
//   - A suspended (or banned, or staged) account is refused by the lifecycle
//     gate — correctly — but the refusal is booked as a failed credential.
//     Lifting the suspension therefore does not restore the account: the
//     counter an attacker (or the user's own retries) ran up while it was
//     deactivated has locked it.
//
// The library already states the invariant these tests encode, in
// plugin/plugin.go's RunFederatedLogin: a lifecycle refusal emits nothing
// precisely so administrative states "must not feed lockout counters".
//
// Assertions are on the lock ROW and on the login.attempt Decision rather than
// on status codes, because /login also carries a per-IP limiter that answers
// 429 of its own — only the stored lock proves the ACCOUNT was locked.
package lockout_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yautherr"
)

// newAdminStateServer builds email-password + lockout over memrepo and hands
// back the repo (to inspect the lock row) and the yauth instance (to ask the
// event pipeline what a fresh login.attempt would be answered with, which is
// what every non-password login path — federated, passkey, magic-link — does
// before it issues anything).
//
// The per-IP /login limiter is switched OFF here on purpose. It is not the
// control under test, and leaving it on would let its own 429 stand in for the
// account lock and hide which of the two actually fired.
func newAdminStateServer(t *testing.T, cfg lockout.Config) (*httptest.Server, repo.Repository, *yauth.YAuth) {
	t.Helper()
	r := memrepo.New()
	cfg.Mailer = &captureMailer{}
	if cfg.LinkBaseURL == "" {
		cfg.LinkBaseURL = "https://example.test/unlock"
	}

	yc := yauth.NewDefaultConfig()
	yc.RateLimit.Login = yauth.RateLimitRule{Max: yauth.RateLimitMax(0)}

	ya, err := yauth.New(r, yc).
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
	t.Cleanup(srv.Close)
	return srv, r, ya
}

// activeLock reports whether userID currently has a lock the gate would block
// on. A missing lock row and a row whose locked_until is nil both mean "not
// locked".
func activeLock(t *testing.T, r repo.Repository, userID string) (*domain.AccountLock, bool) {
	t.Helper()
	lock, err := r.GetAccountLockByUserID(context.Background(), userID)
	if errors.Is(err, yautherr.ErrNotFound) || lock == nil {
		return nil, false
	}
	if err != nil {
		t.Fatalf("GetAccountLockByUserID: %v", err)
	}
	if lock.LockedUntil == nil || !lock.LockedUntil.UTC().After(time.Now().UTC()) {
		return lock, false
	}
	return lock, true
}

// wouldBlockLogin asks the pipeline what a login.attempt for email is answered
// with — the question every login path puts before it issues anything.
func wouldBlockLogin(t *testing.T, ya *yauth.YAuth, email string) bool {
	t.Helper()
	em := email
	dec, err := ya.Emit(context.Background(), events.AuthEvent{
		Type:      events.EventLoginAttempt,
		Email:     &em,
		Timestamp: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Emit login.attempt: %v", err)
	}
	return dec.Kind == events.DecisionKindBlock
}

// TestLockout_PasswordlessAccountCannotBeLockedOut is the unauthenticated
// denial-of-service: bob was provisioned by SSO and has no password at all, so
// nobody can present a wrong one — yet ten /login calls with a junk password
// lock him out of every login path he DOES have.
func TestLockout_PasswordlessAccountCannotBeLockedOut(t *testing.T) {
	const email = "bob@corp.com"

	srv, r, ya := newAdminStateServer(t, lockout.Config{
		MaxAttempts:      5,
		LockoutDurations: []time.Duration{time.Hour},
	})

	ctx := context.Background()
	now := time.Now().UTC()
	user, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// No yauth_passwords row is written: this is exactly how SCIM, SSO,
	// passkey and magic-link provision a user.

	// Statuses are collected rather than asserted: what the spray is answered
	// with is not the point (and turns into the lock's own 429 the moment the
	// bug bites). The lock row is the point.
	codes := make([]int, 0, 10)
	for i := range 10 {
		codes = append(codes, attempt(t, srv, email, "not-his-password", clientAddr(i)))
	}

	if lock, locked := activeLock(t, r, user.ID); locked {
		t.Fatalf("a passwordless account was locked by 10 password guesses it has no password to fail: locked_until=%v failed_count=%d (responses %v) — an unauthenticated attacker can take out any named SSO user",
			lock.LockedUntil, lock.FailedCount, codes)
	}
	if wouldBlockLogin(t, ya, email) {
		t.Fatalf("login.attempt for a passwordless account is Blocked — every federated / passkey / magic-link login for %s now fails, and there is no password to reset", email)
	}
}

// TestLockout_SuspendedStateDoesNotFeedTheLockCounter is the mirror image: the
// lifecycle gate refuses a deactivated account before any credential is
// checked, and that refusal must not be booked as a failed credential. If it
// is, un-suspending the user does not give them their account back.
func TestLockout_SuspendedStateDoesNotFeedTheLockCounter(t *testing.T) {
	const (
		email = "carol@example.com"
		pw    = "correct horse battery staple"
	)

	srv, r, _ := newAdminStateServer(t, lockout.Config{
		MaxAttempts:      5,
		LockoutDurations: []time.Duration{time.Hour},
	})

	c := &http.Client{}
	register(t, srv, c, email, pw)

	ctx := context.Background()
	user, err := r.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}

	now := time.Now().UTC()
	susp := &now
	if _, err := r.UpdateUser(ctx, user.ID, domain.UpdateUser{SuspendedAt: &susp, UpdatedAt: &now}); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	// Carol (or an attacker who knows she exists) keeps trying while the
	// account is deactivated. Every one of these is refused by the lifecycle
	// gate, with the CORRECT password.
	codes := make([]int, 0, 10)
	for i := range 10 {
		codes = append(codes, attempt(t, srv, email, pw, clientAddr(i)))
	}
	if codes[0] != http.StatusForbidden {
		t.Fatalf("first attempt against a suspended account: got %d, want the lifecycle 403", codes[0])
	}

	if lock, locked := activeLock(t, r, user.ID); locked {
		t.Fatalf("a suspended account was locked out by the suspension refusals themselves: locked_until=%v failed_count=%d (responses %v)", lock.LockedUntil, lock.FailedCount, codes)
	}

	// The admin reinstates her. She must be able to sign in again.
	var none *time.Time
	now = time.Now().UTC()
	if _, err := r.UpdateUser(ctx, user.ID, domain.UpdateUser{SuspendedAt: &none, UpdatedAt: &now}); err != nil {
		t.Fatalf("unsuspend: %v", err)
	}
	if code := attempt(t, srv, email, pw, clientAddr(200)); code != http.StatusOK {
		t.Fatalf("after reinstatement the correct password got %d, want 200 — the suspension refusals had locked the account", code)
	}
}

// TestLockout_BadPasswordStillLocks is the POSITIVE CONTROL. Ignoring
// administrative outcomes must not turn the lockout off: a real credential
// failure — a wrong password against an account that HAS one — still counts,
// still locks at the threshold, and still stops the correct password.
func TestLockout_BadPasswordStillLocks(t *testing.T) {
	const (
		email = "dave@example.com"
		pw    = "correct horse battery staple"
	)

	srv, r, ya := newAdminStateServer(t, lockout.Config{
		MaxAttempts:      5,
		LockoutDurations: []time.Duration{time.Hour},
	})

	c := &http.Client{}
	register(t, srv, c, email, pw)

	user, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || user == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}

	for i := range 5 {
		if code := attempt(t, srv, email, "wrong-password", clientAddr(i)); code != http.StatusUnauthorized {
			t.Fatalf("guess #%d: got %d, want 401", i+1, code)
		}
	}

	if _, locked := activeLock(t, r, user.ID); !locked {
		t.Fatalf("five wrong passwords did not lock the account — the lockout has been broken outright")
	}
	if !wouldBlockLogin(t, ya, email) {
		t.Fatalf("login.attempt for a locked account was not Blocked")
	}
	if code := attempt(t, srv, email, pw, clientAddr(200)); code != http.StatusTooManyRequests {
		t.Fatalf("the correct password got %d during a lockout, want 429", code)
	}
}
