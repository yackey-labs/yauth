// A banked MFA challenge completes a login for a LOCKED account on the native
// path, and clears the lock on the way out.
//
// The counter never moves when /token hands back a step-up: the MFA gate
// answers login.succeeded with RequireMfa, which short-circuits Emit before any
// failure is recorded, and no failure happened anyway — the password was
// right. So an attacker who holds the password can collect
// pending_session_ids first and pay nothing for them.
//
// Afterwards the account gets locked (by their own guessing, or by anyone
// spraying the address). lockout refuses logins on events.EventLoginAttempt
// only — handler.go onAttempt — and bearer's registerTokenMFA emits no
// login.attempt at all: it goes verifier.VerifyPendingChallenge → the
// ban/suspend/staged/must-change gates → mint. None of those consults the lock.
// The marked login.succeeded it finishes with then reaches lockout's
// onSucceeded, which resets failed_count and calls AutoUnlockAccount.
//
// So the banked challenge yields a full access+refresh pair for an account
// that /token itself is refusing with 429, and the lock is gone afterwards.
// /mfa/verify has the identical shape on the cookie path (see
// plugins/mfa/account_lock_test.go).
//
// This drives the REAL stack (memrepo + email-password + mfa + lockout +
// bearer) through the newStack builder in integration_test.go, because the
// defect is precisely which events cross plugin boundaries — a stub handler
// could not show it.
package bearer_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/yackey-labs/yauth/plugins/lockout"
)

// lockedStack is the stack these tests share: mfa + lockout in the
// NewFromConfig registration order, locking after two failures for an hour.
func lockedStack(t *testing.T) (*stack, func()) {
	t.Helper()
	return newStack(t, stackOpts{mfa: true, lockoutFirst: true, lockout: &lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{time.Hour},
	}})
}

// TestTokenMFA_HonoursAccountLock banks a challenge, gets the account locked,
// then spends the challenge.
func TestTokenMFA_HonoursAccountLock(t *testing.T) {
	s, stop := lockedStack(t)
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	// Banked while the account is healthy. The correct password moves no
	// counter, and the step-up costs the attacker nothing.
	pending := s.bearerStepUp(t)

	// Now the account is locked — by this attacker's own spray, or by anyone
	// who knows the address.
	s.failPassword(t, "/api/auth/token")
	s.failPassword(t, "/api/auth/token")

	res := s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("precondition: /token with the correct password got %d, want 429 (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Spend the banked challenge.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	res = s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": pending, "code": code,
	})
	status := res.StatusCode
	pair := decode(t, res)

	if pair.AccessToken != "" || pair.RefreshToken != "" {
		t.Fatalf("a LOCKED account was minted a token pair by /token/mfa (access_token=%d bytes, refresh_token=%d bytes) — the banked challenge walked past the lock that /token itself is enforcing",
			len(pair.AccessToken), len(pair.RefreshToken))
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("/token/mfa on a locked account got %d, want 429", status)
	}

	// And the lock must survive: completing the challenge must not be the
	// attacker's own unlock button.
	res = s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after the MFA exchange the lock was gone: /token got %d, want 429 — lockout.onSucceeded cleared the counter for a login it should never have seen (%s)",
			res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestTokenMFA_UnlockedAccountStillGetsTokens is the POSITIVE CONTROL: with
// lockout in the stack and no lock standing, the native stepped-up login must
// still end in a usable token pair.
func TestTokenMFA_UnlockedAccountStillGetsTokens(t *testing.T) {
	s, stop := lockedStack(t)
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	pending := s.bearerStepUp(t)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	res := s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": pending, "code": code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an unlocked account must still complete its MFA login: %d (%s)", res.StatusCode, drain(res))
	}
	pair := decode(t, res)
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.TokenType != "Bearer" {
		t.Fatalf("expected a full token pair, got %+v", pair)
	}
}
