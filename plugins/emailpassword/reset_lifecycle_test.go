package emailpassword_test

// /reset-password consults the account lifecycle nowhere.
//
// registerLogin re-checks it on every leg — banned, suspended, staged, each
// with its own 403 (plugins/emailpassword/handlers.go:592-604). #111 pushed
// the same re-check through the bearer and refresh legs. registerResetPassword
// (handlers.go:1381) never got one: it consumes the token, compares history,
// hashes the new password and calls UpsertPassword, and the only thing it ever
// loads the user row for is the email it needs to invalidate magic links with
// (handlers.go:1483).
//
// So the kill switch is not a kill switch. An admin hits POST
// /admin/users/{id}/suspend — or SCIM sends active:false, which suspends
// globally (plugins/scim/users.go) — after which the account cannot log in,
// cannot mint a token and cannot pass auth resolution. Anyone holding a
// password-reset link minted BEFORE that moment can still POST it, and yauth
// will happily write a new credential for the offboarded account, clear
// must_change_password, and wipe every session and refresh token the org still
// had on the user (handlers.go:1457-1473). The password that lands is chosen
// by whoever held the link. If the suspension is ever lifted — reinstated
// contractor, mistaken offboarding reversed — that password is live.
//
// The refusals below are paired with two positive controls. An ordinary active
// account must still reset, obviously. And a STAGED account (ActivatesAt in
// the future) must still reset, because invite-then-set-your-password is a
// real provisioning flow: the invite mail carries a reset link and the user
// clicks it before their start date. Folding staged in with banned/suspended
// would break that, which is why the gate must name the two states it means.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// plantResetToken mints a live password-reset row for the user and returns the
// raw token, the way /forgot-password would have mailed it.
func plantResetToken(t *testing.T, r repo.Repository, userID string) string {
	t.Helper()
	raw, hash := mintRawToken(t)
	now := time.Now().UTC()
	if err := r.CreatePasswordReset(context.Background(), domain.NewPasswordReset{
		ID: uuid.NewString(), UserID: userID, TokenHash: hash,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("plant password reset: %v", err)
	}
	return raw
}

func currentPasswordHash(t *testing.T, r repo.Repository, userID string) string {
	t.Helper()
	p, err := r.GetPasswordByUserID(context.Background(), userID)
	if err != nil || p == nil {
		t.Fatalf("load password for %s: %v", userID, err)
	}
	return p.PasswordHash
}

// setLifecycle applies a lifecycle state to the user row the way the admin API
// and SCIM both ultimately do — through repo.UpdateUser.
func setLifecycle(t *testing.T, r repo.Repository, userID string, up domain.UpdateUser) {
	t.Helper()
	now := time.Now().UTC()
	up.UpdatedAt = &now
	if _, err := r.UpdateUser(context.Background(), userID, up); err != nil {
		t.Fatalf("update lifecycle for %s: %v", userID, err)
	}
}

// TestResetPassword_RefusedForSuspendedAccount is the offboarding case: the
// account has been globally deactivated and a link minted before that must not
// be able to write a new credential onto it.
func TestResetPassword_RefusedForSuspendedAccount(t *testing.T) {
	srv, r := newRecoveryServer(t)
	const email, pw = "offboarded@example.com", "old-password-123"

	registerUser(t, srv, email, pw)
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("lookup user: %v", err)
	}
	token := plantResetToken(t, r, u.ID)
	before := currentPasswordHash(t, r, u.ID)

	// The kill switch.
	now := time.Now().UTC()
	nowPtr := &now
	reason := "offboarded"
	reasonPtr := &reason
	setLifecycle(t, r, u.ID, domain.UpdateUser{SuspendedAt: &nowPtr, SuspendedReason: &reasonPtr})

	res := postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": token, "password": "chosen-by-the-holder-1",
	})
	body := drain(res)

	// The thing that matters is the persisted credential, not the status code.
	if after := currentPasswordHash(t, r, u.ID); after != before {
		t.Errorf("a reset link minted before the suspension REWROTE the password of a deactivated account "+
			"(HTTP %d: %s) — the account's credential is now whoever held the link", res.StatusCode, body)
	}
	if res.StatusCode == http.StatusOK {
		t.Errorf("reset-password answered 200 for a suspended account: %s", body)
	}
}

// TestResetPassword_RefusedForBannedAccount is the security-incident case. A
// ban is the response to a compromise; letting the link that may itself be
// part of that compromise set a fresh password is exactly backwards.
func TestResetPassword_RefusedForBannedAccount(t *testing.T) {
	srv, r := newRecoveryServer(t)
	const email, pw = "banned@example.com", "old-password-123"

	registerUser(t, srv, email, pw)
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("lookup user: %v", err)
	}
	token := plantResetToken(t, r, u.ID)
	before := currentPasswordHash(t, r, u.ID)

	banned := true
	setLifecycle(t, r, u.ID, domain.UpdateUser{Banned: &banned})

	res := postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": token, "password": "chosen-by-the-holder-1",
	})
	body := drain(res)

	if after := currentPasswordHash(t, r, u.ID); after != before {
		t.Errorf("a reset link REWROTE the password of a BANNED account (HTTP %d: %s)", res.StatusCode, body)
	}
	if res.StatusCode == http.StatusOK {
		t.Errorf("reset-password answered 200 for a banned account: %s", body)
	}
}

// POSITIVE CONTROL. The ordinary case — a live account clicking the link in
// its inbox — must keep working, credential and all.
func TestResetPassword_AllowedForActiveAccount(t *testing.T) {
	srv, r := newRecoveryServer(t)
	const email, pw = "ordinary@example.com", "old-password-123"

	registerUser(t, srv, email, pw)
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("lookup user: %v", err)
	}
	token := plantResetToken(t, r, u.ID)
	before := currentPasswordHash(t, r, u.ID)

	res := postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": token, "password": "chosen-by-the-owner-1",
	})
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("reset-password on a live account: %d (%s)", res.StatusCode, body)
	}
	if after := currentPasswordHash(t, r, u.ID); after == before {
		t.Fatalf("reset answered 200 but the stored password never changed")
	}
}

// POSITIVE CONTROL, and the deliberate exemption. A staged account — invited,
// start date in the future — cannot log in yet (registerLogin 403s it), but
// the invite mail's reset link is precisely how it sets its first password.
// The lifecycle gate must name banned and suspended, not "anything
// CanAuthenticate refuses".
func TestResetPassword_AllowedForStagedAccount(t *testing.T) {
	srv, r := newRecoveryServer(t)
	const email, pw = "starts-monday@example.com", "old-password-123"

	registerUser(t, srv, email, pw)
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("lookup user: %v", err)
	}
	token := plantResetToken(t, r, u.ID)
	before := currentPasswordHash(t, r, u.ID)

	future := time.Now().UTC().Add(72 * time.Hour)
	futurePtr := &future
	setLifecycle(t, r, u.ID, domain.UpdateUser{ActivatesAt: &futurePtr})
	if got := mustLoadUser(t, r, u.ID); !got.Staged(time.Now().UTC()) {
		t.Fatalf("fixture is not staged: activates_at=%v", got.ActivatesAt)
	}

	res := postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": token, "password": "first-password-ever-1",
	})
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("reset-password for a STAGED (invited, not yet started) account: %d (%s) — "+
			"invite-then-set-password is a real provisioning flow", res.StatusCode, body)
	}
	if after := currentPasswordHash(t, r, u.ID); after == before {
		t.Fatalf("staged reset answered 200 but stored no password")
	}
}

func mustLoadUser(t *testing.T, r repo.Repository, id string) *domain.User {
	t.Helper()
	u, err := r.GetUserByID(context.Background(), id)
	if err != nil || u == nil {
		t.Fatalf("get user %s: %v", id, err)
	}
	return u
}
