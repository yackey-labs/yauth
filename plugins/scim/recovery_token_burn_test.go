// recovery_token_burn_test.go — a SCIM rename retires the SESSIONS of the
// identity it repointed, and nothing else.
//
// #96 closed the takeover where an org-scoped SCIM key could repoint
// yauth_users.email at any address at all: handlePutUser / handlePatchUser now
// call requireVerifiedNamespace (plugins/scim/users.go:219) and a rename is
// only allowed into a domain the org has proven it controls. On a genuine
// rename both paths then call burnCredentials (users.go:275-279), which does
// exactly two things — DeleteUserSessions and RevokeAllUserRefreshTokens.
//
// It does NOT touch the credentials sitting in the OLD mailbox. Every one of
// these outlives the rename that was supposed to be the remediation:
//
//   - a password-reset token (yauth_password_resets, keyed by user id): the
//     holder POSTs /api/auth/reset-password and the handler consumes the row,
//     sets a password of their choosing, clears must_change_password and then
//     wipes every session and refresh token the real user has
//     (plugins/emailpassword/handlers.go:1446-1473). The remediation becomes
//     the victim's lockout.
//   - an email-verification token (keyed by user id, NOT by the address it was
//     mailed to): registerVerifyEmail consumes it and writes
//     EmailVerified:true against whatever the CURRENT email is
//     (handlers.go:1143-1148), so a contractor who kept the token from
//     contractor@corp.example ends up with staff@corp.example marked as an
//     address someone proved control of. auth.AutoJoinFromEmail then runs on
//     that bit, and ssooidc adoption trusts it.
//   - a magic link (keyed by EMAIL, so it stays bound to the old address) and
//     an unlock token (keyed by user id) — a live sign-in and a live lockout
//     clear.
//
// emailpassword already treats these four as one set: invalidateRecoveryTokens
// (handlers.go:1568) deletes resets, magic links and unlock tokens together
// whenever a password rotates. A rename of the login identity is the same
// event with a different trigger, and SCIM never learned it.
//
// The refusal cases below are paired with a positive control proving the
// routine IdP re-sync — a PUT that re-sends the SAME userName — still retires
// nothing, so the fix cannot be "delete recovery tokens on every SCIM write",
// which would silently kill the inbox link of every user on every sync.
package scim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// recoveryStash is the set of raw credentials a holder of the OLD mailbox
// would be sitting on at the moment the IdP renames the identity.
type recoveryStash struct {
	resetHash  string
	verifyHash string
	magicHash  string
	unlockHash string
}

func mintHash(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// seedRecoveryStash plants one live token of each recovery family. The magic
// link is keyed by the address, exactly as magiclink issues it, so it records
// the OLD mailbox.
func seedRecoveryStash(t *testing.T, app *testApp, userID, email string) recoveryStash {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	s := recoveryStash{
		resetHash:  mintHash(t),
		verifyHash: mintHash(t),
		magicHash:  mintHash(t),
		unlockHash: mintHash(t),
	}
	if err := app.repo.CreatePasswordReset(ctx, domain.NewPasswordReset{
		ID: uuid.NewString(), UserID: userID, TokenHash: s.resetHash, ExpiresAt: exp, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed password reset: %v", err)
	}
	if err := app.repo.CreateEmailVerification(ctx, domain.NewEmailVerification{
		ID: uuid.NewString(), UserID: userID, TokenHash: s.verifyHash, ExpiresAt: exp, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed email verification: %v", err)
	}
	if err := app.repo.CreateMagicLink(ctx, domain.NewMagicLink{
		ID: uuid.NewString(), Email: email, TokenHash: s.magicHash, ExpiresAt: exp, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed magic link: %v", err)
	}
	if err := app.repo.CreateUnlockToken(ctx, domain.NewUnlockToken{
		ID: uuid.NewString(), UserID: userID, TokenHash: s.unlockHash, ExpiresAt: exp, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed unlock token: %v", err)
	}
	return s
}

// assertRetired proves each credential no longer redeems. The two Consume*
// calls are how the real handlers reach these rows, so "Consume still returns
// a row" is precisely "the attacker's POST still works".
func (s recoveryStash) assertRetired(t *testing.T, app *testApp) {
	t.Helper()
	ctx := context.Background()

	if pr, err := app.repo.ConsumePasswordReset(ctx, s.resetHash); err == nil && pr != nil {
		t.Errorf("password-reset token minted for the OLD address still redeems after the rename (user %s) — "+
			"POST /reset-password sets a password of the holder's choosing and wipes every session the real user has",
			pr.UserID)
	}
	if ev, err := app.repo.ConsumeEmailVerification(ctx, s.verifyHash); err == nil && ev != nil {
		t.Errorf("email-verification token minted for the OLD address still redeems after the rename (user %s) — "+
			"it marks the CURRENT address verified, an address nobody proved control of", ev.UserID)
	}
	if ml, err := app.repo.GetUnusedMagicLinkByTokenHash(ctx, s.magicHash); err == nil && ml != nil {
		t.Errorf("magic link for %q survived the rename — it signs in as the renamed account outright", ml.Email)
	}
	if ut, err := app.repo.GetUnlockTokenByHash(ctx, s.unlockHash); err == nil && ut != nil {
		t.Errorf("unlock token survived the rename (user %s) — it clears the lockout that is the trace of the attack", ut.UserID)
	}
}

// assertStillLive is the positive-control mirror: nothing legitimate happened,
// so every link the user has in their inbox must still work.
func (s recoveryStash) assertStillLive(t *testing.T, app *testApp) {
	t.Helper()
	ctx := context.Background()

	if ml, err := app.repo.GetUnusedMagicLinkByTokenHash(ctx, s.magicHash); err != nil || ml == nil {
		t.Errorf("magic link was retired by a no-op profile sync (err=%v)", err)
	}
	if ut, err := app.repo.GetUnlockTokenByHash(ctx, s.unlockHash); err != nil || ut == nil {
		t.Errorf("unlock token was retired by a no-op profile sync (err=%v)", err)
	}
	// Consume last: it is destructive, and by here the test is over.
	if pr, err := app.repo.ConsumePasswordReset(ctx, s.resetHash); err != nil || pr == nil {
		t.Errorf("password-reset link was retired by a no-op profile sync — the user clicks it and it is dead (err=%v)", err)
	}
	if ev, err := app.repo.ConsumeEmailVerification(ctx, s.verifyHash); err != nil || ev == nil {
		t.Errorf("email-verification link was retired by a no-op profile sync (err=%v)", err)
	}
}

// TestPut_RenameUnderVerifiedDomain_RetiresRecoveryCredentials is exploit (a)
// and (b) on the PUT path: the IdP moves the login to a new address inside a
// domain the org has verified — the flow #96 deliberately still permits — and
// every credential minted against the OLD mailbox must die with it.
func TestPut_RenameUnderVerifiedDomain_RetiresRecoveryCredentials(t *testing.T) {
	app := newTestApp(t)
	const dom = "alpha-corp.example"
	const oldEmail = "contractor@alpha-corp.example"
	const newEmail = "staff@alpha-corp.example"

	seedVerifiedDomain(t, app, app.orgA.orgID, dom)
	user := seedGlobalUser(t, app, oldEmail, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	stash := seedRecoveryStash(t, app, user.ID, oldEmail)

	resp := app.do(t, "PUT", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": newEmail,
		"emails":   []map[string]any{{"value": newEmail, "primary": true}},
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200 — a rename under a VERIFIED domain is the flow SCIM exists to serve", resp.StatusCode)
	}
	if u := mustUser(t, app, user.ID); u.Email != newEmail {
		t.Fatalf("email: got %q want %q", u.Email, newEmail)
	}

	stash.assertRetired(t, app)
}

// TestPatch_RenameUnderVerifiedDomain_RetiresRecoveryCredentials is the same
// exploit through the PATCH path, which is the one a real IdP actually uses
// for a rename.
func TestPatch_RenameUnderVerifiedDomain_RetiresRecoveryCredentials(t *testing.T) {
	app := newTestApp(t)
	const dom = "alpha-corp.example"
	const oldEmail = "old.name@alpha-corp.example"
	const newEmail = "new.name@alpha-corp.example"

	seedVerifiedDomain(t, app, app.orgA.orgID, dom)
	user := seedGlobalUser(t, app, oldEmail, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	stash := seedRecoveryStash(t, app, user.ID, oldEmail)

	resp := app.do(t, "PATCH", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey, map[string]any{
		"schemas":    []string{PatchOpSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "userName", "value": newEmail}},
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if u := mustUser(t, app, user.ID); u.Email != newEmail {
		t.Fatalf("email: got %q want %q", u.Email, newEmail)
	}

	stash.assertRetired(t, app)
}

// POSITIVE CONTROL. The overwhelmingly common SCIM write re-sends the same
// userName. It is not a rename, and it must retire nothing: the reset link a
// user requested thirty seconds ago has to survive the sync that runs while
// they are reading their mail. This pins the EqualFold gate the fix must keep
// hanging its cleanup off.
func TestPut_RoutineProfileSync_LeavesRecoveryCredentialsAlone(t *testing.T) {
	app := newTestApp(t)
	const email = "steady@alpha-corp.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	stash := seedRecoveryStash(t, app, user.ID, email)

	resp := app.do(t, "PUT", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreUserSchema},
		"userName":    email,
		"emails":      []map[string]any{{"value": email, "primary": true}},
		"displayName": "Steady Eddie",
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	stash.assertStillLive(t, app)
}
