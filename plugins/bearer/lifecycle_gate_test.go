package bearer

// The three credential legs of this plugin disagree about what "may this
// account authenticate" means, and only one of them asks the whole question.
//
// domain.User.CanAuthenticate is the library-wide invariant: not banned, not
// suspended (offboarded), past any scheduled start. /token/mfa applies it in
// full (handlers.go, the second-factor leg). registerToken checks user.Banned
// and nothing else, and registerRefresh checks user.Banned and nothing else.
// So:
//
//   - An offboarded (SuspendedAt) or not-yet-started (ActivatesAt in the
//     future) user who still knows their password POSTs /token and gets 200
//     with a live access+refresh pair. The access token is separately refused
//     by resolver.go, but the refresh FAMILY is minted and rotatable, and
//     login.succeeded is emitted for the offboarded account — which is the
//     event the lockout plugin uses to clear a failure counter.
//
//   - registerRefresh never re-reads must_change_password, so an admin who
//     sets the forced-rotation flag revokes nothing: POST /token is refused
//     with the must-change 403 while POST /token/refresh keeps handing out
//     fresh pairs for the whole 30-day refresh TTL, each rotation pushing the
//     window forward. middleware.MustRotatePassword classifies bearer as a
//     machine method and returns false, so no downstream route re-checks it
//     either — the flag is permanently escapable through this one endpoint.
//
// Every refusal below is paired with a POSITIVE CONTROL on the same harness —
// a healthy account minting a token pair, or the same account rotating once
// the condition is cleared — so a "fix" that breaks /token or /token/refresh
// outright cannot pass.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
)

const lifecyclePW = "correct horse battery staple"

// suspendUser marks the account offboarded, exactly as the admin
// /admin/users/{id}/suspend endpoint does (SuspendedAt non-nil).
func suspendUser(t *testing.T, fr *fakeRepo, userID string) {
	t.Helper()
	u, ok := fr.users[userID]
	if !ok {
		t.Fatalf("suspendUser: no such user %q", userID)
	}
	now := time.Now().UTC()
	u.SuspendedAt = &now
	fr.users[userID] = u
}

// stageUser schedules the account to start in the future, the "onboarding
// ahead of a start date" state domain.User.Staged reports on.
func stageUser(t *testing.T, fr *fakeRepo, userID string) {
	t.Helper()
	u, ok := fr.users[userID]
	if !ok {
		t.Fatalf("stageUser: no such user %q", userID)
	}
	at := time.Now().UTC().Add(72 * time.Hour)
	u.ActivatesAt = &at
	fr.users[userID] = u
}

// liveRefreshTokens counts the UNREVOKED refresh rows belonging to userID.
// This — not the status code — is the credential that must not exist.
func liveRefreshTokens(fr *fakeRepo, userID string) int {
	n := 0
	for _, rt := range fr.refreshTokens {
		if rt.UserID == userID && !rt.Revoked {
			n++
		}
	}
	return n
}

func loginSucceededFor(h *harness, userID string) bool {
	for _, e := range h.host.emitted {
		if e.Type == events.EventLoginSucceeded && e.UserID != nil && *e.UserID == userID {
			return true
		}
	}
	return false
}

func decodeTokens(t *testing.T, body []byte) tokenResponse {
	t.Helper()
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		// A 4xx error body is not a tokenResponse; that is fine, the
		// zero value says "no credential".
		return tokenResponse{}
	}
	return tr
}

// TestToken_SuspendedAccountRefused: an offboarded user with the right
// password still gets a token pair from POST /token.
//
// POSITIVE CONTROL: a healthy account on the same harness mints its pair.
func TestToken_SuspendedAccountRefused(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, lifecyclePW)
	control := mustUser(t, fr, "control@example.com")
	mustPassword(t, fr, control.ID, lifecyclePW)

	suspendUser(t, fr, user.ID)

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"`+lifecyclePW+`"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Errorf("suspended account: expected 403 from /token, got %d body=%s", resp.Code, resp.Body.String())
	}
	tr := decodeTokens(t, resp.Body.Bytes())
	if tr.AccessToken != "" {
		t.Errorf("a suspended (offboarded) account was issued an access token")
	}
	if tr.RefreshToken != "" {
		t.Errorf("a suspended (offboarded) account was issued a refresh token")
	}
	if n := liveRefreshTokens(fr, user.ID); n != 0 {
		t.Errorf("a suspended account has %d live refresh-token row(s); /token minted a rotatable family for an offboarded user", n)
	}
	if loginSucceededFor(h, user.ID) {
		t.Errorf("login.succeeded emitted for a suspended account — lockout's onSucceeded clears the failure counter for an offboarded user")
	}

	// POSITIVE CONTROL.
	ctrl := h.issue(t, "control@example.com", lifecyclePW)
	if ctrl.AccessToken == "" || ctrl.RefreshToken == "" {
		t.Fatalf("control: a healthy account must still get a token pair, got %+v", ctrl)
	}
}

// TestToken_StagedAccountRefused: an account whose start date has not arrived
// is likewise waved through POST /token.
//
// POSITIVE CONTROL: the same account, once its start date has passed, mints
// its pair.
func TestToken_StagedAccountRefused(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, lifecyclePW)

	stageUser(t, fr, user.ID)

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"`+lifecyclePW+`"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Errorf("staged account: expected 403 from /token, got %d body=%s", resp.Code, resp.Body.String())
	}
	tr := decodeTokens(t, resp.Body.Bytes())
	if tr.AccessToken != "" || tr.RefreshToken != "" {
		t.Errorf("a staged account (start date in the future) was issued a token pair")
	}
	if n := liveRefreshTokens(fr, user.ID); n != 0 {
		t.Errorf("a staged account has %d live refresh-token row(s)", n)
	}

	// POSITIVE CONTROL: clear the staging and the same call succeeds.
	u := fr.users[user.ID]
	u.ActivatesAt = nil
	fr.users[user.ID] = u
	ctrl := h.issue(t, "alice@example.com", lifecyclePW)
	if ctrl.AccessToken == "" || ctrl.RefreshToken == "" {
		t.Fatalf("control: an activated account must get a token pair, got %+v", ctrl)
	}
}

// TestRefresh_SuspendedAccountBlocked: offboarding the user does not stop the
// refresh family they already hold — the next rotation returns 200 and mints
// a fresh pair.
//
// POSITIVE CONTROL: an un-suspended account rotates normally.
func TestRefresh_SuspendedAccountBlocked(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, lifecyclePW)

	first := h.issue(t, "alice@example.com", lifecyclePW)

	// POSITIVE CONTROL, taken FIRST on the healthy account: rotation works.
	ctrl := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+first.RefreshToken+`"}`, nil)
	if ctrl.Code != http.StatusOK {
		t.Fatalf("control: a healthy account must be able to rotate, got %d body=%s", ctrl.Code, ctrl.Body.String())
	}
	rotated := decodeTokens(t, ctrl.Body.Bytes())
	if rotated.RefreshToken == "" {
		t.Fatalf("control: rotation returned no refresh token")
	}

	// Now offboard the user and present the token they still hold.
	suspendUser(t, fr, user.ID)

	before := liveRefreshTokens(fr, user.ID)
	resp := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+rotated.RefreshToken+`"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Errorf("suspended account: expected 403 from /token/refresh, got %d body=%s", resp.Code, resp.Body.String())
	}
	tr := decodeTokens(t, resp.Body.Bytes())
	if tr.AccessToken != "" || tr.RefreshToken != "" {
		t.Errorf("an offboarded user rotated their refresh family and got a fresh credential pair")
	}
	if after := liveRefreshTokens(fr, user.ID); after > before {
		t.Errorf("refresh minted a new live token for a suspended user: %d live rows before, %d after", before, after)
	}
}

// TestRefresh_StagedAccountBlocked: same for a not-yet-started account.
func TestRefresh_StagedAccountBlocked(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, lifecyclePW)

	first := h.issue(t, "alice@example.com", lifecyclePW)
	stageUser(t, fr, user.ID)

	resp := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+first.RefreshToken+`"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Errorf("staged account: expected 403 from /token/refresh, got %d body=%s", resp.Code, resp.Body.String())
	}
	if tr := decodeTokens(t, resp.Body.Bytes()); tr.AccessToken != "" || tr.RefreshToken != "" {
		t.Errorf("a staged account rotated its refresh family and got a fresh credential pair")
	}

	// The refusal must be a no-op: the presented token stays live so the
	// account works the moment its start date arrives.
	stored, err := fr.GetRefreshTokenByHash(context.Background(), auth.HashToken(first.RefreshToken))
	if err != nil {
		t.Fatalf("lookup presented token: %v", err)
	}
	if stored.Revoked {
		t.Errorf("the staged-account refusal consumed the presented refresh token; a lifecycle refusal must not burn the family")
	}

	// POSITIVE CONTROL: an active account on the same harness rotates fine.
	control := mustUser(t, fr, "control@example.com")
	mustPassword(t, fr, control.ID, lifecyclePW)
	ctrlPair := h.issue(t, "control@example.com", lifecyclePW)
	ctrl := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+ctrlPair.RefreshToken+`"}`, nil)
	if ctrl.Code != http.StatusOK {
		t.Fatalf("control: an active account must be able to rotate, got %d body=%s", ctrl.Code, ctrl.Body.String())
	}
}

// TestRefresh_MustChangePasswordBlocked: the forced-rotation flag is enforced
// at /token (TestToken_MustChangePasswordBlocked covers that) but never
// re-checked at /token/refresh, so a client holding a refresh token escapes it
// forever.
//
// POSITIVE CONTROL: clearing the flag lets the same token rotate again, so a
// fix cannot pass by refusing every refresh.
func TestRefresh_MustChangePasswordBlocked(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, lifecyclePW)

	first := h.issue(t, "alice@example.com", lifecyclePW)

	if err := fr.SetUserMustChangePassword(context.Background(), user.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}
	// Precondition: the front door is shut for this account.
	if resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"`+lifecyclePW+`"}`, nil); resp.Code != http.StatusForbidden {
		t.Fatalf("precondition: /token should refuse a must-change account, got %d", resp.Code)
	}

	resp := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+first.RefreshToken+`"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Errorf("must_change_password: expected 403 from /token/refresh, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), middleware.MustChangePasswordDetail) {
		t.Errorf("expected the must-change detail %q so clients handle it uniformly, got %s",
			middleware.MustChangePasswordDetail, resp.Body.String())
	}
	tr := decodeTokens(t, resp.Body.Bytes())
	if tr.AccessToken != "" || tr.RefreshToken != "" {
		t.Errorf("a must_change_password account rotated past the gate and got a fresh credential pair")
	}
	// The presented token must still be usable once the password is rotated:
	// a policy refusal must not burn the family.
	stored, err := fr.GetRefreshTokenByHash(context.Background(), auth.HashToken(first.RefreshToken))
	if err != nil {
		t.Fatalf("lookup presented token: %v", err)
	}
	if stored.Revoked {
		t.Errorf("the must-change refusal revoked the presented refresh token; a policy refusal must be a no-op")
	}

	// POSITIVE CONTROL: an account without the flag rotates normally on the
	// same harness, so a fix cannot pass by refusing every refresh.
	control := mustUser(t, fr, "control@example.com")
	mustPassword(t, fr, control.ID, lifecyclePW)
	ctrlPair := h.issue(t, "control@example.com", lifecyclePW)
	ctrl := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+ctrlPair.RefreshToken+`"}`, nil)
	if ctrl.Code != http.StatusOK {
		t.Fatalf("control: an account without must_change_password must be able to rotate, got %d body=%s", ctrl.Code, ctrl.Body.String())
	}
}
