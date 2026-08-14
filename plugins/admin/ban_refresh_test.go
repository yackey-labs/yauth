package admin_test

// The two incident levers disagree about what they terminate.
//
// registerSuspendUser — the offboarding path — calls DeleteUserSessions AND
// RevokeAllUserRefreshTokens, and its doc comment calls itself the kill
// switch. registerBanUser — the path an operator reaches for during a security
// incident — calls DeleteUserSessions and stops. Refresh tokens live for the
// whole refresh TTL (30 days by default) and rotate forward on every use, so
// banning an account kicks it out of its cookie sessions while leaving every
// native/mobile client holding a rotatable refresh family. The moment the ban
// is lifted — and the bearer refresh leg only ever looked at user.Banned — a
// token stolen before the incident starts working again.
//
// registerPatchUser has the same hole on must_change_password: setting the
// forced-rotation flag revokes nothing, so a client that already holds a
// refresh family never passes through the gate at all.
//
// POSITIVE CONTROL: the suspend path on the same harness must keep revoking
// refresh tokens (it is the behaviour being copied), and ban must keep killing
// sessions — so a fix cannot pass by breaking either lever.

import (
	"context"
	"net/http"
	"testing"

	"github.com/yackey-labs/yauth/auth"
)

// TestBanUser_RevokesRefreshTokens is the regression.
func TestBanUser_RevokesRefreshTokens(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "ban-admin@example.com", "admin")
	target := env.seedUser(t, "ban-target@example.com", "user")
	_ = env.issueSession(t, target.ID)
	rawRefresh := env.seedRefreshToken(t, target.ID)
	tok := env.issueSession(t, admin.ID)

	res := env.do(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/ban", tok, map[string]any{
		"reason": "credential compromise",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ban: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Control leg: the ban demonstrably ran — sessions are gone.
	if env.targetHasSession(t, target.ID) {
		t.Fatalf("precondition: ban must terminate the user's sessions")
	}

	rt, err := env.repo.GetRefreshTokenByHash(context.Background(), auth.HashToken(rawRefresh))
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	if !rt.Revoked {
		t.Errorf("banning a user left their refresh-token family live; the token keeps rotating for the whole refresh TTL and comes back the moment the ban is lifted")
	}
}

// TestPatchUser_MustChangePasswordRevokesRefreshTokens: forcing a password
// change must terminate the credentials that would otherwise skip it.
//
// POSITIVE CONTROL: a PATCH that does NOT set the flag must leave the family
// alone — the fix must not turn every admin edit into a mass sign-out.
func TestPatchUser_MustChangePasswordRevokesRefreshTokens(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "mcp-admin@example.com", "admin")
	tok := env.issueSession(t, admin.ID)

	// Control first: an unrelated PATCH on another user must not revoke.
	bystander := env.seedUser(t, "mcp-bystander@example.com", "user")
	bystanderRefresh := env.seedRefreshToken(t, bystander.ID)
	res := env.do(t, http.MethodPatch, "/api/auth/admin/users/"+bystander.ID, tok, map[string]any{
		"display_name": "Bystander",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("control patch: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	brt, err := env.repo.GetRefreshTokenByHash(context.Background(), auth.HashToken(bystanderRefresh))
	if err != nil {
		t.Fatalf("get bystander refresh token: %v", err)
	}
	if brt.Revoked {
		t.Fatalf("control: an ordinary PATCH must not revoke refresh tokens")
	}

	target := env.seedUser(t, "mcp-target@example.com", "user")
	rawRefresh := env.seedRefreshToken(t, target.ID)
	res = env.do(t, http.MethodPatch, "/api/auth/admin/users/"+target.ID, tok, map[string]any{
		"must_change_password": true,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	rt, err := env.repo.GetRefreshTokenByHash(context.Background(), auth.HashToken(rawRefresh))
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	if !rt.Revoked {
		t.Errorf("setting must_change_password left the user's refresh family live, so the client rotates straight past the forced-rotation gate")
	}
}
