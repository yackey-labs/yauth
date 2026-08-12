// org_authz_status_test.go — regression suite for EffectiveOrgMembership
// ignoring Membership.Status.
//
// EffectiveOrgMembership is the single gate behind all of
// plugins/organizations, the ssooidc/ssosaml admin handlers, and the exported
// RequireOrgRole / RequireOrgPermission helpers. It looked the membership up
// by (org_id, user_id) and returned it — with no status check — so a
// "suspended" row (which domain.MembershipSuspended exists precisely to block)
// and an "invited" row (an offer not yet accepted) both authorized at whatever
// role they carried.
//
// The reachable path: SCIM active:false suspends the membership AND the global
// user; an operator later runs the routine POST /admin/users/{id}/unsuspend,
// which clears the global flag and touches no membership row — and the
// offboarded user logs back in still holding org-admin.
//
// Every other consumer already filtered on status (auth/active_org.go,
// plugins/bearer/handlers.go, plugins/organizations/active_org_handlers.go);
// this was the one that did not.
package middleware

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yautherr"
)

// seedStatusMembership plants a membership at the given role and status and
// returns (repo, orgID, userID).
func seedStatusMembership(t *testing.T, role string, status domain.MembershipStatus) (repo.Repository, string, string) {
	t.Helper()
	r := memrepo.New()
	ctx := context.Background()
	now := time.Now().UTC()
	orgID, userID := uuid.NewString(), uuid.NewString()
	if _, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: "acme-" + orgID[:8], CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: userID,
		Role: role, Status: status, CreatedAt: now, UpdatedAt: now,
		OwnerRoleAuthorized: true, // test fixture: seeds state directly
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return r, orgID, userID
}

func authUserFor(userID string) *domain.AuthUser {
	return &domain.AuthUser{
		User:      domain.User{ID: userID},
		Principal: domain.NewUserPrincipal(userID),
	}
}

// A suspended membership must confer nothing, whatever role it carries.
func TestEffectiveOrgMembership_SuspendedIsForbidden(t *testing.T) {
	r, orgID, userID := seedStatusMembership(t, auth.RoleAdmin, domain.MembershipSuspended)
	ctx := context.Background()

	if _, err := EffectiveOrgMembership(ctx, r, authUserFor(userID), orgID); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("EffectiveOrgMembership: got %v want ErrForbidden", err)
	}

	// And through both exported gates, which is how every caller reaches it.
	gated := withAuthUser(ctx, authUserFor(userID))
	if err := RequireOrgRole(gated, r, orgID, auth.RoleAdmin); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("RequireOrgRole(admin): got %v want ErrForbidden", err)
	}
	if err := RequireOrgPermission(gated, r, orgID, auth.PermMembersRemove); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("RequireOrgPermission(members:remove): got %v want ErrForbidden", err)
	}
}

// A suspended OWNER is the worst case: the top of the role ladder, blocked.
func TestEffectiveOrgMembership_SuspendedOwnerIsForbidden(t *testing.T) {
	r, orgID, userID := seedStatusMembership(t, auth.RoleOwner, domain.MembershipSuspended)
	gated := withAuthUser(context.Background(), authUserFor(userID))
	if err := RequireOrgRole(gated, r, orgID, auth.RoleMember); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("suspended owner passed a member-level gate: %v", err)
	}
}

// "invited" is a listing convenience for an offer that has not been accepted.
// Holding the offer is not holding the role.
func TestEffectiveOrgMembership_InvitedIsForbidden(t *testing.T) {
	r, orgID, userID := seedStatusMembership(t, auth.RoleAdmin, domain.MembershipInvited)
	ctx := context.Background()

	if _, err := EffectiveOrgMembership(ctx, r, authUserFor(userID), orgID); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("EffectiveOrgMembership: got %v want ErrForbidden", err)
	}
	gated := withAuthUser(ctx, authUserFor(userID))
	if err := RequireOrgRole(gated, r, orgID, auth.RoleAdmin); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("RequireOrgRole(admin): got %v want ErrForbidden", err)
	}
}

// An unrecognised status must fail closed: it is not evidence of an active
// member. (A hand-built row with no status at all lands here too.)
func TestEffectiveOrgMembership_UnknownStatusFailsClosed(t *testing.T) {
	r, orgID, userID := seedStatusMembership(t, auth.RoleAdmin, domain.MembershipStatus("pending_review"))
	if _, err := EffectiveOrgMembership(context.Background(), r, authUserFor(userID), orgID); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("got %v want ErrForbidden", err)
	}
}

// --- positive controls ----------------------------------------------------

// An active membership is unaffected.
func TestEffectiveOrgMembership_ActiveStillAuthorizes(t *testing.T) {
	r, orgID, userID := seedStatusMembership(t, auth.RoleAdmin, domain.MembershipActive)
	ctx := context.Background()

	m, err := EffectiveOrgMembership(ctx, r, authUserFor(userID), orgID)
	if err != nil {
		t.Fatalf("active membership refused: %v", err)
	}
	if m.Role != auth.RoleAdmin {
		t.Fatalf("role: got %q want admin", m.Role)
	}
	gated := withAuthUser(ctx, authUserFor(userID))
	if err := RequireOrgRole(gated, r, orgID, auth.RoleAdmin); err != nil {
		t.Fatalf("RequireOrgRole(admin) on an active admin: %v", err)
	}
	if err := RequireOrgPermission(gated, r, orgID, auth.PermMembersRemove); err != nil {
		t.Fatalf("RequireOrgPermission on an active admin: %v", err)
	}
}

// A service account's membership is synthetic — the key's own binding, which
// has no lifecycle row to suspend. The status gate must not disturb it.
func TestEffectiveOrgMembership_ServiceAccountUnaffected(t *testing.T) {
	r := memrepo.New()
	orgID := uuid.NewString()
	role := auth.RoleAdmin
	au := &domain.AuthUser{
		User: domain.User{ID: uuid.NewString()},
		Principal: domain.Principal{
			Kind:  domain.PrincipalKindServiceAccount,
			OrgID: &orgID,
			Role:  &role,
		},
	}
	m, err := EffectiveOrgMembership(context.Background(), r, au, orgID)
	if err != nil {
		t.Fatalf("service account refused: %v", err)
	}
	if m.Role != auth.RoleAdmin {
		t.Fatalf("role: got %q want admin", m.Role)
	}
}
