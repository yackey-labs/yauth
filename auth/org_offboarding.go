// Package auth — the group-side half of offboarding a member from an org.
//
// yauth states an invariant in two places already ("group membership ⊆ org
// membership": plugins/organizations.registerAddGroupMember and
// plugins/scim.addMemberIfOrgMember) but only ever enforced it on the WRITE
// side. Nothing enforced it on removal:
//
//   - plugins/organizations.registerRemoveMember deleted only the membership
//     row; plugins/scim.handleDeleteUser deleted the membership, the external
//     identity, the sessions and the refresh tokens — but neither touched
//     yauth_group_members.
//   - There is no FK behind those rows to cascade for us: the schema in
//     migrate/postgres/001_initial.sql stores bare TEXT columns.
//   - The reads that decide access do not join memberships at all.
//     repo/pgxrepo/queries/groups.sql UserInAssignedGroup joins
//     yauth_client_group_assignments to yauth_group_members and stops;
//     ListGroupNamesForUser is a bare `WHERE gm.user_id = $1`.
//
// So the four production readers — plugins/oauth2server/authorize.go and
// device.go (the enforce_group_assignment gate) and plugins/oidc/handlers.go
// plus oauth2server/token.go (the `groups` claim) — all kept saying yes for a
// user who had been offboarded. An ex-employee who could still authenticate
// (SCIM DELETE deliberately does not set suspended_at, so they can log in
// again) kept their app access and their groups claim.
//
// This helper closes it on the write side, where the membership row is
// deleted, rather than by adding a membership join to the group queries. The
// read-side fix would be strictly stronger, but it would deny group access in
// every deployment that uses groups without matching membership rows, and it
// would drag sqlc regeneration, memrepo, repo/conformance and four
// *_group_stub_test.go files along with it. Removing the rows at the moment
// their justification disappears satisfies the invariant the plugins already
// claim to hold.
//
// SCOPE, deliberately: this revokes GROUP rows inside ONE org and nothing
// else. It does not delete sessions and it does not revoke refresh tokens —
// those are account-global artifacts (a domain.Session carries an
// active_org_id but belongs to the account, and a domain.RefreshToken carries
// a ClientID that may belong to a different org entirely), so letting an org
// admin reach them would hand any org's admin a cross-tenant logout primitive.
// It is also unnecessary for the org itself: auth.ResolveActiveOrg,
// MembershipRoleResolver.RoleFor and middleware.EffectiveOrgMembership all
// re-derive org authority from the membership row on every request, so the
// surviving cookie confers nothing in the org the moment the row is gone.
package auth

import (
	"context"
	"errors"

	"github.com/yackey-labs/yauth/domain"
)

// OrgGroupOffboardRepo is the narrow repo surface RevokeOrgGroupMemberships
// needs. Kept as its own interface — rather than repo.Repository or a new
// method on it — so callers can fake it and so no new method has to ripple
// through memrepo, pgxrepo, repo/conformance and the group stubs in the
// middleware/apikey/bearer/passkey tests.
type OrgGroupOffboardRepo interface {
	ListGroupsForUser(ctx context.Context, orgID, userID string) ([]*domain.Group, error)
	RemoveGroupMember(ctx context.Context, groupID, userID string) error
}

// RevokeOrgGroupMemberships removes userID from every group belonging to
// orgID. Callers run it immediately after the membership row is deleted.
//
// Enumeration goes through ListGroupsForUser(ctx, orgID, userID), which is
// org-filtered at the source (pgxrepo/queries/groups.sql filters on
// `g.organization_id = $1`; memrepo/groups.go does the same). That filter is
// load-bearing: a user may hold memberships — and group memberships — in
// several orgs, and offboarding them from org A must not strip their groups in
// org B. Do not reimplement this over a global group list.
//
// The loop is best-effort in the sense that one failing group does not abort
// the rest: every group is attempted and the errors are joined and returned
// together, so a caller that logs the result sees all of them. The membership
// delete is the load-bearing part of offboarding and callers should not fail
// the request on this error.
func RevokeOrgGroupMemberships(ctx context.Context, r OrgGroupOffboardRepo, orgID, userID string) error {
	if r == nil || orgID == "" || userID == "" {
		return nil
	}
	groups, err := r.ListGroupsForUser(ctx, orgID, userID)
	if err != nil {
		return err
	}
	var errs []error
	for _, g := range groups {
		if g == nil {
			continue
		}
		// Belt and braces: the query is org-scoped, but never remove a row
		// for a group that does not belong to this org.
		if g.OrganizationID != orgID {
			continue
		}
		if err := r.RemoveGroupMember(ctx, g.ID, userID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
