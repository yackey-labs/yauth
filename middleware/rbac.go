// rbac.go — context-bound org-scoped RBAC helpers.
//
// The cross-cutting question "is the caller permitted to act on this org?"
// resolves down to: (1) is there an authenticated AuthUser in context;
// (2) does that user have a membership row for (org_id, caller_id); and
// (3) does the membership role satisfy the requested role/permission.
//
// Helpers below return typed errors so handlers can map them to wire
// status codes:
//
//   - yautherr.ErrUnauthorized  → 401 (no AuthUser in context)
//   - yautherr.ErrForbidden     → 403 (not a member, or insufficient role)
//
// Any backend error (membership lookup failed) bubbles up unwrapped so
// the caller maps it to 500.
package middleware

import (
	"context"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// RequireOrgRole returns nil iff the AuthUser in ctx has a membership in
// the given org whose role is at least the required built-in role.
//
// "At least" follows auth.RoleAtLeast (owner > admin > billing_admin >
// member > viewer). Comparing against a custom role string always
// returns ErrForbidden — for custom roles use RequireOrgPermission with
// an explicit permission instead.
func RequireOrgRole(ctx context.Context, r repo.Repository, orgID, requiredRole string) error {
	au, ok := AuthUserFromContext(ctx)
	if !ok || au == nil {
		return yautherr.ErrUnauthorized
	}
	m, err := r.GetMembershipByOrgUser(ctx, orgID, au.User.ID)
	if err != nil {
		return err
	}
	if m == nil {
		return yautherr.ErrForbidden
	}
	if !auth.RoleAtLeast(m.Role, requiredRole) {
		return yautherr.ErrForbidden
	}
	return nil
}

// RequireOrgPermission returns nil iff the AuthUser in ctx has a
// membership in the given org whose role grants perm under the default
// permission catalogue.
//
// Custom roles always return ErrForbidden under this helper — callers
// who ship custom roles must layer their own permission check using
// the row Role returned from MembershipFromContext (TODO when needed)
// or a repo lookup. yauth's default catalogue is for built-in roles.
func RequireOrgPermission(ctx context.Context, r repo.Repository, orgID string, perm auth.Permission) error {
	au, ok := AuthUserFromContext(ctx)
	if !ok || au == nil {
		return yautherr.ErrUnauthorized
	}
	m, err := r.GetMembershipByOrgUser(ctx, orgID, au.User.ID)
	if err != nil {
		return err
	}
	if m == nil {
		return yautherr.ErrForbidden
	}
	if !auth.HasPermission(m.Role, perm) {
		return yautherr.ErrForbidden
	}
	return nil
}
