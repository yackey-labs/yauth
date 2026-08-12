// Package auth — Org-scoped RBAC primitive (yauth Rust #88 port).
//
// The RBAC layer sits on top of `domain.Membership.Role`, which is a free-
// form string. yauth ships a small enum of built-in roles and a default
// permission catalogue mapped to each. Applications layering their own
// permissions on top can:
//
//   - use the built-in roles as-is and rely on default_permissions(role)
//     to gate yauth-managed routes (member invite, billing, settings)
//   - store custom role strings on the membership row; the helpers below
//     refuse cleanly (no panic, no implicit allow) when the role is
//     unknown
//
// Owner-protection (exactly one owner per org; cannot be demoted or
// removed without first transferring ownership) is enforced at the repo
// layer, not here.
package auth

import (
	"errors"
	"strings"
)

// Built-in role constants. Mirrors the yauth Rust feat/88 spec.
//
// The values are the same lowercase strings the Rust crate persists, so
// a single database can be read by either implementation.
const (
	RoleOwner        = "owner"
	RoleAdmin        = "admin"
	RoleBillingAdmin = "billing_admin"
	RoleMember       = "member"
	RoleViewer       = "viewer"
)

// BuiltinRoles is the ordered list of built-in roles, highest privilege
// first. Used by RoleAtLeast to compute a strict ordering.
var BuiltinRoles = []string{
	RoleOwner,
	RoleAdmin,
	RoleBillingAdmin,
	RoleMember,
	RoleViewer,
}

// ErrOwnerRoleNotAssignable is returned by ValidateAssignableRole for the
// owner role. Handlers map it to 400 with their own wording.
var ErrOwnerRoleNotAssignable = errors.New("yauth: owner can only be set by creating an organization or via transfer-ownership")

// ValidateAssignableRole rejects a role that a request may not choose freely.
//
// Today that is exactly one value: owner. Ownership is a slot, not a grade —
// an org has one owner, only they can transfer it, and only they are refused
// removal. So every surface that takes a role from the wire (invitations,
// verified-domain auto-join defaults, SSO JIT defaults and group→role maps)
// funnels through here rather than growing its own copy of the check. That
// divergence is exactly what happened: add-member, set-role and org API keys
// each refused owner while invitations, domain auto-join and SSO JIT shipped
// without it.
//
// Custom (non-built-in) role strings pass: yauth's catalogue grants them
// nothing, and refusing them would break applications that layer their own.
// The comparison is exact after trimming surrounding whitespace.
//
// The repository enforces the same ceiling as a backstop — see "the owner
// ceiling" on domain.UpdateMembership. This function is the layer that hands
// the caller a clean 400 instead of a 500.
func ValidateAssignableRole(role string) error {
	if strings.TrimSpace(role) == RoleOwner {
		return ErrOwnerRoleNotAssignable
	}
	return nil
}

// ValidateAssignableRoles applies ValidateAssignableRole to every value of a
// role-mapping table — an IdP group→role map, say — and returns the first
// error found. Iteration order is unspecified, which is harmless: any single
// offending entry refuses the whole write.
func ValidateAssignableRoles(m map[string]string) error {
	for _, role := range m {
		if err := ValidateAssignableRole(role); err != nil {
			return err
		}
	}
	return nil
}

// IsBuiltinRole reports whether r is one of the built-in role constants.
func IsBuiltinRole(r string) bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleBillingAdmin, RoleMember, RoleViewer:
		return true
	}
	return false
}

// roleRank returns a 0-based "strictly greater = more privileged" rank
// for a built-in role. Unknown roles return -1, which means the helpers
// below treat them as no-privilege.
//
// owner=4, admin=3, billing_admin=2, member=1, viewer=0.
//
// billing_admin sits above member because the only special privilege
// member has over billing_admin is "see members"; in practice we treat
// billing_admin as a sibling-with-different-domain rather than strictly
// stronger. The single ordering here is the conservative choice: any
// gate that wants finer discrimination should use HasPermission instead.
func roleRank(r string) int {
	switch r {
	case RoleOwner:
		return 4
	case RoleAdmin:
		return 3
	case RoleBillingAdmin:
		return 2
	case RoleMember:
		return 1
	case RoleViewer:
		return 0
	}
	return -1
}

// RoleAtLeast reports whether actual has at least the rank of required.
//
// Both arguments must be built-in roles; an unknown role on either side
// returns false (deny-by-default). For comparisons against custom
// strings, use HasPermission with an explicit permission instead.
func RoleAtLeast(actual, required string) bool {
	a, b := roleRank(actual), roleRank(required)
	if a < 0 || b < 0 {
		return false
	}
	return a >= b
}

// Permission is a fine-grained right enforced inside an organization.
// The string form is stable across yauth implementations.
type Permission string

// Default permission catalogue. The values are the strings the Rust
// crate exposes verbatim; new permissions go here AND in the Rust crate
// in lockstep.
const (
	// Member-management permissions.
	PermMembersInvite     Permission = "members:invite"
	PermMembersRemove     Permission = "members:remove"
	PermMembersChangeRole Permission = "members:change_role"
	PermMembersView       Permission = "members:view"

	// Billing permissions.
	PermBillingView   Permission = "billing:view"
	PermBillingUpdate Permission = "billing:update"
	PermBillingCancel Permission = "billing:cancel"

	// Settings permissions.
	PermSettingsRead  Permission = "settings:read"
	PermSettingsWrite Permission = "settings:write"

	// Org-management permissions.
	PermOrgDelete            Permission = "org:delete"
	PermOrgTransferOwnership Permission = "org:transfer_ownership"
)

// PermissionSet is the set of permissions a role grants. Stored as a
// map for O(1) Has() lookups.
type PermissionSet map[Permission]struct{}

// NewPermissionSet returns a PermissionSet seeded with ps.
func NewPermissionSet(ps ...Permission) PermissionSet {
	out := make(PermissionSet, len(ps))
	for _, p := range ps {
		out[p] = struct{}{}
	}
	return out
}

// Has reports whether s contains p.
func (s PermissionSet) Has(p Permission) bool {
	if s == nil {
		return false
	}
	_, ok := s[p]
	return ok
}

// List returns the permissions in deterministic (alphabetical) order so
// the list-permissions endpoint is reproducible.
func (s PermissionSet) List() []Permission {
	out := make([]Permission, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	// Sort lexically for stable JSON output.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// DefaultPermissions returns the permission set the built-in role
// implies. For unknown roles the result is an empty set — callers must
// layer their own permission map atop yauth for custom role strings.
//
// The catalogue mirrors the yauth Rust feat/88 default mapping.
func DefaultPermissions(role string) PermissionSet {
	switch role {
	case RoleOwner:
		return NewPermissionSet(
			PermMembersInvite, PermMembersRemove, PermMembersChangeRole, PermMembersView,
			PermBillingView, PermBillingUpdate, PermBillingCancel,
			PermSettingsRead, PermSettingsWrite,
			PermOrgDelete, PermOrgTransferOwnership,
		)
	case RoleAdmin:
		return NewPermissionSet(
			PermMembersInvite, PermMembersRemove, PermMembersChangeRole, PermMembersView,
			PermBillingView,
			PermSettingsRead, PermSettingsWrite,
		)
	case RoleBillingAdmin:
		return NewPermissionSet(
			PermMembersView,
			PermBillingView, PermBillingUpdate, PermBillingCancel,
			PermSettingsRead,
		)
	case RoleMember:
		return NewPermissionSet(
			PermMembersView,
			PermSettingsRead,
		)
	case RoleViewer:
		return NewPermissionSet(
			PermMembersView,
			PermSettingsRead,
		)
	}
	return NewPermissionSet()
}

// HasPermission reports whether the built-in role grants perm under the
// default catalogue. For custom role strings the result is always
// false — applications wrap this helper with their own map for any
// non-built-in role they ship.
func HasPermission(role string, perm Permission) bool {
	return DefaultPermissions(role).Has(perm)
}
