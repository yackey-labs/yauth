package auth

import (
	"testing"

	"github.com/yackey-labs/yauth/domain"
)

// KeySatisfiesRole is the narrowest signature-compatible narrowing of a
// role gate for callers that CAN see the key's scope list.
func TestKeySatisfiesRole(t *testing.T) {
	cases := []struct {
		name     string
		role     string
		scopes   []string
		required string
		want     bool
	}{
		{"role-only admin passes admin gate (matches RequireOrgRole)", RoleAdmin, nil, RoleAdmin, true},
		{"role-only viewer fails admin gate", RoleViewer, nil, RoleAdmin, false},
		{"empty scope list means role-only", RoleAdmin, []string{}, RoleAdmin, true},
		{"blank scope list means role-only", RoleAdmin, []string{"  "}, RoleAdmin, true},
		{"narrowed admin fails admin gate (the pinned gap)", RoleAdmin, []string{"members:view"}, RoleAdmin, false},
		{"narrowed admin fails even member gate (loses full member set)", RoleAdmin, []string{"members:view"}, RoleMember, false},
		{"fully-scoped admin passes admin gate", RoleAdmin, []string{"members:view", "members:invite", "members:remove", "members:change_role", "billing:view", "settings:read", "settings:write"}, RoleAdmin, true},
		{"custom role never passes built-in gate", "support_bot", []string{"members:view"}, RoleMember, false},
		{"unknown required role denies", RoleAdmin, nil, "telepathy", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := KeySatisfiesRole(tc.role, tc.scopes, tc.required); got != tc.want {
				t.Fatalf("KeySatisfiesRole(%q,%q,%q) = %v, want %v",
					tc.role, tc.scopes, tc.required, got, tc.want)
			}
		})
	}
}

// Pins the divergence the KNOWN GAPS comment describes: RoleAtLeast (what
// middleware.RequireOrgRole tests) still passes a scoped-down key, while
// the scope-aware helpers refuse it. Until RequireOrgRole adopts
// KeySatisfiesRole or every route moves to RequireOrgPermission, this gap
// stands — this test forces any change to be deliberate.
func TestRoleGateDivergencePinned(t *testing.T) {
	role, scopes := RoleAdmin, []string{"members:view"}
	if !RoleAtLeast(role, RoleAdmin) {
		t.Fatalf("precondition: RoleAtLeast(admin, admin) must be true (role gate passes)")
	}
	if KeySatisfiesRole(role, scopes, RoleAdmin) {
		t.Fatalf("KeySatisfiesRole(admin, [members:view], admin) must be false (narrowed key fails)")
	}
	if KeyHasPermission(role, scopes, PermMembersInvite) {
		t.Fatalf("KeyHasPermission must refuse members:invite for the narrowed key")
	}
	if !KeyHasPermission(role, scopes, PermMembersView) {
		t.Fatalf("KeyHasPermission must still grant members:view")
	}
}

// Pins the user-scoped half of the gap: a user principal carries NO scope
// list by construction, so there is nothing for a scope-aware gate to
// enforce. The apikey resolver builds the user path via
// domain.NewUserPrincipal (Scopes always nil) and drops the stored column
// at resolution.
func TestUserScopedKeyScopesDroppedAtResolution(t *testing.T) {
	p := domain.NewUserPrincipal("u1")
	if p.Scopes != nil {
		t.Fatalf("user principal must carry nil Scopes, got %v", p.Scopes)
	}
	if p.IsServiceAccount() {
		t.Fatalf("user principal must not read as a service account")
	}
	// EffectiveKeyPermissions is org-scoped only: with no role and no
	// scopes it grants nothing, so it cannot serve as a user-key gate.
	if got := EffectiveKeyPermissions("", nil); len(got) != 0 {
		t.Fatalf("roleless/scopeless grant must be empty, got %v", got.List())
	}
}
