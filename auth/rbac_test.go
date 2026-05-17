package auth

import (
	"testing"
)

func TestIsBuiltinRole(t *testing.T) {
	for _, r := range []string{RoleOwner, RoleAdmin, RoleBillingAdmin, RoleMember, RoleViewer} {
		if !IsBuiltinRole(r) {
			t.Errorf("expected %q to be built-in", r)
		}
	}
	for _, r := range []string{"", "custom", "OWNER", "Admin"} {
		if IsBuiltinRole(r) {
			t.Errorf("expected %q to NOT be built-in", r)
		}
	}
}

func TestRoleAtLeast(t *testing.T) {
	tests := []struct {
		actual, required string
		want             bool
	}{
		{RoleOwner, RoleAdmin, true},
		{RoleOwner, RoleOwner, true},
		{RoleAdmin, RoleOwner, false},
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleMember, true},
		{RoleMember, RoleAdmin, false},
		{RoleViewer, RoleMember, false},
		{RoleMember, RoleViewer, true},
		{RoleBillingAdmin, RoleMember, true},
		{RoleBillingAdmin, RoleAdmin, false},
		// Unknown roles deny.
		{"custom", RoleMember, false},
		{RoleMember, "custom", false},
		{"", RoleViewer, false},
	}
	for _, tc := range tests {
		if got := RoleAtLeast(tc.actual, tc.required); got != tc.want {
			t.Errorf("RoleAtLeast(%q, %q) = %v, want %v", tc.actual, tc.required, got, tc.want)
		}
	}
}

func TestDefaultPermissionsOwnerHasEverything(t *testing.T) {
	ps := DefaultPermissions(RoleOwner)
	for _, p := range []Permission{
		PermMembersInvite, PermMembersRemove, PermMembersChangeRole, PermMembersView,
		PermBillingView, PermBillingUpdate, PermBillingCancel,
		PermSettingsRead, PermSettingsWrite,
		PermOrgDelete, PermOrgTransferOwnership,
	} {
		if !ps.Has(p) {
			t.Errorf("owner is missing permission %q", p)
		}
	}
}

func TestDefaultPermissionsAdminCannotTransferOrDelete(t *testing.T) {
	ps := DefaultPermissions(RoleAdmin)
	if ps.Has(PermOrgTransferOwnership) {
		t.Error("admin must not have org:transfer_ownership")
	}
	if ps.Has(PermOrgDelete) {
		t.Error("admin must not have org:delete")
	}
	if !ps.Has(PermMembersInvite) {
		t.Error("admin must have members:invite")
	}
}

func TestDefaultPermissionsViewerIsReadOnly(t *testing.T) {
	ps := DefaultPermissions(RoleViewer)
	for _, p := range []Permission{
		PermMembersInvite, PermMembersRemove, PermMembersChangeRole,
		PermBillingUpdate, PermBillingCancel,
		PermSettingsWrite, PermOrgDelete, PermOrgTransferOwnership,
	} {
		if ps.Has(p) {
			t.Errorf("viewer must NOT have %q", p)
		}
	}
	if !ps.Has(PermMembersView) {
		t.Error("viewer must have members:view")
	}
	if !ps.Has(PermSettingsRead) {
		t.Error("viewer must have settings:read")
	}
}

func TestDefaultPermissionsMemberCannotInviteOrChangeRole(t *testing.T) {
	ps := DefaultPermissions(RoleMember)
	if ps.Has(PermMembersInvite) {
		t.Error("member must not invite")
	}
	if ps.Has(PermMembersChangeRole) {
		t.Error("member must not change roles")
	}
}

func TestDefaultPermissionsBillingAdminScope(t *testing.T) {
	ps := DefaultPermissions(RoleBillingAdmin)
	if !ps.Has(PermBillingUpdate) {
		t.Error("billing_admin must have billing:update")
	}
	if !ps.Has(PermBillingCancel) {
		t.Error("billing_admin must have billing:cancel")
	}
	if ps.Has(PermMembersInvite) {
		t.Error("billing_admin must not invite members")
	}
	if ps.Has(PermSettingsWrite) {
		t.Error("billing_admin must not write settings")
	}
}

func TestDefaultPermissionsUnknownRoleIsEmpty(t *testing.T) {
	ps := DefaultPermissions("custom_super_admin")
	if len(ps) != 0 {
		t.Errorf("unknown role should have no default perms, got %v", ps.List())
	}
}

func TestHasPermissionShortcut(t *testing.T) {
	if !HasPermission(RoleAdmin, PermMembersInvite) {
		t.Fatal("admin must have members:invite")
	}
	if HasPermission(RoleViewer, PermMembersInvite) {
		t.Fatal("viewer must NOT have members:invite")
	}
	if HasPermission("unknown", PermSettingsRead) {
		t.Fatal("unknown role must have no perms")
	}
}

func TestPermissionSetListIsSorted(t *testing.T) {
	ps := NewPermissionSet(PermSettingsWrite, PermBillingView, PermMembersInvite)
	got := ps.List()
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Fatalf("List() not sorted: %v", got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("List() len = %d, want 3", len(got))
	}
}

func TestNilPermissionSetHasIsFalse(t *testing.T) {
	var ps PermissionSet
	if ps.Has(PermSettingsRead) {
		t.Fatal("nil PermissionSet.Has should be false")
	}
}
