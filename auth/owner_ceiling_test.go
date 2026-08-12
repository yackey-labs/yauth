package auth

import (
	"errors"
	"testing"

	"github.com/yackey-labs/yauth/domain"
)

// domain.RoleOwnerName is a deliberate duplicate of auth.RoleOwner — domain
// sits below auth in the import graph, so the repository ceiling cannot import
// the constant it enforces. This is the test that keeps the two honest.
func TestOwnerRoleConstantsAgree(t *testing.T) {
	if domain.RoleOwnerName != RoleOwner {
		t.Fatalf("domain.RoleOwnerName = %q but auth.RoleOwner = %q — the repository ceiling and the handler validator would disagree",
			domain.RoleOwnerName, RoleOwner)
	}
}

func TestValidateAssignableRole(t *testing.T) {
	for _, tc := range []struct {
		role    string
		refused bool
	}{
		{RoleOwner, true},
		{" owner ", true}, // padding must not smuggle it past a handler that does not trim
		{RoleAdmin, false},
		{RoleBillingAdmin, false},
		{RoleMember, false},
		{RoleViewer, false},
		{"", false},
		{"custom-role", false}, // custom roles grant nothing here; refusing them would break callers
		{"Owner", false},       // roles are matched case-sensitively everywhere else
	} {
		err := ValidateAssignableRole(tc.role)
		if tc.refused && !errors.Is(err, ErrOwnerRoleNotAssignable) {
			t.Errorf("ValidateAssignableRole(%q): got %v want ErrOwnerRoleNotAssignable", tc.role, err)
		}
		if !tc.refused && err != nil {
			t.Errorf("ValidateAssignableRole(%q): got %v want nil", tc.role, err)
		}
	}
}

func TestValidateAssignableRoles(t *testing.T) {
	if err := ValidateAssignableRoles(map[string]string{
		"eng": RoleAdmin, "sales": RoleMember,
	}); err != nil {
		t.Fatalf("a clean map was refused: %v", err)
	}
	if err := ValidateAssignableRoles(map[string]string{
		"eng": RoleAdmin, "platform": RoleOwner,
	}); !errors.Is(err, ErrOwnerRoleNotAssignable) {
		t.Fatalf("a map containing owner: got %v want ErrOwnerRoleNotAssignable", err)
	}
	if err := ValidateAssignableRoles(nil); err != nil {
		t.Fatalf("nil map: got %v want nil", err)
	}
}
