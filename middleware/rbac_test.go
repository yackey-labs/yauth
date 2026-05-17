package middleware

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

func seedUserAndMembership(t *testing.T, r *memrepo.Repo, role string) (string, string) {
	t.Helper()
	now := time.Now().UTC()
	orgID := uuid.NewString()
	userID := uuid.NewString()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgID, Name: "Org", Slug: "org-" + orgID, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: userID, Role: role,
		Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return orgID, userID
}

func ctxWithUser(t *testing.T, userID string) context.Context {
	t.Helper()
	return withAuthUser(context.Background(), &domain.AuthUser{
		User: domain.User{ID: userID},
	})
}

func TestRequireOrgRoleOK(t *testing.T) {
	r := memrepo.New()
	orgID, userID := seedUserAndMembership(t, r, auth.RoleAdmin)
	ctx := ctxWithUser(t, userID)
	if err := RequireOrgRole(ctx, r, orgID, auth.RoleAdmin); err != nil {
		t.Fatalf("admin RequireOrgRole(admin): %v", err)
	}
	if err := RequireOrgRole(ctx, r, orgID, auth.RoleMember); err != nil {
		t.Fatalf("admin RequireOrgRole(member): %v", err)
	}
	if err := RequireOrgRole(ctx, r, orgID, auth.RoleOwner); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("admin RequireOrgRole(owner) must be Forbidden, got %v", err)
	}
}

func TestRequireOrgRoleNonMemberForbidden(t *testing.T) {
	r := memrepo.New()
	orgID, _ := seedUserAndMembership(t, r, auth.RoleOwner)
	strangerCtx := ctxWithUser(t, "stranger")
	if err := RequireOrgRole(strangerCtx, r, orgID, auth.RoleViewer); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("non-member must be Forbidden; got %v", err)
	}
}

func TestRequireOrgRoleNoAuthUnauthorized(t *testing.T) {
	r := memrepo.New()
	orgID, _ := seedUserAndMembership(t, r, auth.RoleOwner)
	if err := RequireOrgRole(context.Background(), r, orgID, auth.RoleViewer); !errors.Is(err, yautherr.ErrUnauthorized) {
		t.Fatalf("no auth must be Unauthorized; got %v", err)
	}
}

func TestRequireOrgPermissionOK(t *testing.T) {
	r := memrepo.New()
	orgID, userID := seedUserAndMembership(t, r, auth.RoleAdmin)
	ctx := ctxWithUser(t, userID)
	if err := RequireOrgPermission(ctx, r, orgID, auth.PermMembersInvite); err != nil {
		t.Fatalf("admin must have members:invite: %v", err)
	}
	if err := RequireOrgPermission(ctx, r, orgID, auth.PermOrgTransferOwnership); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("admin must NOT have org:transfer_ownership; got %v", err)
	}
}

func TestRequireOrgPermissionViewerDeniedWriteOps(t *testing.T) {
	r := memrepo.New()
	orgID, userID := seedUserAndMembership(t, r, auth.RoleViewer)
	ctx := ctxWithUser(t, userID)
	if err := RequireOrgPermission(ctx, r, orgID, auth.PermSettingsWrite); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("viewer must not have settings:write; got %v", err)
	}
	if err := RequireOrgPermission(ctx, r, orgID, auth.PermSettingsRead); err != nil {
		t.Fatalf("viewer must have settings:read; got %v", err)
	}
}

func TestRequireOrgPermissionCustomRoleDenied(t *testing.T) {
	// Custom role strings are stored but have no default permission
	// mapping — yauth refuses (deny by default).
	r := memrepo.New()
	orgID, userID := seedUserAndMembership(t, r, "super_duper_custom")
	ctx := ctxWithUser(t, userID)
	if err := RequireOrgPermission(ctx, r, orgID, auth.PermMembersView); !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("custom role must be Forbidden; got %v", err)
	}
}
