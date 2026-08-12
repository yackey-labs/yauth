package organizations

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// seedMember adds (orgID, userID, role) directly via the repo.
func seedMember(t *testing.T, r repo.Repository, orgID, userID, role string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		OwnerRoleAuthorized: true, // test fixture: seeds state directly, bypassing the handler layer
		ID:                  uuid.NewString(),
		OrganizationID:      orgID,
		UserID:              userID,
		Role:                role,
		Status:              domain.MembershipActive,
		CreatedAt:           now,
		UpdatedAt:           now,
	}); err != nil {
		t.Fatalf("seed membership (%s, %s, %s): %v", orgID, userID, role, err)
	}
}

// --- Change-role endpoint ---

func TestChangeRoleAdminCanPromoteMemberToAdmin(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	// Owner creates org.
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)
	// Add a member.
	targetID := "u-member"
	seedMember(t, r, org.ID, targetID, auth.RoleMember)

	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members/"+targetID+"/role", map[string]string{
		"role": auth.RoleAdmin,
	})
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("want 200, got %d body=%s", res.StatusCode, body)
	}
	got, _ := r.GetMembershipByOrgUser(context.Background(), org.ID, targetID)
	if got == nil || got.Role != auth.RoleAdmin {
		t.Fatalf("role not updated: %+v", got)
	}
}

func TestChangeRoleMemberCannotEscalate(t *testing.T) {
	// Caller is a member, not an admin. They should get 403.
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	// Seed an org owned by someone else; make the caller a member.
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o1", Name: "Other", Slug: "other", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	seedMember(t, r, "o1", "owner-uid", auth.RoleOwner)
	seedMember(t, r, "o1", caller.ID, auth.RoleMember)
	// Some peer member that the caller wants to promote.
	seedMember(t, r, "o1", "peer", auth.RoleMember)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/members/peer/role", map[string]string{
		"role": auth.RoleAdmin,
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", res.StatusCode)
	}
}

func TestChangeRoleViewerCannotEscalateSelf(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o1", Name: "Other", Slug: "other", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	seedMember(t, r, "o1", "owner-uid", auth.RoleOwner)
	seedMember(t, r, "o1", caller.ID, auth.RoleViewer)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/members/"+caller.ID+"/role", map[string]string{
		"role": auth.RoleOwner,
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer must not change roles; got %d", res.StatusCode)
	}
}

func TestChangeRoleRejectsOwnerTarget(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	// Add an admin caller so the gate passes the admin check.
	// (Owner can also call, so just use the owner directly.)
	_ = r
	// Try to change the owner's role (which is the owner themselves).
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members/"+owner.ID+"/role", map[string]string{
		"role": auth.RoleAdmin,
	})
	if res.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("want 400 (must transfer first), got %d body=%s", res.StatusCode, body)
	}
}

func TestChangeRoleRejectsPromotingToOwner(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	seedMember(t, r, org.ID, "u-member", auth.RoleMember)

	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members/u-member/role", map[string]string{
		"role": auth.RoleOwner,
	})
	if res.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("want 400 (use transfer), got %d body=%s", res.StatusCode, body)
	}
}

func TestChangeRoleTargetMustBeMember(t *testing.T) {
	owner := seededUser()
	srv, _ := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)

	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members/u-not-a-member/role", map[string]string{
		"role": auth.RoleMember,
	})
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", res.StatusCode)
	}
}

// --- Transfer-ownership endpoint ---

func TestTransferOwnershipPromotesAndDemotes(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	seedMember(t, r, org.ID, "new-owner", auth.RoleMember)

	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/transfer-ownership", map[string]string{
		"new_owner_user_id": "new-owner",
	})
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("want 200, got %d body=%s", res.StatusCode, body)
	}
	// New owner now holds owner role.
	newMem, _ := r.GetMembershipByOrgUser(context.Background(), org.ID, "new-owner")
	if newMem == nil || newMem.Role != auth.RoleOwner {
		t.Fatalf("new owner role: %+v", newMem)
	}
	// Prior owner demoted to admin.
	priorMem, _ := r.GetMembershipByOrgUser(context.Background(), org.ID, owner.ID)
	if priorMem == nil || priorMem.Role != auth.RoleAdmin {
		t.Fatalf("prior owner not demoted to admin: %+v", priorMem)
	}
}

func TestTransferOwnershipAdminCannotInitiate(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o1", Name: "Other", Slug: "other", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	seedMember(t, r, "o1", "owner-uid", auth.RoleOwner)
	seedMember(t, r, "o1", caller.ID, auth.RoleAdmin)
	seedMember(t, r, "o1", "peer", auth.RoleMember)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/transfer-ownership", map[string]string{
		"new_owner_user_id": "peer",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("admin must not transfer ownership; got %d", res.StatusCode)
	}
}

func TestTransferOwnershipRejectsNonMember(t *testing.T) {
	owner := seededUser()
	srv, _ := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)

	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/transfer-ownership", map[string]string{
		"new_owner_user_id": "stranger",
	})
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 (stranger isn't a member), got %d", res.StatusCode)
	}
}

func TestTransferOwnershipRejectsSelfTransfer(t *testing.T) {
	owner := seededUser()
	srv, _ := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)

	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/transfer-ownership", map[string]string{
		"new_owner_user_id": owner.ID,
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("self-transfer must 400; got %d", res.StatusCode)
	}
}

// --- List-permissions endpoint ---

func TestListPermissionsOwnerHasFullSet(t *testing.T) {
	owner := seededUser()
	srv, _ := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)

	res = doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/permissions", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", res.StatusCode)
	}
	var out listPermissionsResponse
	decode(t, res, &out)
	if out.Role != auth.RoleOwner {
		t.Fatalf("role: %q", out.Role)
	}
	wantHas := []string{string(auth.PermOrgTransferOwnership), string(auth.PermOrgDelete), string(auth.PermBillingCancel)}
	set := map[string]bool{}
	for _, p := range out.Permissions {
		set[p] = true
	}
	for _, w := range wantHas {
		if !set[w] {
			t.Errorf("owner missing permission %q in list: %v", w, out.Permissions)
		}
	}
}

func TestListPermissionsViewerIsReadOnly(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o1", Name: "Other", Slug: "other", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	seedMember(t, r, "o1", "owner-uid", auth.RoleOwner)
	seedMember(t, r, "o1", caller.ID, auth.RoleViewer)

	res := doJSON(t, http.MethodGet, srv.URL+"/organizations/o1/permissions", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", res.StatusCode)
	}
	var out listPermissionsResponse
	decode(t, res, &out)
	if out.Role != auth.RoleViewer {
		t.Fatalf("role: %q", out.Role)
	}
	set := map[string]bool{}
	for _, p := range out.Permissions {
		set[p] = true
	}
	for _, banned := range []auth.Permission{
		auth.PermMembersInvite, auth.PermMembersRemove, auth.PermMembersChangeRole,
		auth.PermBillingUpdate, auth.PermBillingCancel,
		auth.PermSettingsWrite, auth.PermOrgDelete, auth.PermOrgTransferOwnership,
	} {
		if set[string(banned)] {
			t.Errorf("viewer should not have %q", banned)
		}
	}
}

func TestListPermissionsNonMemberIs403(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o-other", Name: "Other", Slug: "other", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	res := doJSON(t, http.MethodGet, srv.URL+"/organizations/o-other/permissions", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-member must 403; got %d", res.StatusCode)
	}
}

// --- Owner-protection at the repo layer ---

func TestRepoRefusesToDemoteLastOwner(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	mem, _ := r.GetMembershipByOrgUser(context.Background(), org.ID, owner.ID)
	memberRole := auth.RoleMember
	_, err := r.UpdateMembership(context.Background(), mem.ID, domain.UpdateMembership{Role: &memberRole})
	if err == nil {
		t.Fatal("repo should refuse to demote last owner")
	}
}

func TestRepoRefusesToDeleteLastOwner(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	mem, _ := r.GetMembershipByOrgUser(context.Background(), org.ID, owner.ID)
	err := r.DeleteMembership(context.Background(), mem.ID)
	if err == nil {
		t.Fatal("repo should refuse to delete last owner")
	}
}

func TestCrossOrgIsolationViewerCannotActOnAnotherOrg(t *testing.T) {
	// Caller is owner of org1 but not a member of org2. They must
	// not be able to read members or change roles in org2.
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	// Create caller's own org so they have at least one membership.
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Mine", "slug": "mine"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", res.StatusCode)
	}
	// Seed another org the caller isn't a member of.
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o2", Name: "Other", Slug: "other", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	seedMember(t, r, "o2", "o2-owner", auth.RoleOwner)
	seedMember(t, r, "o2", "o2-member", auth.RoleMember)

	// Cannot view o2 permissions.
	res = doJSON(t, http.MethodGet, srv.URL+"/organizations/o2/permissions", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org permissions read must 403; got %d", res.StatusCode)
	}
	// Cannot change a role in o2.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/o2/members/o2-member/role", map[string]string{
		"role": auth.RoleViewer,
	})
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org change-role must 403; got %d", res.StatusCode)
	}
	// Cannot transfer ownership on o2.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/o2/transfer-ownership", map[string]string{
		"new_owner_user_id": "o2-member",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org transfer-ownership must 403; got %d", res.StatusCode)
	}
}
