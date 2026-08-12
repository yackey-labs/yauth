// owner_ceiling_test.go — regression suite for the missing "owner" ceiling.
//
// The org plugin refused the owner role in three places (add-member, set-role,
// org API keys) and forgot it in the paths where the role reaches a membership
// indirectly:
//
//   - INVITATIONS took Body.role verbatim and accept wrote it straight onto the
//     membership, so an org admin minted an owner by inviting a colluding
//     address as one.
//   - DOMAIN AUTO-JOIN took default_role_on_auto_join from the body (create and
//     PATCH), and auth/domain_autojoin.go fed it to CreateMembership for every
//     signup under the domain.
//
// The fix is a shared validator (auth.ValidateAssignableRole) at each input
// surface, backed by a ceiling in the repository itself
// (domain.NewMembership.OwnerRoleRefused) so a future path cannot reintroduce
// the hole by forgetting a fourth copy of the check.
package organizations

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// seedAdminOrg plants an org with the caller as an ACTIVE admin.
func seedAdminOrg(t *testing.T, r repo.Repository, userID string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	orgID := uuid.NewString()
	if _, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: "acme-" + orgID[:8], CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: userID,
		Role: auth.RoleAdmin, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return orgID
}

// --- invitations ----------------------------------------------------------

func TestInviteAsOwner_Refused(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID := seedAdminOrg(t, r, caller.ID)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/invitations",
		map[string]any{"email": "accomplice@example.com", "role": auth.RoleOwner})
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("invite as owner: got %d want 400", res.StatusCode)
	}

	invs, err := r.ListPendingInvitationsForOrg(context.Background(), orgID)
	if err != nil {
		t.Fatalf("list invitations: %v", err)
	}
	if len(invs) != 0 {
		t.Fatalf("an owner invitation was persisted: %+v", invs)
	}
}

// Whitespace must not smuggle it through a handler that does not trim.
func TestInviteAsPaddedOwner_Refused(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID := seedAdminOrg(t, r, caller.ID)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/invitations",
		map[string]any{"email": "accomplice@example.com", "role": " owner "})
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("invite as ' owner ': got %d want 400", res.StatusCode)
	}
}

// Positive control: inviting an admin is exactly what this endpoint is for.
func TestInviteAsAdmin_StillWorks(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID := seedAdminOrg(t, r, caller.ID)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/invitations",
		map[string]any{"email": "colleague@example.com", "role": auth.RoleAdmin})
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("invite as admin: got %d want 201", res.StatusCode)
	}
	invs, err := r.ListPendingInvitationsForOrg(context.Background(), orgID)
	if err != nil || len(invs) != 1 {
		t.Fatalf("admin invitation not persisted: %d %v", len(invs), err)
	}
}

// --- verified-domain auto-join -------------------------------------------

func TestDomainAutoJoinRoleOwner_RefusedOnCreate(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID := seedAdminOrg(t, r, caller.ID)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/domains", map[string]any{
		"domain":                    "acme.example",
		"auto_join_on_signup":       true,
		"default_role_on_auto_join": auth.RoleOwner,
	})
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("domain with default_role_on_auto_join=owner: got %d want 400", res.StatusCode)
	}

	doms, err := r.ListOrganizationDomainsByOrg(context.Background(), orgID)
	if err != nil {
		t.Fatalf("list domains: %v", err)
	}
	if len(doms) != 0 {
		t.Fatalf("the domain row was persisted anyway: %+v", doms)
	}
}

func TestDomainAutoJoinRoleOwner_RefusedOnPatch(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID := seedAdminOrg(t, r, caller.ID)

	create := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/domains",
		map[string]any{"domain": "acme.example"})
	if create.StatusCode != http.StatusCreated {
		t.Fatalf("seed domain: got %d want 201", create.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	decode(t, create, &created)

	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/"+orgID+"/domains/"+created.ID,
		map[string]any{"default_role_on_auto_join": auth.RoleOwner})
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("PATCH default_role_on_auto_join=owner: got %d want 400", res.StatusCode)
	}

	d, err := r.GetOrganizationDomainByID(context.Background(), created.ID)
	if err != nil || d == nil {
		t.Fatalf("domain lookup: %v", err)
	}
	if d.DefaultRoleOnAutoJoin == auth.RoleOwner {
		t.Fatalf("the owner role was written to the domain row anyway")
	}
}

// Positive control: a non-owner default role is still configurable.
func TestDomainAutoJoinRoleAdmin_StillWorks(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID := seedAdminOrg(t, r, caller.ID)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/domains", map[string]any{
		"domain":                    "acme.example",
		"default_role_on_auto_join": auth.RoleAdmin,
	})
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("domain with default_role_on_auto_join=admin: got %d want 201", res.StatusCode)
	}
	doms, err := r.ListOrganizationDomainsByOrg(context.Background(), orgID)
	if err != nil || len(doms) != 1 || doms[0].DefaultRoleOnAutoJoin != auth.RoleAdmin {
		t.Fatalf("admin default role not persisted: %+v (%v)", doms, err)
	}
}

// --- the repository backstop ---------------------------------------------

// Even a caller that bypasses every handler cannot mint an owner without
// saying so explicitly. This is the invariant that covers the paths this file
// does not touch (SSO JIT, and any future one).
func TestRepoRefusesUnauthorizedOwnerMembership(t *testing.T) {
	_, r := newTestServer(t, seededUser())
	ctx := context.Background()
	now := time.Now().UTC()
	orgID := uuid.NewString()
	if _, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: "acme-repo", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	_, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: uuid.NewString(),
		Role: auth.RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	})
	if !errors.Is(err, yautherr.ErrOwnerProtected) {
		t.Fatalf("CreateMembership(owner) without authorization: got %v want ErrOwnerProtected", err)
	}

	// A plain member, then an attempt to promote them.
	memberID := uuid.NewString()
	m, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: memberID,
		Role: auth.RoleMember, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed member: %v", err)
	}
	ownerRole := auth.RoleOwner
	if _, err := r.UpdateMembership(ctx, m.ID, domain.UpdateMembership{Role: &ownerRole}); !errors.Is(err, yautherr.ErrOwnerProtected) {
		t.Fatalf("UpdateMembership(→owner) without authorization: got %v want ErrOwnerProtected", err)
	}
	after, err := r.GetMembershipByOrgUser(ctx, orgID, memberID)
	if err != nil || after == nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if after.Role != auth.RoleMember {
		t.Fatalf("role changed to %q despite the refusal", after.Role)
	}
}

// --- positive controls for the two legitimate owner paths -----------------

// Creating an organization still makes its creator the owner.
func TestCreateOrg_StillMintsAnOwner(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations",
		map[string]any{"name": "Acme", "slug": "acme-owner-control"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create org: got %d want 201", res.StatusCode)
	}
	var out struct {
		ID string `json:"id"`
	}
	decode(t, res, &out)

	m, err := r.GetMembershipByOrgUser(context.Background(), out.ID, caller.ID)
	if err != nil || m == nil {
		t.Fatalf("creator membership: %v", err)
	}
	if m.Role != auth.RoleOwner {
		t.Fatalf("creator role: got %q want owner", m.Role)
	}
}

// transfer-ownership still promotes the new owner and demotes the prior one.
func TestTransferOwnership_StillWorks(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	ctx := context.Background()

	create := doJSON(t, http.MethodPost, srv.URL+"/organizations",
		map[string]any{"name": "Acme", "slug": "acme-transfer-control"})
	if create.StatusCode != http.StatusCreated {
		t.Fatalf("create org: got %d want 201", create.StatusCode)
	}
	var org struct {
		ID string `json:"id"`
	}
	decode(t, create, &org)

	successor := uuid.NewString()
	now := time.Now().UTC()
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: org.ID, UserID: successor,
		Role: auth.RoleAdmin, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed successor: %v", err)
	}

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/transfer-ownership",
		map[string]any{"new_owner_user_id": successor})
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("transfer-ownership: got %d want 200", res.StatusCode)
	}

	newOwner, err := r.GetMembershipByOrgUser(ctx, org.ID, successor)
	if err != nil || newOwner == nil {
		t.Fatalf("successor membership: %v", err)
	}
	if newOwner.Role != auth.RoleOwner {
		t.Fatalf("successor role: got %q want owner", newOwner.Role)
	}
	prior, err := r.GetMembershipByOrgUser(ctx, org.ID, caller.ID)
	if err != nil || prior == nil {
		t.Fatalf("prior owner membership: %v", err)
	}
	if prior.Role != auth.RoleAdmin {
		t.Fatalf("prior owner role: got %q want admin", prior.Role)
	}
}
