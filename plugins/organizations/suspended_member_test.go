// suspended_member_test.go — the HTTP-level half of the
// EffectiveOrgMembership status regression (the unit-level half lives in
// middleware/org_authz_status_test.go).
//
// Suspending a member used to leave every org-scoped route open to them,
// because middleware.EffectiveOrgMembership — the one gate this plugin routes
// through — returned the row without looking at Status. These cases drive the
// real handlers and assert both the 403 AND that no state moved.
package organizations

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// seedOrgWithMember plants an org, the caller's membership at the given role
// and status, and a second member for the caller to act on. Returns the org id
// and the victim's membership id.
func seedOrgWithMember(t *testing.T, r repo.Repository, callerID, role string, status domain.MembershipStatus) (orgID, victimID, victimMembershipID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	orgID = uuid.NewString()
	victimID = uuid.NewString()
	victimMembershipID = uuid.NewString()

	if _, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: "acme-" + orgID[:8], CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: callerID,
		Role: role, Status: status, CreatedAt: now, UpdatedAt: now,
		OwnerRoleAuthorized: true, // test fixture: seeds state directly
	}); err != nil {
		t.Fatalf("seed caller membership: %v", err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: victimMembershipID, OrganizationID: orgID, UserID: victimID,
		Role: auth.RoleMember, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed victim membership: %v", err)
	}
	return orgID, victimID, victimMembershipID
}

// The offboarding scenario: SCIM (or an admin) suspends the membership, an
// operator later clears only the GLOBAL suspension, and the user comes back
// still holding org-admin. They must not.
func TestSuspendedAdmin_CannotRemoveMembers(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID, victimID, _ := seedOrgWithMember(t, r, caller.ID, auth.RoleAdmin, domain.MembershipSuspended)

	res := doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+orgID+"/members/"+victimID, nil)
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("suspended admin removing a member: got %d want 403", res.StatusCode)
	}

	m, err := r.GetMembershipByOrgUser(context.Background(), orgID, victimID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m == nil {
		t.Fatalf("the victim was removed by a suspended admin")
	}
}

// The same authority, exercised through the role-change route.
func TestSuspendedAdmin_CannotChangeRoles(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID, victimID, _ := seedOrgWithMember(t, r, caller.ID, auth.RoleAdmin, domain.MembershipSuspended)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/members/"+victimID+"/role",
		map[string]any{"role": auth.RoleAdmin})
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("suspended admin changing a role: got %d want 403", res.StatusCode)
	}

	m, err := r.GetMembershipByOrgUser(context.Background(), orgID, victimID)
	if err != nil || m == nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m.Role != auth.RoleMember {
		t.Fatalf("role was escalated to %q by a suspended admin", m.Role)
	}
}

// An invitation is an offer. Holding one confers nothing until it is accepted.
func TestInvitedAdmin_CannotRemoveMembers(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID, victimID, _ := seedOrgWithMember(t, r, caller.ID, auth.RoleAdmin, domain.MembershipInvited)

	res := doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+orgID+"/members/"+victimID, nil)
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("invited admin removing a member: got %d want 403", res.StatusCode)
	}
	m, err := r.GetMembershipByOrgUser(context.Background(), orgID, victimID)
	if err != nil || m == nil {
		t.Fatalf("the victim was removed by an unaccepted invitation")
	}
}

// Positive control: an ACTIVE admin still administers their org.
func TestActiveAdmin_StillRemovesMembers(t *testing.T) {
	caller := seededUser()
	srv, r := newTestServer(t, caller)
	orgID, victimID, _ := seedOrgWithMember(t, r, caller.ID, auth.RoleAdmin, domain.MembershipActive)

	res := doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+orgID+"/members/"+victimID, nil)
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("active admin removing a member: got %d want 200", res.StatusCode)
	}
	m, err := r.GetMembershipByOrgUser(context.Background(), orgID, victimID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m != nil {
		t.Fatalf("active admin's removal did not take effect")
	}
}
