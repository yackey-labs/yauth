// tenancy_audit_test.go — the org mutations that matter most, driven end to
// end, asserting a row actually lands.
//
// audit_coverage_test.go proves every mutating route CONTAINS an audit call by
// reading the source; that is what stops the next handler being added silently.
// It cannot prove the call runs, reaches the store, or carries the org scope —
// a call placed after an early return, or on a branch the happy path skips,
// would satisfy it. These cases close that gap for the highest-stakes
// operations by exercising the real HTTP surface and reading the audit log
// back.
//
// Each step uses Errorf rather than Fatalf so a failure names every silent
// operation instead of stopping at the first, and each is paired with a
// positive control asserting the mutation itself really happened — otherwise
// "no audit row" and "no mutation" look identical.
package organizations

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/domain"
)

// auditRowFor returns the newest audit row whose EventType matches, or nil.
func auditRowFor(rows []*domain.AuditLog, event string) *domain.AuditLog {
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].EventType == event {
			return rows[i]
		}
	}
	return nil
}

// TestOrgLifecycle_IsAudited covers create -> role change -> ownership
// transfer -> delete. Between them these are the operations that decide who
// controls a tenant, and every one of them wrote nothing before this change.
//
// Member ADD is exercised through the repo rather than the route: direct
// enrolment over HTTP is gated on consent or a verified domain, and that gate
// has its own suite. Its audit call is covered structurally by
// audit_coverage_test.go instead.
func TestOrgLifecycle_IsAudited(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	ctx := context.Background()

	// --- create -----------------------------------------------------------
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)

	rows := orgAuditRows(t, r)
	if auditRowFor(rows, "organization.created") == nil {
		t.Errorf("POST /organizations created a tenant and wrote no audit row (saw: %v)", orgAuditTypes(rows))
	}

	// The org id must be in the metadata: plugin.WriteAudit reads the scope
	// back out of it, and that is what routes the row to this org's own export
	// destinations. A row with no scope is invisible to the tenant it concerns.
	if row := auditRowFor(rows, "organization.created"); row != nil {
		if !strings.Contains(string(row.Metadata), org.ID) {
			t.Errorf("organization.created metadata does not carry the organization id, so the row "+
				"cannot be scoped to the org it describes: %s", string(row.Metadata))
		}
	}

	// --- add a second member ---------------------------------------------
	other, err := r.CreateUser(ctx, domain.NewUser{
		ID: "22222222-2222-4222-8222-222222222222", Email: "second@acme.test", Role: "user",
	})
	if err != nil {
		t.Fatalf("seed second user: %v", err)
	}
	// Direct enrolment over HTTP is gated on consent or a verified domain
	// (that gate is the subject of its own suite), so the membership is
	// created through the repo. What is under test here is the audit coverage
	// of the operations that follow, not the enrolment gate.
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: "33333333-3333-4333-8333-333333333333", OrganizationID: org.ID,
		UserID: other.ID, Role: "member", Status: domain.MembershipActive,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	// --- change their role ------------------------------------------------
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members/"+other.ID+"/role",
		map[string]any{"role": "admin"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("change role: %d", res.StatusCode)
	}
	res.Body.Close()
	if m, _ := r.GetMembershipByOrgUser(ctx, org.ID, other.ID); m == nil || m.Role != "admin" {
		t.Fatal("positive control: the role change did not take effect")
	}
	if rows = orgAuditRows(t, r); auditRowFor(rows, "organization.member_role_changed") == nil {
		t.Errorf("promoting a member to admin wrote no audit row (saw: %v)", orgAuditTypes(rows))
	}

	// --- transfer ownership ----------------------------------------------
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/transfer-ownership",
		map[string]any{"new_owner_user_id": other.ID})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("transfer ownership: %d", res.StatusCode)
	}
	res.Body.Close()
	if m, _ := r.GetMembershipByOrgUser(ctx, org.ID, other.ID); m == nil || m.Role != "owner" {
		t.Fatal("positive control: ownership did not actually move")
	}
	if rows = orgAuditRows(t, r); auditRowFor(rows, "organization.ownership_transferred") == nil {
		t.Errorf("TRANSFERRING OWNERSHIP OF A TENANT wrote no audit row (saw: %v)", orgAuditTypes(rows))
	}

	// --- delete the org ---------------------------------------------------
	res = doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+org.ID, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete org: %d", res.StatusCode)
	}
	res.Body.Close()
	if o, _ := r.GetOrganizationByID(ctx, org.ID); o != nil {
		t.Fatal("positive control: the organization was not actually deleted")
	}
	if rows = orgAuditRows(t, r); auditRowFor(rows, "organization.deleted") == nil {
		t.Errorf("DELETING AN ORGANIZATION wrote no audit row — the one event an investigator would "+
			"look for first (saw: %v)", orgAuditTypes(rows))
	}
}

// TestOrgGroupMutations_AreAudited covers the group surface, which is what
// actually grants application access: a group membership feeds
// UserInAssignedGroup and the id_token groups claim.
func TestOrgGroupMutations_AreAudited(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Beta", "slug": "beta"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)

	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/groups",
		map[string]any{"name": "engineers", "description": nil, "external_id": nil})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create group: %d", res.StatusCode)
	}
	var g groupJSON
	decode(t, res, &g)
	if rows := orgAuditRows(t, r); auditRowFor(rows, "organization.group_created") == nil {
		t.Errorf("creating a group wrote no audit row (saw: %v)", orgAuditTypes(rows))
	}

	// The group grants app access, so adding the caller to it is a grant.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/groups/"+g.ID+"/members",
		map[string]any{"user_id": user.ID})
	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusOK {
		t.Fatalf("add group member: %d", res.StatusCode)
	}
	res.Body.Close()
	if rows := orgAuditRows(t, r); auditRowFor(rows, "organization.group_member_added") == nil {
		t.Errorf("granting a user a group — which is what grants application access — wrote no audit "+
			"row (saw: %v)", orgAuditTypes(rows))
	}

	res = doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+org.ID+"/groups/"+g.ID, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete group: %d", res.StatusCode)
	}
	res.Body.Close()
	if rows := orgAuditRows(t, r); auditRowFor(rows, "organization.group_deleted") == nil {
		t.Errorf("deleting a group wrote no audit row (saw: %v)", orgAuditTypes(rows))
	}
}
