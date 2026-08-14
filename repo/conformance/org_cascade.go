package conformance

// Deleting an organization used to leave the access it granted behind.
//
// repo.OrganizationRepository documents DeleteOrganization as cascading to the
// org's children, and repo/repo.go tells implementors that SQL backends get
// that cascade "via FK ON DELETE CASCADE". migrate/postgres declares no foreign
// keys at all — every child column is bare TEXT — so the cascade is whatever
// each backend spells out by hand, and neither backend spells out groups.
// pgxrepo's DeleteOrganization deletes invitations, memberships, verified
// domains and org-scoped API keys and then the org row; memrepo deletes those
// four plus the org policy and the SSO connections. Nobody deletes
// yauth_groups, yauth_group_members, yauth_client_group_assignments or
// yauth_client_role_assignments.
//
// That matters because the OAuth2 access gate never looks at the organization.
// plugins/oauth2server/authorize.go (and device.go) call
// repo.UserInAssignedGroup(clientID, userID) when a client has
// enforce_group_assignment set, and that query is a two-table join from
// yauth_client_group_assignments to yauth_group_members — no yauth_groups, no
// yauth_memberships, no yauth_organizations. So an org whose row is gone keeps
// letting its former members through the gate of any client its groups were
// assigned to, keeps putting its group names in the id_token "groups" claim via
// ListGroupNamesForUser (which has no org predicate), and keeps injecting the
// per-app "roles" claim through ResolveUserRolesForClient's group_id path.
// None of those rows are reachable through the API any more — every group and
// SSO route gates on an org that now 404s — so an operator cannot even see the
// access they are still granting, let alone revoke it.
//
// DeleteGroup has the same defect one level down on pgx: queries/groups.sql is
// a bare `DELETE FROM yauth_groups WHERE id = $1`, so DELETE
// /organizations/{id}/groups/{gid} removes the group people can see and leaves
// the membership and client-assignment rows that actually decide access.
//
// On pgx only, the org's auth policy and its SSO connections survive too: a
// federated login into a deleted org still resolves its connection
// (plugins/ssooidc/handlers_login.go only checks Status == active), and
// re-creating an org under the same id — which idempotent provisioning does —
// silently resurrects the old policy.
//
// Every case below asserts the legitimate path FIRST: the gate must say yes
// while the org is alive. A "fix" that revokes group access outright, or that
// deletes another org's assignments off the same client, fails those
// assertions rather than passing the cascade ones by accident.

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// mustCreateOrgForCascade creates an organization or fails the test.
func mustCreateOrgForCascade(t *testing.T, r repo.Repository, id, name, slug string) {
	t.Helper()
	now := nowUTC()
	if _, err := r.CreateOrganization(ctx(), domain.NewOrganization{
		ID: id, Name: name, Slug: slug, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateOrganization(%s): %v", id, err)
	}
}

// mustCreateGroupForCascade creates a group in an org or fails the test.
func mustCreateGroupForCascade(t *testing.T, r repo.Repository, id, orgID, name string) {
	t.Helper()
	now := nowUTC()
	if _, err := r.CreateGroup(ctx(), domain.NewGroup{
		ID: id, OrganizationID: orgID, Name: name, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateGroup(%s): %v", id, err)
	}
}

// mustCreateGatedClient creates an OAuth2 client with the
// enforce_group_assignment access gate switched on.
func mustCreateGatedClient(t *testing.T, r repo.Repository, id, clientID string) {
	t.Helper()
	if err := r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
		ID:                     id,
		ClientID:               clientID,
		RedirectURIs:           json.RawMessage(`[]`),
		GrantTypes:             json.RawMessage(`[]`),
		Scopes:                 json.RawMessage(`[]`),
		CreatedAt:              nowUTC(),
		EnforceGroupAssignment: true,
	}); err != nil {
		t.Fatalf("CreateOAuth2Client(%s): %v", clientID, err)
	}
}

// mustGrantGroupAccess wires user -> group -> client, plus a group-scoped role
// assignment, and asserts the grant is live. This is the POSITIVE CONTROL that
// every cascade assertion below is measured against.
func mustGrantGroupAccess(t *testing.T, r repo.Repository, groupID, userID, clientID, roleAssignmentID, role string) {
	t.Helper()
	now := nowUTC()
	if err := r.AddGroupMember(ctx(), groupID, userID, now); err != nil {
		t.Fatalf("AddGroupMember(%s,%s): %v", groupID, userID, err)
	}
	if err := r.AssignClientGroup(ctx(), clientID, groupID, now); err != nil {
		t.Fatalf("AssignClientGroup(%s,%s): %v", clientID, groupID, err)
	}
	gid := groupID
	if err := r.AssignClientRole(ctx(), domain.NewClientRoleAssignment{
		ID: roleAssignmentID, ClientID: clientID, Role: role, GroupID: &gid, CreatedAt: now,
	}); err != nil {
		t.Fatalf("AssignClientRole(%s): %v", roleAssignmentID, err)
	}
	ok, err := r.UserInAssignedGroup(ctx(), clientID, userID)
	if err != nil {
		t.Fatalf("UserInAssignedGroup (positive control): %v", err)
	}
	if !ok {
		t.Fatalf("positive control failed: %s should reach client %s through group %s before any delete", userID, clientID, groupID)
	}
	roles, err := r.ResolveUserRolesForClient(ctx(), clientID, userID)
	if err != nil {
		t.Fatalf("ResolveUserRolesForClient (positive control): %v", err)
	}
	if !containsString(roles, role) {
		t.Fatalf("positive control failed: roles for %s on %s = %v, want %q", userID, clientID, roles, role)
	}
}

// groupIDsOf renders a []*domain.Group as its ids, so a failure message names
// the rows that survived instead of printing pointers.
func groupIDsOf(gs []*domain.Group) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.ID)
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

var orgCascadeCases = []testCase{
	// The headline case: an org is deleted, and every row that decides
	// access for its members has to go with it.
	{"delete_organization_revokes_group_access", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		mustCreateUser(t, r, "u1", "alice@example.com")
		mustCreateOrgForCascade(t, r, "o1", "Acme", "acme")
		mustCreateGroupForCascade(t, r, "g1", "o1", "engineers")
		mustCreateGatedClient(t, r, "c1", "client_gated")
		mustGrantGroupAccess(t, r, "g1", "u1", "client_gated", "cra1", "admin")

		if _, err := r.UpsertOrganizationPolicy(ctx(), "o1", domain.UpdateOrganizationPolicy{
			MfaRequired: ptr(true),
		}); err != nil {
			t.Fatalf("UpsertOrganizationPolicy: %v", err)
		}
		if _, err := r.CreateSsoConnection(ctx(), domain.NewSsoConnection{
			ID: "s1", OrganizationID: "o1", Kind: domain.ConnectionKindOIDCClient,
			Name: "acme-idp", Status: domain.ConnectionStatusActive,
			Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("CreateSsoConnection: %v", err)
		}

		if err := r.DeleteOrganization(ctx(), "o1"); err != nil {
			t.Fatalf("DeleteOrganization: %v", err)
		}

		// The group itself.
		if gs, err := r.ListGroupsByOrg(ctx(), "o1"); err != nil {
			t.Fatalf("ListGroupsByOrg: %v", err)
		} else if len(gs) != 0 {
			t.Errorf("groups survived the org: %v", groupIDsOf(gs))
		}
		// Its membership rows.
		if ok, err := r.IsGroupMember(ctx(), "g1", "u1"); err != nil {
			t.Fatalf("IsGroupMember: %v", err)
		} else if ok {
			t.Error("group membership survived the org")
		}
		// The access gate itself — this is what plugins/oauth2server asks.
		if ok, err := r.UserInAssignedGroup(ctx(), "client_gated", "u1"); err != nil {
			t.Fatalf("UserInAssignedGroup: %v", err)
		} else if ok {
			t.Error("deleted org's group still grants access to client_gated")
		}
		// The id_token "groups" claim.
		if ns, err := r.ListGroupNamesForUser(ctx(), "u1"); err != nil {
			t.Fatalf("ListGroupNamesForUser: %v", err)
		} else if len(ns) != 0 {
			t.Errorf("deleted org's group still in the groups claim: %v", ns)
		}
		// The client-group assignment row.
		if cgs, err := r.ListClientGroups(ctx(), "client_gated"); err != nil {
			t.Fatalf("ListClientGroups: %v", err)
		} else if len(cgs) != 0 {
			t.Errorf("client group assignment survived the org: %v", groupIDsOf(cgs))
		}
		// The per-app "roles" claim, injected through group_id.
		if roles, err := r.ResolveUserRolesForClient(ctx(), "client_gated", "u1"); err != nil {
			t.Fatalf("ResolveUserRolesForClient: %v", err)
		} else if len(roles) != 0 {
			t.Errorf("deleted org's group still injects roles: %v", roles)
		}
		// pgx-only divergence: policy and SSO connections.
		if _, err := r.GetOrganizationPolicy(ctx(), "o1"); !errors.Is(err, yautherr.ErrNotFound) {
			t.Errorf("org policy survived the org: err=%v want ErrNotFound", err)
		}
		if _, err := r.GetSsoConnectionByID(ctx(), "s1"); !errors.Is(err, yautherr.ErrNotFound) {
			t.Errorf("sso connection survived the org: err=%v want ErrNotFound", err)
		}
	}},

	// One level down: deleting a single group has to revoke what the group
	// granted, not just hide the group from the console.
	{"delete_group_revokes_access", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		mustCreateOrgForCascade(t, r, "o1", "Acme", "acme")
		mustCreateGroupForCascade(t, r, "g1", "o1", "engineers")
		mustCreateGatedClient(t, r, "c1", "client_gated")
		mustGrantGroupAccess(t, r, "g1", "u1", "client_gated", "cra1", "admin")

		if err := r.DeleteGroup(ctx(), "g1"); err != nil {
			t.Fatalf("DeleteGroup: %v", err)
		}

		if ok, err := r.IsGroupMember(ctx(), "g1", "u1"); err != nil {
			t.Fatalf("IsGroupMember: %v", err)
		} else if ok {
			t.Error("membership of the deleted group survived")
		}
		if ok, err := r.UserInAssignedGroup(ctx(), "client_gated", "u1"); err != nil {
			t.Fatalf("UserInAssignedGroup: %v", err)
		} else if ok {
			t.Error("deleted group still grants access to client_gated")
		}
		if cgs, err := r.ListClientGroups(ctx(), "client_gated"); err != nil {
			t.Fatalf("ListClientGroups: %v", err)
		} else if len(cgs) != 0 {
			t.Errorf("client group assignment survived the group: %v", groupIDsOf(cgs))
		}
		if roles, err := r.ResolveUserRolesForClient(ctx(), "client_gated", "u1"); err != nil {
			t.Fatalf("ResolveUserRolesForClient: %v", err)
		} else if len(roles) != 0 {
			t.Errorf("deleted group still injects roles: %v", roles)
		}
	}},

	// OVER-DELETION PIN. yauth_client_group_assignments and
	// yauth_client_role_assignments are keyed on client_id + group_id, and one
	// client is routinely assigned groups from several organizations. Deleting
	// o1 must not touch o2's rows on the same client.
	{"delete_organization_spares_other_orgs_grants", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		mustCreateUser(t, r, "u2", "bob@example.com")
		mustCreateOrgForCascade(t, r, "o1", "Acme", "acme")
		mustCreateOrgForCascade(t, r, "o2", "Globex", "globex")
		mustCreateGroupForCascade(t, r, "g1", "o1", "acme-engineers")
		mustCreateGroupForCascade(t, r, "g2", "o2", "globex-engineers")
		mustCreateGatedClient(t, r, "c1", "client_gated")
		mustGrantGroupAccess(t, r, "g1", "u1", "client_gated", "cra1", "admin")
		mustGrantGroupAccess(t, r, "g2", "u2", "client_gated", "cra2", "auditor")

		// o2 keeps a policy and an SSO connection of its own.
		if _, err := r.UpsertOrganizationPolicy(ctx(), "o2", domain.UpdateOrganizationPolicy{
			MfaRequired: ptr(true),
		}); err != nil {
			t.Fatalf("UpsertOrganizationPolicy(o2): %v", err)
		}
		now := nowUTC()
		if _, err := r.CreateSsoConnection(ctx(), domain.NewSsoConnection{
			ID: "s2", OrganizationID: "o2", Kind: domain.ConnectionKindOIDCClient,
			Name: "globex-idp", Status: domain.ConnectionStatusActive,
			Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("CreateSsoConnection(o2): %v", err)
		}

		if err := r.DeleteOrganization(ctx(), "o1"); err != nil {
			t.Fatalf("DeleteOrganization(o1): %v", err)
		}

		// o1's access is gone...
		if ok, err := r.UserInAssignedGroup(ctx(), "client_gated", "u1"); err != nil {
			t.Fatalf("UserInAssignedGroup(u1): %v", err)
		} else if ok {
			t.Error("deleted org o1 still grants access to client_gated")
		}
		// ...and o2's is untouched.
		if ok, err := r.IsGroupMember(ctx(), "g2", "u2"); err != nil {
			t.Fatalf("IsGroupMember(g2,u2): %v", err)
		} else if !ok {
			t.Error("over-deletion: surviving org o2 lost its group membership")
		}
		if ok, err := r.UserInAssignedGroup(ctx(), "client_gated", "u2"); err != nil {
			t.Fatalf("UserInAssignedGroup(u2): %v", err)
		} else if !ok {
			t.Error("over-deletion: surviving org o2 lost access to client_gated")
		}
		cgs, err := r.ListClientGroups(ctx(), "client_gated")
		if err != nil {
			t.Fatalf("ListClientGroups: %v", err)
		}
		if len(cgs) != 1 || cgs[0].ID != "g2" {
			t.Errorf("client group assignments after deleting o1: got %v, want exactly [g2]", groupIDsOf(cgs))
		}
		if roles, err := r.ResolveUserRolesForClient(ctx(), "client_gated", "u2"); err != nil {
			t.Fatalf("ResolveUserRolesForClient(u2): %v", err)
		} else if !containsString(roles, "auditor") {
			t.Errorf("over-deletion: surviving org o2 lost its role grant: %v", roles)
		}
		if ns, err := r.ListGroupNamesForUser(ctx(), "u2"); err != nil {
			t.Fatalf("ListGroupNamesForUser(u2): %v", err)
		} else if !containsString(ns, "globex-engineers") {
			t.Errorf("over-deletion: surviving org o2 lost its groups claim: %v", ns)
		}
		if _, err := r.GetOrganizationPolicy(ctx(), "o2"); err != nil {
			t.Errorf("over-deletion: surviving org o2 lost its policy: %v", err)
		}
		if _, err := r.GetSsoConnectionByID(ctx(), "s2"); err != nil {
			t.Errorf("over-deletion: surviving org o2 lost its SSO connection: %v", err)
		}
	}},
}
