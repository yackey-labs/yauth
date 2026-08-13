// group_offboarding_test.go — SCIM deprovision left the group grants standing.
//
// handleDeleteUser (plugins/scim/users.go) is the IdP's offboarding hook. It
// deletes the membership row, unlinks the SCIM external identity, terminates
// every session and revokes every refresh token — but it never touches
// yauth_group_members. There is no FK cascade behind those rows either
// (migrate/postgres/001_initial.sql stores bare TEXT columns), so the group
// membership simply outlives the org membership that justified it. The plugin
// states the invariant it breaks in its own comment on addMemberIfOrgMember
// (plugins/scim/groups.go): "group membership ⊆ org membership".
//
// That matters because DELETE deliberately does NOT set suspended_at — the
// comment in handleDeleteUser says so, to keep a later re-POST clean. So the
// account stays authenticatable: the user logs back in with their password,
// and repo.UserInAssignedGroup — the exact read plugins/oauth2server's
// /authorize makes when a client sets enforce_group_assignment — still says
// yes, off a group they were removed from the org for.
//
// The cleanup is scoped to ONE org: SCIM's key speaks for one tenant's
// directory, so a user who is also a member of another org keeps their groups
// there. The cross-org control below exists because a cleanup loop written
// over "every group this user is in" would satisfy every other assertion in
// this test while quietly stripping an unrelated tenant.
//
// Sessions and refresh tokens are a different matter and SCIM's existing
// global kill switch stays: unlike an org admin, the SCIM key represents the
// workforce IdP and does hold account-level authority over the identities it
// provisions. The positive controls below pin that it keeps firing.
//
// The second case covers the granting side of the same invariant:
// addMemberIfOrgMember checks only `m == nil`, so a SUSPENDED membership is
// still good enough to be written into a group, even though
// middleware.EffectiveOrgMembership refuses every non-active status. All three
// verbs that call it — POST, PUT and PATCH /Groups — are covered, and each
// asserts the request STILL SUCCEEDS: the skip has to stay silent, or one
// stale entry in an IdP's member push would fail the whole payload.
//
// Every refusal is paired with a positive control: a colleague who was not
// deprovisioned keeps their group and their app access, an active member is
// still addable by every verb, and SCIM's existing session/refresh kill switch
// must keep working.
package scim

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

func scimGroupPath(orgID, gid string) string { return groupsPath(orgID) + "/" + gid }

// createScimGroup drives POST /Groups with the given member ids and returns the
// created group's id. Accepts 201 only.
func createScimGroup(t *testing.T, app *testApp, name string, memberIDs ...string) string {
	t.Helper()
	members := make([]map[string]any, 0, len(memberIDs))
	for _, id := range memberIDs {
		members = append(members, map[string]any{"value": id})
	}
	resp := app.do(t, "POST", groupsPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreGroupSchema},
		"displayName": name,
		"members":     members,
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		t.Fatalf("create group %s: %d body=%s", name, resp.StatusCode, body)
	}
	m := decodeJSON(t, resp)
	gid, _ := m["id"].(string)
	if gid == "" {
		t.Fatalf("create group %s: no id in response %v", name, m)
	}
	return gid
}

// seedScimSession plants a live session row so the deprovision kill switch has
// something observable to destroy.
func seedScimSession(t *testing.T, r repo.Repository, userID string) string {
	t.Helper()
	id := uuid.NewString()
	if err := r.CreateSession(context.Background(), domain.NewSession{
		ID:        id,
		UserID:    userID,
		TokenHash: "hash-" + id,
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed session for %s: %v", userID, err)
	}
	return id
}

// seedScimRefreshToken plants a live refresh token for userID.
func seedScimRefreshToken(t *testing.T, r repo.Repository, userID string) string {
	t.Helper()
	hash := "rt-" + uuid.NewString()
	if err := r.CreateRefreshToken(context.Background(), domain.NewRefreshToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: hash,
		FamilyID:  uuid.NewString(),
		Scopes:    json.RawMessage(`["openid"]`),
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed refresh token for %s: %v", userID, err)
	}
	return hash
}

// TestScimDeleteUser_ClearsGroupMemberships is the S5 case: after the IdP
// deprovisions someone, no group row may survive to keep granting them app
// access or a groups claim.
func TestScimDeleteUser_ClearsGroupMemberships(t *testing.T) {
	app := newTestApp(t)
	ctx := context.Background()
	orgID := app.orgA.orgID

	victimID := seedScimUser(t, app, "victim@x.com")
	stayerID := seedScimUser(t, app, "stayer@x.com")
	groupID := createScimGroup(t, app, "engineering", victimID, stayerID)

	// The group gates an OAuth2 client with enforce_group_assignment.
	clientID := "client-" + uuid.NewString()[:8]
	if err := app.repo.AssignClientGroup(ctx, clientID, groupID, time.Now().UTC()); err != nil {
		t.Fatalf("assign group to client: %v", err)
	}
	for _, uid := range []string{victimID, stayerID} {
		if allowed, err := app.repo.UserInAssignedGroup(ctx, clientID, uid); err != nil || !allowed {
			t.Fatalf("precondition: %s should pass the client gate before deprovision (err=%v)", uid, err)
		}
	}

	// CROSS-ORG CONTROL. The same human is also an active member of org B and
	// in a group there. SCIM DELETE is scoped to one org's directory, so the
	// group cleanup must be too — a loop over every group the user belongs to
	// would pass every other assertion here while stripping org B's grants.
	joinOrg(t, app, app.orgB.orgID, victimID, "member", domain.MembershipActive)
	resp := app.do(t, "POST", groupsPath(app.orgB.orgID), app.orgB.apiKey, map[string]any{
		"schemas":     []string{CoreGroupSchema},
		"displayName": "platform",
		"members":     []map[string]any{{"value": victimID}},
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		t.Fatalf("create org B group: %d body=%s", resp.StatusCode, body)
	}
	groupBID, _ := decodeJSON(t, resp)["id"].(string)
	clientBID := "client-" + uuid.NewString()[:8]
	if err := app.repo.AssignClientGroup(ctx, clientBID, groupBID, time.Now().UTC()); err != nil {
		t.Fatalf("assign org B group to client: %v", err)
	}
	if allowed, err := app.repo.UserInAssignedGroup(ctx, clientBID, victimID); err != nil || !allowed {
		t.Fatalf("precondition: victim should pass org B's client gate (err=%v)", err)
	}

	victimSession := seedScimSession(t, app.repo, victimID)
	victimRefresh := seedScimRefreshToken(t, app.repo, victimID)

	resp = app.do(t, "DELETE", userPath(orgID, victimID), app.orgA.apiKey, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete user: got %d want 204 body=%s", resp.StatusCode, body)
	}
	if m, err := app.repo.GetMembershipByOrgUser(ctx, orgID, victimID); err != nil || m != nil {
		t.Fatalf("precondition: membership should be gone, got %+v err=%v", m, err)
	}

	// THE DEFECT: the group rows outlive the deleted membership.
	groups, err := app.repo.ListGroupsForUser(ctx, orgID, victimID)
	if err != nil {
		t.Fatalf("ListGroupsForUser: %v", err)
	}
	if len(groups) != 0 {
		names := make([]string, 0, len(groups))
		for _, g := range groups {
			names = append(names, g.Name)
		}
		t.Errorf("deprovisioned user still holds group memberships in org %s: %v", orgID, names)
	}
	if member, err := app.repo.IsGroupMember(ctx, groupID, victimID); err != nil {
		t.Fatalf("IsGroupMember: %v", err)
	} else if member {
		t.Errorf("deprovisioned user is still a row in yauth_group_members for group %q", groupID)
	}
	if allowed, err := app.repo.UserInAssignedGroup(ctx, clientID, victimID); err != nil {
		t.Fatalf("UserInAssignedGroup: %v", err)
	} else if allowed {
		t.Errorf("deprovisioned user still passes the client's group-assignment gate — and DELETE leaves the account unsuspended, so they can log back in and use it")
	}
	if names, err := app.repo.ListGroupNamesForUser(ctx, victimID); err != nil {
		t.Fatalf("ListGroupNamesForUser: %v", err)
	} else {
		for _, n := range names {
			if n == "engineering" {
				t.Errorf("deprovisioned user's groups claim still carries %q", n)
			}
		}
	}
	// The group's own membership projection must not list them either.
	getResp := app.do(t, "GET", scimGroupPath(orgID, groupID), app.orgA.apiKey, nil)
	if getResp.StatusCode != http.StatusOK {
		getResp.Body.Close() //nolint:errcheck
		t.Fatalf("get group: %d", getResp.StatusCode)
	}
	g := decodeJSON(t, getResp)
	if ms, ok := g["members"].([]any); ok {
		for _, raw := range ms {
			if mm, ok := raw.(map[string]any); ok && mm["value"] == victimID {
				t.Errorf("SCIM group %q still lists the deprovisioned user as a member", groupID)
			}
		}
	}

	// POSITIVE CONTROL 1: the existing kill switch must keep working.
	if s, err := app.repo.GetSessionByID(ctx, victimSession); err == nil && s != nil {
		t.Errorf("regression: SCIM deprovision no longer terminates sessions")
	}
	if rt, err := app.repo.GetRefreshTokenByHash(ctx, victimRefresh); err == nil && rt != nil && !rt.Revoked {
		t.Errorf("regression: SCIM deprovision no longer revokes refresh tokens")
	}

	// POSITIVE CONTROL 2: the colleague who was not deprovisioned is untouched.
	if allowed, err := app.repo.UserInAssignedGroup(ctx, clientID, stayerID); err != nil || !allowed {
		t.Fatalf("regression: deprovisioning one user revoked another's app access (err=%v)", err)
	}
	if gs, err := app.repo.ListGroupsForUser(ctx, orgID, stayerID); err != nil || len(gs) != 1 {
		t.Fatalf("regression: remaining member should still hold 1 group, got %d (err=%v)", len(gs), err)
	}

	// POSITIVE CONTROL 3 (cross-org): org B's directory is untouched. Org A's
	// SCIM key speaks for org A's IdP only.
	if member, err := app.repo.IsGroupMember(ctx, groupBID, victimID); err != nil || !member {
		t.Errorf("deprovisioning from org A stripped the user's group in org B (err=%v) — the cleanup loop is not org-scoped", err)
	}
	if gs, err := app.repo.ListGroupsForUser(ctx, app.orgB.orgID, victimID); err != nil || len(gs) != 1 {
		t.Errorf("user should still hold 1 group in org B, got %d (err=%v)", len(gs), err)
	}
	if allowed, err := app.repo.UserInAssignedGroup(ctx, clientBID, victimID); err != nil || !allowed {
		t.Errorf("deprovisioning from org A revoked the user's app access in org B (err=%v)", err)
	}
}

// TestScimCreateGroup_SkipsNonActiveMembership is the granting half:
// addMemberIfOrgMember accepts any membership row, so a suspended member is
// still written into the group and still passes the client's assignment gate.
func TestScimCreateGroup_SkipsNonActiveMembership(t *testing.T) {
	app := newTestApp(t)
	ctx := context.Background()
	orgID := app.orgA.orgID

	suspendedID := seedScimUser(t, app, "suspended@x.com")
	activeID := seedScimUser(t, app, "active@x.com")

	m, err := app.repo.GetMembershipByOrgUser(ctx, orgID, suspendedID)
	if err != nil || m == nil {
		t.Fatalf("lookup membership: %+v err=%v", m, err)
	}
	status := domain.MembershipSuspended
	now := time.Now().UTC()
	if _, err := app.repo.UpdateMembership(ctx, m.ID, domain.UpdateMembership{
		Status: &status, UpdatedAt: &now,
	}); err != nil {
		t.Fatalf("suspend membership: %v", err)
	}

	groupID := createScimGroup(t, app, "engineering", suspendedID, activeID)
	clientID := "client-" + uuid.NewString()[:8]
	if err := app.repo.AssignClientGroup(ctx, clientID, groupID, now); err != nil {
		t.Fatalf("assign group to client: %v", err)
	}

	if member, err := app.repo.IsGroupMember(ctx, groupID, suspendedID); err != nil {
		t.Fatalf("IsGroupMember: %v", err)
	} else if member {
		t.Errorf("a suspended member was written into yauth_group_members")
	}
	if allowed, err := app.repo.UserInAssignedGroup(ctx, clientID, suspendedID); err != nil {
		t.Fatalf("UserInAssignedGroup: %v", err)
	} else if allowed {
		t.Errorf("a suspended member now passes the client's group-assignment gate")
	}

	// POSITIVE CONTROL: the active member in the same request is still added
	// and still gets the app access the feature exists to grant.
	if member, err := app.repo.IsGroupMember(ctx, groupID, activeID); err != nil || !member {
		t.Fatalf("regression: an active member was not added to the group (err=%v)", err)
	}
	if allowed, err := app.repo.UserInAssignedGroup(ctx, clientID, activeID); err != nil || !allowed {
		t.Fatalf("regression: an active member must pass the client's group-assignment gate (err=%v)", err)
	}

	// addMemberIfOrgMember is shared by POST, PUT and PATCH /Groups, and the
	// skip must stay SILENT on all three: an IdP pushing a whole member list
	// that happens to contain one deactivated user must still have the rest of
	// the push applied, not get the payload rejected. So each verb below is
	// asserted twice — the request still succeeds AND the suspended user is
	// still not in the group, while the active member survives the round-trip.
	t.Run("put-skips-silently", func(t *testing.T) {
		resp := app.do(t, "PUT", scimGroupPath(orgID, groupID), app.orgA.apiKey, map[string]any{
			"schemas":     []string{CoreGroupSchema},
			"displayName": "engineering",
			"members": []map[string]any{
				{"value": suspendedID},
				{"value": activeID},
			},
		})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT /Groups with one suspended member must still succeed: got %d body=%s", resp.StatusCode, body)
		}
		if member, err := app.repo.IsGroupMember(ctx, groupID, suspendedID); err != nil {
			t.Fatalf("IsGroupMember: %v", err)
		} else if member {
			t.Errorf("PUT /Groups wrote a suspended member into yauth_group_members")
		}
		if member, err := app.repo.IsGroupMember(ctx, groupID, activeID); err != nil || !member {
			t.Fatalf("regression: PUT /Groups dropped the active member (err=%v)", err)
		}
	})

	t.Run("patch-skips-silently", func(t *testing.T) {
		resp := app.do(t, "PATCH", scimGroupPath(orgID, groupID), app.orgA.apiKey, map[string]any{
			"schemas": []string{PatchOpSchema},
			"Operations": []map[string]any{{
				"op":    "add",
				"path":  "members",
				"value": []map[string]any{{"value": suspendedID}},
			}},
		})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PATCH /Groups adding a suspended member must still succeed: got %d body=%s", resp.StatusCode, body)
		}
		if member, err := app.repo.IsGroupMember(ctx, groupID, suspendedID); err != nil {
			t.Fatalf("IsGroupMember: %v", err)
		} else if member {
			t.Errorf("PATCH /Groups wrote a suspended member into yauth_group_members")
		}
		if allowed, err := app.repo.UserInAssignedGroup(ctx, clientID, suspendedID); err != nil {
			t.Fatalf("UserInAssignedGroup: %v", err)
		} else if allowed {
			t.Errorf("a suspended member added via PATCH now passes the client's group-assignment gate")
		}
		// POSITIVE CONTROL: an active member added by the same verb IS added.
		newActiveID := seedScimUser(t, app, "active2@x.com")
		resp = app.do(t, "PATCH", scimGroupPath(orgID, groupID), app.orgA.apiKey, map[string]any{
			"schemas": []string{PatchOpSchema},
			"Operations": []map[string]any{{
				"op":    "add",
				"path":  "members",
				"value": []map[string]any{{"value": newActiveID}},
			}},
		})
		resp.Body.Close() //nolint:errcheck
		if member, err := app.repo.IsGroupMember(ctx, groupID, newActiveID); err != nil || !member {
			t.Fatalf("regression: PATCH /Groups no longer adds an active member (err=%v)", err)
		}
	})
}
