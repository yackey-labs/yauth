// group_offboarding_test.go — group membership was allowed to outlive the org
// membership that justified it, and could be granted to a member who was not
// active.
//
// Two halves of one invariant, "group membership ⊆ org membership":
//
//  1. Offboarding. DELETE /organizations/{id}/members/{user_id} lands in
//     registerRemoveMember (plugins/organizations/rbac_handlers.go), which
//     calls repo.DeleteMembership and nothing else. The group rows in
//     yauth_group_members are untouched — there is no FK cascade behind them
//     (migrate/postgres/001_initial.sql stores bare TEXT columns), and
//     RemoveGroupMember has only two production callers, neither on this
//     path. So after an admin offboards someone, repo.UserInAssignedGroup —
//     the exact call plugins/oauth2server/authorize.go:133 makes when a client
//     sets enforce_group_assignment — still answers true, and
//     ListGroupNamesForUser still puts the group in the id_token's groups
//     claim. The ex-member keeps app access.
//
//     The fix strips group rows for THIS org only. It deliberately does NOT
//     destroy the ex-member's sessions or refresh tokens, and
//     TestRemoveMember_LeavesAccountGlobalCredentialsAlone below pins that:
//     both are account-global artifacts (a user holds memberships in several
//     orgs; a domain.RefreshToken carries a ClientID that may belong to
//     another org's client or to first-party bearer login), so an org admin
//     reaching them would be a cross-tenant logout primitive. It is also
//     unnecessary — auth.ResolveActiveOrg, MembershipRoleResolver.RoleFor and
//     middleware.EffectiveOrgMembership all re-derive org authority per
//     request, so the surviving cookie confers nothing in the org.
//
//     KNOWN RESIDUAL, owned by the oauth2-revocation-is-cosmetic batch, not
//     this one: a refresh token minted BEFORE offboarding keeps working,
//     because grantRefreshToken (plugins/oauth2server/token.go) re-checks
//     clientGrantAllowed and CanAuthenticate but never re-checks
//     UserInAssignedGroup. That is token-revocation semantics and closing it
//     here with a global kill would buy a narrow win at the cost of letting
//     any org's admin sign a user out of every other tenant.
//
//  2. Granting. registerAddGroupMember (groups_handlers.go) enforces the
//     invariant with `if m == nil` and never looks at m.Status, so a SUSPENDED
//     or merely INVITED membership can still be dropped into a group — and
//     that group grants OAuth2 app access through UserInAssignedGroup even
//     though middleware.EffectiveOrgMembership refuses every non-active status
//     everywhere else.
//
// Each refusal below is paired with a positive control so a fix cannot pass by
// simply breaking groups, offboarding, or bystanders.
package organizations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// seedGroupAssignedToClient creates a group in orgID and assigns it to an
// OAuth2 client, mirroring an app that runs with enforce_group_assignment.
func seedGroupAssignedToClient(t *testing.T, r repo.Repository, orgID, name string) (groupID, clientID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	groupID = uuid.NewString()
	clientID = "client-" + uuid.NewString()[:8]

	if _, err := r.CreateGroup(ctx, domain.NewGroup{
		ID: groupID, OrganizationID: orgID, Name: name, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed group %s: %v", name, err)
	}
	if err := r.AssignClientGroup(ctx, clientID, groupID, now); err != nil {
		t.Fatalf("assign group to client: %v", err)
	}
	return groupID, clientID
}

// seedSession plants a live session row for userID and returns its id.
func seedSession(t *testing.T, r repo.Repository, userID string) string {
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

// seedRefreshToken plants a live refresh token for userID and returns its hash.
func seedRefreshToken(t *testing.T, r repo.Repository, userID string) string {
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

// createOrgAsOwner drives POST /organizations so the caller ends up owner.
func createOrgAsOwner(t *testing.T, srv string) string {
	t.Helper()
	res := doJSON(t, http.MethodPost, srv+"/organizations", map[string]string{
		"name": "Acme", "slug": "acme-" + uuid.NewString()[:8],
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close() //nolint:errcheck
		t.Fatalf("create org: %d body=%s", res.StatusCode, body)
	}
	var org organizationJSON
	decode(t, res, &org)
	return org.ID
}

// TestRemoveMember_ClearsGroupMemberships is the G4 offboarding case: the
// ex-member must lose the group grants that only their org membership
// justified. The assertion is on UserInAssignedGroup and ListGroupsForUser —
// the two reads that actually decide OAuth2 app access and the groups claim —
// not on the DELETE's status code.
func TestRemoveMember_ClearsGroupMemberships(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	ctx := context.Background()
	orgID := createOrgAsOwner(t, srv.URL)

	groupID, clientID := seedGroupAssignedToClient(t, r, orgID, "engineering")

	// The victim, and a colleague who stays — the positive control.
	victimID := "u-victim"
	stayerID := "u-stayer"
	seedMember(t, r, orgID, victimID, auth.RoleMember)
	seedMember(t, r, orgID, stayerID, auth.RoleMember)
	for _, uid := range []string{victimID, stayerID} {
		res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/groups/"+groupID+"/members",
			map[string]string{"user_id": uid})
		if res.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(res.Body)
			res.Body.Close() //nolint:errcheck
			t.Fatalf("add %s to group: %d body=%s", uid, res.StatusCode, body)
		}
		res.Body.Close() //nolint:errcheck
	}

	// CROSS-ORG CONTROL. The victim is also a member of a SECOND org, and in
	// a group there too. Offboarding them from org A must not touch org B —
	// a cleanup loop that enumerated every group the user belongs to (rather
	// than the org-filtered ListGroupsForUser) would pass every other
	// assertion in this test while quietly stripping an unrelated tenant's
	// grants.
	orgBID := createOrgAsOwner(t, srv.URL)
	groupBID, clientBID := seedGroupAssignedToClient(t, r, orgBID, "platform")
	seedMember(t, r, orgBID, victimID, auth.RoleMember)
	resB := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgBID+"/groups/"+groupBID+"/members",
		map[string]string{"user_id": victimID})
	if resB.StatusCode != http.StatusNoContent {
		bodyB, _ := io.ReadAll(resB.Body)
		resB.Body.Close() //nolint:errcheck
		t.Fatalf("add victim to org B group: %d body=%s", resB.StatusCode, bodyB)
	}
	resB.Body.Close() //nolint:errcheck

	// Sanity: the app gate lets both of them in while they are members.
	for _, uid := range []string{victimID, stayerID} {
		allowed, err := r.UserInAssignedGroup(ctx, clientID, uid)
		if err != nil {
			t.Fatalf("UserInAssignedGroup(%s): %v", uid, err)
		}
		if !allowed {
			t.Fatalf("precondition: %s should be assigned to the client before offboarding", uid)
		}
	}

	// Offboard the victim.
	res := doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+orgID+"/members/"+victimID, nil)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("remove member: got %d want 200 body=%s", res.StatusCode, body)
	}
	if m, err := r.GetMembershipByOrgUser(ctx, orgID, victimID); err != nil || m != nil {
		t.Fatalf("precondition: membership should be gone, got %+v err=%v", m, err)
	}

	// THE DEFECT: the group row outlives the membership row.
	groups, err := r.ListGroupsForUser(ctx, orgID, victimID)
	if err != nil {
		t.Fatalf("ListGroupsForUser: %v", err)
	}
	if len(groups) != 0 {
		names := make([]string, 0, len(groups))
		for _, g := range groups {
			names = append(names, g.Name)
		}
		t.Errorf("ex-member still holds group memberships in org %s: %v", orgID, names)
	}
	if member, err := r.IsGroupMember(ctx, groupID, victimID); err != nil {
		t.Fatalf("IsGroupMember: %v", err)
	} else if member {
		t.Errorf("ex-member is still a row in yauth_group_members for group %q", groupID)
	}
	// The read oauth2server/authorize.go makes under enforce_group_assignment.
	allowed, err := r.UserInAssignedGroup(ctx, clientID, victimID)
	if err != nil {
		t.Fatalf("UserInAssignedGroup(victim): %v", err)
	}
	if allowed {
		t.Errorf("ex-member still passes the client's group-assignment gate — /authorize would issue them a code")
	}
	// The read that fills the id_token / userinfo groups claim.
	names, err := r.ListGroupNamesForUser(ctx, victimID)
	if err != nil {
		t.Fatalf("ListGroupNamesForUser: %v", err)
	}
	for _, n := range names {
		if n == "engineering" {
			t.Errorf("ex-member's groups claim still carries %q", n)
		}
	}

	// POSITIVE CONTROL: the colleague who was not removed keeps everything.
	if allowed, err := r.UserInAssignedGroup(ctx, clientID, stayerID); err != nil {
		t.Fatalf("UserInAssignedGroup(stayer): %v", err)
	} else if !allowed {
		t.Fatalf("regression: offboarding the victim also revoked the remaining member's app access")
	}
	if gs, err := r.ListGroupsForUser(ctx, orgID, stayerID); err != nil {
		t.Fatalf("ListGroupsForUser(stayer): %v", err)
	} else if len(gs) != 1 {
		t.Fatalf("regression: remaining member should still hold 1 group, got %d", len(gs))
	}

	// POSITIVE CONTROL (cross-org): the victim's UNRELATED tenant is intact.
	// Org A's admin has no authority in org B.
	if member, err := r.IsGroupMember(ctx, groupBID, victimID); err != nil || !member {
		t.Errorf("offboarding from org A stripped the user's group in org B (err=%v) — the cleanup loop is not org-scoped", err)
	}
	if gs, err := r.ListGroupsForUser(ctx, orgBID, victimID); err != nil || len(gs) != 1 {
		t.Errorf("user should still hold 1 group in org B, got %d (err=%v)", len(gs), err)
	}
	if allowed, err := r.UserInAssignedGroup(ctx, clientBID, victimID); err != nil || !allowed {
		t.Errorf("offboarding from org A revoked the user's app access in org B (err=%v)", err)
	}
	if names, err := r.ListGroupNamesForUser(ctx, victimID); err != nil {
		t.Fatalf("ListGroupNamesForUser: %v", err)
	} else {
		found := false
		for _, n := range names {
			if n == "platform" {
				found = true
			}
		}
		if !found {
			t.Errorf("org B's group vanished from the user's groups claim: %v", names)
		}
	}
}

// TestRemoveMember_LeavesAccountGlobalCredentialsAlone is the OVER-REACH
// guard on the fix above, and it replaces an earlier
// TestRemoveMember_KillsSessionsAndRefreshTokens that asserted the opposite.
// That earlier test was wrong: it demanded that an org-scoped route call
// DeleteUserSessions(userID) and RevokeAllUserRefreshTokens(userID), both of
// which are ACCOUNT-global. A yauth session belongs to the account (it merely
// carries an active_org_id, and the same user may be a member of several orgs
// or of none), and a domain.RefreshToken carries a ClientID that may belong to
// a different org's client entirely. Making org A's admin able to trip them
// would hand every org admin a cross-tenant logout and DoS primitive against
// any user who happens to be in their org — the same shape of over-refusal
// that #96 established doctrine against.
//
// It is also unnecessary, and the second half of this test proves it: org
// authority is re-derived from the membership row on every single request, so
// the removal takes effect immediately without any session surgery.
//
// (SCIM's deprovision keeps its global kill — that key represents the
// workforce IdP and does hold account-level authority. See
// plugins/scim/group_offboarding_test.go.)
func TestRemoveMember_LeavesAccountGlobalCredentialsAlone(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	ctx := context.Background()
	orgID := createOrgAsOwner(t, srv.URL)

	victim := seededUser()
	victim.Email = "victim@example.com"
	stayerID := "u-stayer"
	seedMember(t, r, orgID, victim.ID, auth.RoleMember)
	seedMember(t, r, orgID, stayerID, auth.RoleMember)

	victimSession := seedSession(t, r, victim.ID)
	victimRefresh := seedRefreshToken(t, r, victim.ID)
	stayerSession := seedSession(t, r, stayerID)
	stayerRefresh := seedRefreshToken(t, r, stayerID)

	res := doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+orgID+"/members/"+victim.ID, nil)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("remove member: got %d want 200", res.StatusCode)
	}

	// (i) The account-global credentials must survive. An org admin has no
	// authority over the user's account, only over their membership.
	if s, err := r.GetSessionByID(ctx, victimSession); err != nil || s == nil {
		t.Errorf("an org admin destroyed an account-global session row (err=%v) — that signs the user out of every OTHER org and of their personal account", err)
	}
	if rt, err := r.GetRefreshTokenByHash(ctx, victimRefresh); err != nil || rt == nil || rt.Revoked {
		t.Errorf("an org admin revoked an account-global refresh token (err=%v) — domain.RefreshToken carries a ClientID that may belong to another org's client", err)
	}
	// Bystanders, obviously, must also be untouched.
	if s, err := r.GetSessionByID(ctx, stayerSession); err != nil || s == nil {
		t.Fatalf("regression: a bystander's session was destroyed by someone else's offboard (err=%v)", err)
	}
	if rt, err := r.GetRefreshTokenByHash(ctx, stayerRefresh); err != nil || rt == nil || rt.Revoked {
		t.Fatalf("regression: a bystander's refresh token was revoked by someone else's offboard (err=%v)", err)
	}

	// (ii) ...and the removal is nevertheless effective RIGHT NOW. A second
	// server over the same repo, authenticated as the victim, must be refused
	// every org-scoped route: requireOrgMember →
	// middleware.EffectiveOrgMembership re-reads the membership row per
	// request and there is no longer one. This is why no session surgery is
	// needed.
	victimSrv := newTestServerWithSharedRepo(t, victim, r)
	res = doJSON(t, http.MethodGet, victimSrv.URL+"/organizations/"+orgID+"/members", nil)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("ex-member reading org members: got %d want 403 body=%s", res.StatusCode, body)
	}

	// POSITIVE CONTROL: the same route from a member who was NOT removed
	// still works, so the 403 above is the missing membership and not a
	// blanket break of the endpoint.
	stayer := seededUser()
	stayer.Email = "stayer@example.com"
	seedMember(t, r, orgID, stayer.ID, auth.RoleAdmin)
	stayerSrv := newTestServerWithSharedRepo(t, stayer, r)
	res = doJSON(t, http.MethodGet, stayerSrv.URL+"/organizations/"+orgID+"/members", nil)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("regression: a current member can no longer read org members: got %d body=%s", res.StatusCode, body)
	}
}

// TestAddGroupMember_RefusesNonActiveMembership is G9: the handler's
// `if m == nil` check treats a suspended or invited membership as good enough
// to justify a group grant, and that grant is load-bearing for OAuth2 app
// access via UserInAssignedGroup.
func TestAddGroupMember_RefusesNonActiveMembership(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status domain.MembershipStatus
	}{
		{"suspended", domain.MembershipSuspended},
		{"invited", domain.MembershipInvited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := seededUser()
			srv, r := newTestServer(t, owner)
			ctx := context.Background()
			orgID := createOrgAsOwner(t, srv.URL)
			groupID, clientID := seedGroupAssignedToClient(t, r, orgID, "engineering")

			targetID := "u-target"
			now := time.Now().UTC()
			if _, err := r.CreateMembership(ctx, domain.NewMembership{
				ID: uuid.NewString(), OrganizationID: orgID, UserID: targetID,
				Role: auth.RoleMember, Status: tc.status, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatalf("seed %s membership: %v", tc.status, err)
			}

			res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/groups/"+groupID+"/members",
				map[string]string{"user_id": targetID})
			body, _ := io.ReadAll(res.Body)
			res.Body.Close() //nolint:errcheck
			if res.StatusCode != http.StatusConflict {
				t.Errorf("adding a %s member to a group: got %d want 409 body=%s", tc.status, res.StatusCode, body)
			}

			// Assert the grant, not just the status: no group row, and the
			// client's assignment gate still refuses them.
			if member, err := r.IsGroupMember(ctx, groupID, targetID); err != nil {
				t.Fatalf("IsGroupMember: %v", err)
			} else if member {
				t.Errorf("a %s member was written into yauth_group_members", tc.status)
			}
			if allowed, err := r.UserInAssignedGroup(ctx, clientID, targetID); err != nil {
				t.Fatalf("UserInAssignedGroup: %v", err)
			} else if allowed {
				t.Errorf("a %s member now passes the client's group-assignment gate", tc.status)
			}
		})
	}

	// POSITIVE CONTROL: an ACTIVE member is still addable and still gets the
	// app access the feature exists to grant.
	t.Run("active-still-works", func(t *testing.T) {
		owner := seededUser()
		srv, r := newTestServer(t, owner)
		ctx := context.Background()
		orgID := createOrgAsOwner(t, srv.URL)
		groupID, clientID := seedGroupAssignedToClient(t, r, orgID, "engineering")

		targetID := "u-target"
		seedMember(t, r, orgID, targetID, auth.RoleMember)

		res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/groups/"+groupID+"/members",
			map[string]string{"user_id": targetID})
		body, _ := io.ReadAll(res.Body)
		res.Body.Close() //nolint:errcheck
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("active member must still be addable: got %d want 204 body=%s", res.StatusCode, body)
		}
		if member, err := r.IsGroupMember(ctx, groupID, targetID); err != nil || !member {
			t.Fatalf("active member was not written into the group (err=%v)", err)
		}
		if allowed, err := r.UserInAssignedGroup(ctx, clientID, targetID); err != nil || !allowed {
			t.Fatalf("active member must pass the client's group-assignment gate (err=%v)", err)
		}
	})
}
