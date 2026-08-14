// Regression suite for consentless direct org enrolment, and for the
// invitation rows nobody could list or revoke.
//
// POST /organizations/{id}/members (handlers.go registerAddMember) asked one
// question only: is the CALLER an org admin-or-higher, or an install-wide
// admin? It then looked the TARGET up by id and wrote them a membership with
// Status: MembershipActive and JoinedAt stamped. The target was never
// consulted, never notified, and no invitation row was ever involved.
//
// Nothing upstream makes that a privileged position. registerCreate has no
// role gate at all: any ordinary account POSTs /organizations and comes back
// the OWNER of a brand-new org. So the whole primitive is reachable from a
// role-"user" session plus one victim user id — and a user id is not a secret.
// It is the `sub` of every id_token yauth issues, it is in the member list of
// any shared org, and it is in the SCIM Users representation.
//
// What the manufactured membership then buys, in this codebase:
//
//   - GROUPS CLAIM POISONING. groups_handlers.go registerAddGroupMember
//     requires an ACTIVE membership before it will put a user in a group —
//     which the enrolment just manufactured. ListGroupNamesForUser carries NO
//     organization predicate, and plugins/oauth2server/token.go feeds it
//     straight into the id_token `groups` claim. The victim's next OIDC login
//     at ANY relying party then carries a group name the attacker chose.
//   - POLICY CAPTURE. auth.SelectDefaultActiveOrg picks the first active
//     membership by org name, so an early-sorting org name lands the victim's
//     next session on the ATTACKER's IPAllowlist, AllowedAuthMethods,
//     MaxSessionDuration and MfaRequired.
//   - The victim cannot undo it: removing a member is org-admin-gated, so only
//     the attacker can withdraw the membership the attacker created.
//
// The proof this suite asks for already exists in the library and is not
// reimplemented here: plugins/scim requireAdoptable admits a pre-existing
// account into an org when the address sits under a domain that org has
// VERIFIED, and auth.AutoJoinFromEmail is keyed on the same thing. A verified
// domain is this codebase's existing statement of "this namespace is mine".
// Absent that proof, enrolment must go through an invitation the target
// accepts.
//
// The second half of the file is the invitation surface itself. The repository
// has ListPendingInvitationsForOrg and DeleteInvitation on both backends, and
// NO route reaches either. plugin.go Routes registers create-invitation and
// accept-invitation and nothing else, so a mis-sent invitation stays live for
// the full InvitationTTL (7 days by default) with no way to see it and no way
// to revoke it.
//
// Every refusal below is paired with a positive control, because the failure
// mode of a fix here is locking legitimate operators out: the realm-flat
// console whose install admin manages one auto-managed org, the org that HAS
// verified its domain, and the org-scoped service account that automates
// membership for its own org must all keep working.
package organizations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
)

// seedVerifiedDomain claims emailDomain for orgID at the given status,
// bypassing the DNS round-trip the /verify route would perform. This is the
// same row auth.AutoJoinFromEmail and plugins/scim requireAdoptable read.
func seedVerifiedDomain(t *testing.T, r interface {
	CreateOrganizationDomain(ctx context.Context, input domain.NewOrganizationDomain) (domain.OrganizationDomain, error)
}, orgID, emailDomain string, status domain.DomainStatus) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID:                uuid.NewString(),
		OrganizationID:    orgID,
		Domain:            emailDomain,
		Status:            status,
		VerificationToken: "tok-" + uuid.NewString(),
		CreatedAt:         now,
		UpdatedAt:         now,
	}); err != nil {
		t.Fatalf("seed organization domain: %v", err)
	}
}

// createOrgAs POSTs /organizations on srv and returns the new org.
func createOrgAs(t *testing.T, srvURL, name, slug string) organizationJSON {
	t.Helper()
	res := doJSON(t, http.MethodPost, srvURL+"/organizations", map[string]string{"name": name, "slug": slug})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create org %q: status=%d body=%s", slug, res.StatusCode, body)
	}
	var org organizationJSON
	decode(t, res, &org)
	return org
}

// TestAddMember_RefusedWithoutVerifiedDomain is the verbatim exploit: an
// ordinary role-"user" account creates an org, then enrols a stranger by id.
func TestAddMember_RefusedWithoutVerifiedDomain(t *testing.T) {
	attacker := seededUser() // role "user" — no install-wide authority anywhere
	srv, r := newTestServer(t, attacker)

	org := createOrgAs(t, srv.URL, "Acme Corp", "acme-corp")
	victim := seedUser(t, r, "victim@othercorp.example")

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": victim.ID,
		"role":    RoleAdmin,
	})
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()

	if res.StatusCode != http.StatusForbidden {
		t.Errorf("an ordinary account enrolled a stranger into its own org with no consent "+
			"and no verified domain: status=%d body=%s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "allow_direct_member_enrollment") {
		t.Errorf("the refusal must name the escape hatch and the invitation route so an "+
			"operator learns both from the response; body=%s", body)
	}

	// The assertion that matters is STATE, not the status line: no membership
	// row may exist for the victim.
	m, err := r.GetMembershipByOrgUser(context.Background(), org.ID, victim.ID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m != nil {
		t.Fatalf("a membership row was written for a user who never consented: "+
			"role=%q status=%q joined_at=%v", m.Role, m.Status, m.JoinedAt)
	}
}

// TestAddMember_AllowedOnVerifiedDomain is the positive control for the
// headline case. Once the org has PROVED it owns othercorp.example — the same
// proof plugins/scim requireAdoptable and auth.AutoJoinFromEmail accept —
// direct enrolment of that domain's users must still work.
func TestAddMember_AllowedOnVerifiedDomain(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)

	org := createOrgAs(t, srv.URL, "Othercorp", "othercorp")
	seedVerifiedDomain(t, r, org.ID, "othercorp.example", domain.DomainVerified)
	target := seedUser(t, r, "staffer@othercorp.example")

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": target.ID,
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("an org that verified the target's email domain must still enrol them "+
			"directly: status=%d body=%s", res.StatusCode, body)
	}
	var m membershipJSON
	decode(t, res, &m)
	if m.Status != string(domain.MembershipActive) || m.JoinedAt == nil {
		t.Fatalf("verified-domain enrolment must still produce an ACTIVE, joined membership: %+v", m)
	}

	got, err := r.GetMembershipByOrgUser(context.Background(), org.ID, target.ID)
	if err != nil || got == nil {
		t.Fatalf("expected a persisted membership row, got %v (err=%v)", got, err)
	}
}

// TestAddMember_PendingDomainStillRefused pins that only a VERIFIED claim
// counts. A pending row is an unproved assertion — anyone may type any domain
// into POST /organizations/{id}/domains.
func TestAddMember_PendingDomainStillRefused(t *testing.T) {
	attacker := seededUser()
	srv, r := newTestServer(t, attacker)

	org := createOrgAs(t, srv.URL, "Acme Corp", "acme-corp")
	seedVerifiedDomain(t, r, org.ID, "othercorp.example", domain.DomainPending)
	victim := seedUser(t, r, "victim@othercorp.example")

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": victim.ID,
	})
	if res.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Errorf("a merely CLAIMED domain proved nothing, yet it enrolled the user: "+
			"status=%d body=%s", res.StatusCode, body)
	}
	m, err := r.GetMembershipByOrgUser(context.Background(), org.ID, victim.ID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m != nil {
		t.Fatal("a pending domain claim wrote a membership row")
	}
}

// TestAddMember_InstallAdminArmUntouched is the control for the population the
// risk note leads with: the realm-flat console driving this route as a global
// role-"admin" human with no membership anywhere. That arm must not change.
func TestAddMember_InstallAdminArmUntouched(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	org := createOrgAs(t, srv.URL, "Acme Corp", "acme-corp")
	target := seedUser(t, r, "newhire@nobody-verified-this.example")

	installAdmin := domain.User{
		ID: uuid.NewString(), Email: "root@example.com", Role: "admin",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	adminSrv := newServerSharingRepo(t, r, installAdmin)

	res := doJSON(t, http.MethodPost, adminSrv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": target.ID,
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("the install-admin arm is the realm-flat console path and must stay open: "+
			"status=%d body=%s", res.StatusCode, body)
	}
}

// TestAddMember_ServiceAccountStillRefused guards the existing carve-out at
// handlers.go: on a service-account principal au.User is the HUMAN who minted
// the key, so honouring au.User.Role would hand every key minted by an install
// admin the install-admin arm. The key here is org-admin for the org, which is
// exactly the caller org keys exist to be — so it is refused for the same
// reason a human org admin is, not for being a machine.
func TestAddMember_ServiceAccountStillRefused(t *testing.T) {
	human := seededUser()
	human.Role = "admin" // the key was minted by an install-wide admin
	srv, r := newTestServer(t, human)
	org := createOrgAs(t, srv.URL, "Acme Corp", "acme-corp")
	victim := seedUser(t, r, "victim@othercorp.example")

	orgAdmin := RoleAdmin
	sa := domain.NewServiceAccountPrincipal(org.ID, "key-1", human.ID)
	sa.Role = &orgAdmin
	saSrv := newTestServerWithSharedRepoAndPrincipal(t, &domain.AuthUser{User: human, Principal: sa}, r)

	res := doJSON(t, http.MethodPost, saSrv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": victim.ID,
	})
	if res.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Errorf("an org-scoped API key enrolled a stranger with no verified domain: "+
			"status=%d body=%s", res.StatusCode, body)
	}
	if m, err := r.GetMembershipByOrgUser(context.Background(), org.ID, victim.ID); err != nil {
		t.Fatalf("membership lookup: %v", err)
	} else if m != nil {
		t.Fatal("a service-account call wrote a consentless membership row")
	}
}

// TestAddMember_ServiceAccountAllowedOnVerifiedDomain is that test's positive
// control: the automation an org key exists to run keeps running for the users
// whose namespace the org has proved it owns.
func TestAddMember_ServiceAccountAllowedOnVerifiedDomain(t *testing.T) {
	human := seededUser()
	srv, r := newTestServer(t, human)
	org := createOrgAs(t, srv.URL, "Othercorp", "othercorp")
	seedVerifiedDomain(t, r, org.ID, "othercorp.example", domain.DomainVerified)
	target := seedUser(t, r, "staffer@othercorp.example")

	orgAdmin := RoleAdmin
	sa := domain.NewServiceAccountPrincipal(org.ID, "key-1", human.ID)
	sa.Role = &orgAdmin
	saSrv := newTestServerWithSharedRepoAndPrincipal(t, &domain.AuthUser{User: human, Principal: sa}, r)

	res := doJSON(t, http.MethodPost, saSrv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": target.ID,
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("an org-scoped API key must still provision members of a verified domain: "+
			"status=%d body=%s", res.StatusCode, body)
	}
}

// newServerWithConfig is newTestServer over an EXISTING repo with a non-zero
// plugin Config — the shared harness always builds New(Config{}), and the
// escape hatch is precisely a Config field. Kept local to this file so the
// shared harness stays untouched.
func newServerWithConfig(t *testing.T, r repo.Repository, user domain.User, cfg Config) *httptest.Server {
	t.Helper()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})
	mux := http.NewServeMux()
	New(cfg).(*orgsPlugin).Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestAddMember_EscapeHatch is the operator's way back to the old behaviour,
// and it is the control that keeps the gate from being un-turn-off-able: the
// realm-flat console that drives this API as an org owner holding the global
// role "user" sets plugins.organizations.allow_direct_member_enrollment and
// its provisioning keeps working, verified domain or not.
func TestAddMember_EscapeHatch(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	org := createOrgAs(t, srv.URL, "Acme Corp", "acme-corp")
	target := seedUser(t, r, "newhire@nobody-verified-this.example")

	hatched := newServerWithConfig(t, r, owner, Config{AllowDirectMemberEnrollment: true})
	res := doJSON(t, http.MethodPost, hatched.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": target.ID,
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("allow_direct_member_enrollment must restore the pre-release behaviour "+
			"verbatim: status=%d body=%s", res.StatusCode, body)
	}
	var m membershipJSON
	decode(t, res, &m)
	if m.Status != string(domain.MembershipActive) || m.JoinedAt == nil {
		t.Fatalf("the hatch must produce the same ACTIVE, joined membership as before: %+v", m)
	}

	// ...and it is per-deployment, not global state: the default server built
	// on the SAME repo still refuses.
	victim := seedUser(t, r, "victim@othercorp.example")
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": victim.ID,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("the gate is off by default and must stay on where the flag is unset: status=%d",
			res.StatusCode)
	}
}

// TestAddMemberRefusal_ComposesWithGroupGuard is the payoff: with enrolment
// refused, the ACTIVE membership the group guard demands never exists, so the
// id_token groups-claim path is closed at both ends.
func TestAddMemberRefusal_ComposesWithGroupGuard(t *testing.T) {
	attacker := seededUser()
	srv, r := newTestServer(t, attacker)
	org := createOrgAs(t, srv.URL, "Acme Corp", "acme-corp")
	victim := seedUser(t, r, "victim@othercorp.example")

	// Step 1 of the exploit: manufacture the membership.
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": victim.ID,
	})
	res.Body.Close()

	// Step 2: a group whose NAME the attacker chose.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/groups", map[string]any{
		"name": "platform-admins", "description": nil, "external_id": nil,
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create group: status=%d body=%s", res.StatusCode, body)
	}
	var g groupJSON
	decode(t, res, &g)

	// Step 3: the group membership that reaches the `groups` claim.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/groups/"+g.ID+"/members",
		map[string]string{"user_id": victim.ID})
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("the attacker put a stranger into an attacker-named group — that name reaches "+
			"the victim's id_token `groups` claim at every relying party: status=%d body=%s",
			res.StatusCode, body)
	}
	if !strings.Contains(string(body), "not an active member") {
		t.Errorf("expected the #102 active-membership guard to be what refuses; body=%s", body)
	}
}

// --- the invitation surface -------------------------------------------
//
// The invited path is what direct enrolment is being pointed AT, so it has to
// be a surface an operator can actually run: see what is outstanding, and take
// back a mis-sent invitation before its 7-day TTL expires.

// TestInvitationLifecycle_ListAndRevoke walks create → list → revoke → the
// token is dead.
func TestInvitationLifecycle_ListAndRevoke(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	org := createOrgAs(t, srv.URL, "Acme", "acme")

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/invitations", map[string]string{
		"email": "mistyped@wrong-company.example",
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create invitation: status=%d body=%s", res.StatusCode, body)
	}
	var created createInvitationResponse
	decode(t, res, &created)

	// List. An org admin cannot act on what they cannot see.
	res = doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/invitations", nil)
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("no route lists an organization's pending invitations, so a mis-sent one "+
			"stays live for the whole TTL unseen: status=%d body=%s", res.StatusCode, raw)
	}
	var list struct {
		Invitations []invitationJSON `json:"invitations"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("decode list: %v (body=%s)", err, raw)
	}
	if len(list.Invitations) != 1 || list.Invitations[0].Email != "mistyped@wrong-company.example" {
		t.Fatalf("expected exactly the one pending invitation, got %s", raw)
	}
	// The listing must never re-expose the bearer secret or its hash — the
	// create response is the ONLY place the token is ever shown.
	if strings.Contains(string(raw), "token") {
		t.Errorf("the invitation listing must carry no token and no token_hash; body=%s", raw)
	}

	// Revoke.
	invID := list.Invitations[0].ID
	res = doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+org.ID+"/invitations/"+invID, nil)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("no route revokes an invitation: status=%d body=%s", res.StatusCode, body)
	}

	// Gone from the listing...
	res = doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/invitations", nil)
	decode(t, res, &list)
	if len(list.Invitations) != 0 {
		t.Fatalf("revoked invitation still listed: %+v", list.Invitations)
	}

	// ...and, the assertion that matters, the TOKEN no longer redeems.
	stranger := domain.User{
		ID: uuid.NewString(), Email: "mistyped@wrong-company.example", Role: "user",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	strangerSrv := newTestServerWithSharedRepo(t, stranger, r)
	res = doJSON(t, http.MethodPost, strangerSrv.URL+"/invitations/accept", map[string]string{"token": created.Token})
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("a revoked invitation token still bought a membership: status=%d", res.StatusCode)
	}
	if m, err := r.GetMembershipByOrgUser(context.Background(), org.ID, stranger.ID); err != nil {
		t.Fatalf("membership lookup: %v", err)
	} else if m != nil {
		t.Fatal("a revoked invitation produced a membership row")
	}
}

// TestDeleteInvitation_CrossOrg pins the load-bearing half of the revoke
// route. Both repo backends take an invitation id ALONE and both are
// idempotent on a miss, so without an organization check any org admin
// anywhere revokes any other org's invitation by guessing or observing an id.
//
// The final leg is the positive control that keeps this test honest: org A's
// own admin must be able to revoke it, so the 404 above cannot be satisfied by
// the route simply not existing.
func TestDeleteInvitation_CrossOrg(t *testing.T) {
	ownerA := seededUser()
	srvA, r := newTestServer(t, ownerA)
	orgA := createOrgAs(t, srvA.URL, "Alpha", "alpha")

	res := doJSON(t, http.MethodPost, srvA.URL+"/organizations/"+orgA.ID+"/invitations", map[string]string{
		"email": "wanted@alpha.example",
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create invitation: status=%d body=%s", res.StatusCode, body)
	}
	var created createInvitationResponse
	decode(t, res, &created)
	invID := created.Invitation.ID

	// A wholly unrelated org, whose owner is an admin of nothing but itself.
	ownerB := domain.User{
		ID: uuid.NewString(), Email: "b@beta.example", Role: "user",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	srvB := newServerSharingRepo(t, r, ownerB)
	orgB := createOrgAs(t, srvB.URL, "Beta", "beta")

	res = doJSON(t, http.MethodDelete, srvB.URL+"/organizations/"+orgB.ID+"/invitations/"+invID, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("org B's admin reached org A's invitation by id: status=%d", res.StatusCode)
	}
	pending, err := r.ListPendingInvitationsForOrg(context.Background(), orgA.ID)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("org A's invitation was destroyed by another org's admin: pending=%d", len(pending))
	}

	// Positive control: org A's own admin revokes it.
	res = doJSON(t, http.MethodDelete, srvA.URL+"/organizations/"+orgA.ID+"/invitations/"+invID, nil)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the owning org's admin must be able to revoke its own invitation: "+
			"status=%d body=%s", res.StatusCode, body)
	}
	pending, err = r.ListPendingInvitationsForOrg(context.Background(), orgA.ID)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("revoke left the row in place: pending=%d", len(pending))
	}
}
