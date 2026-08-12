// cross_tenant_adoption_test.go — regression suite for the SCIM
// cross-tenant account takeover.
//
// POST /Users resolved an existing account with a GLOBAL GetUserByEmail and
// then adopted it. The "Anti-takeover" guard next to that lookup only fired
// when the request carried an externalId AND a SCIM link already existed in
// the CALLER's org — conditions a victim from another tenant never meets. So a
// SCIM key for org A, posting `{"userName": "victim@org-b.example"}`, minted an
// org-A membership for org B's user. That membership then satisfied
// requireUserInOrg, so PUT /Users/{id} could rewrite the victim's GLOBAL login
// email (→ password-reset takeover), and applyScimActiveLifecycle reached
// their GLOBAL account to suspend it and flush every session and refresh
// token.
//
// The cases below assert the REFUSAL — 409, no membership in the attacker's
// org, no suspension, no session flush — and are paired with positive controls
// for the flows SCIM legitimately needs: provisioning a brand-new address,
// re-provisioning an existing member, and claiming an address under a domain
// the org has verified.
package scim

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
)

// victimEmail is an address that exists globally but belongs to org B.
const victimEmail = "victim@other-tenant.example"

// seedVictimInOrgB provisions the victim through org B's own SCIM connector
// (the legitimate path) and returns their user id.
func seedVictimInOrgB(t *testing.T, app *testApp) string {
	t.Helper()
	resp := app.do(t, "POST", usersPath(app.orgB.orgID), app.orgB.apiKey, map[string]any{
		"schemas":    []string{CoreUserSchema},
		"userName":   victimEmail,
		"externalId": "okta-victim",
		"emails":     []map[string]any{{"value": victimEmail, "primary": true}},
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != 201 {
		t.Fatalf("seed victim in org B: got %d want 201", resp.StatusCode)
	}
	u, err := app.repo.GetUserByEmail(context.Background(), victimEmail)
	if err != nil || u == nil {
		t.Fatalf("victim not created: %v", err)
	}
	return u.ID
}

// assertNoOrgAFootprint checks that nothing the attacker posted took effect:
// no membership in their org, and the victim's global account untouched.
func assertNoOrgAFootprint(t *testing.T, app *testApp, victimID string) {
	t.Helper()
	ctx := context.Background()
	m, err := app.repo.GetMembershipByOrgUser(ctx, app.orgA.orgID, victimID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m != nil {
		t.Fatalf("victim was enrolled in the attacker's org: %+v", m)
	}
	u, err := app.repo.GetUserByID(ctx, victimID)
	if err != nil || u == nil {
		t.Fatalf("victim user lookup: %v", err)
	}
	if u.SuspendedAt != nil {
		t.Fatalf("victim's GLOBAL account was suspended by a foreign SCIM key")
	}
	if u.Email != victimEmail {
		t.Fatalf("victim's GLOBAL login email was rewritten to %q", u.Email)
	}
	mb, err := app.repo.GetMembershipByOrgUser(ctx, app.orgB.orgID, victimID)
	if err != nil {
		t.Fatalf("org B membership lookup: %v", err)
	}
	if mb == nil || mb.Status != domain.MembershipActive {
		t.Fatalf("victim's own org membership was disturbed: %+v", mb)
	}
}

// The bare attack: no externalId at all, which is precisely the shape the old
// guard could not see (it was nested inside `if payload.ExternalID != ""`).
func TestCrossTenantAdoption_NoExternalID_Refused(t *testing.T) {
	app := newTestApp(t)
	victimID := seedVictimInOrgB(t, app)

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": victimEmail,
	})
	if resp.StatusCode != 409 {
		t.Fatalf("status: got %d want 409", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["scimType"] != "uniqueness" {
		t.Fatalf("scimType: got %v want uniqueness", body["scimType"])
	}
	assertNoOrgAFootprint(t, app, victimID)
}

// With an externalId the old guard ran, but found no link in the attacker's
// org (the victim was never provisioned there) and so allowed adoption.
func TestCrossTenantAdoption_WithExternalID_Refused(t *testing.T) {
	app := newTestApp(t)
	victimID := seedVictimInOrgB(t, app)

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":    []string{CoreUserSchema},
		"userName":   victimEmail,
		"externalId": "attacker-chosen-id",
	})
	if resp.StatusCode != 409 {
		t.Fatalf("status: got %d want 409", resp.StatusCode)
	}
	assertNoOrgAFootprint(t, app, victimID)

	// The attacker must not have planted a SCIM link either — that would let
	// the next POST take the idempotent branch and skip the check entirely.
	links, err := app.repo.ListExternalIdentitiesByUser(context.Background(), victimID)
	if err != nil {
		t.Fatalf("list external identities: %v", err)
	}
	for _, l := range links {
		if l != nil && l.Provider == scimProvider(app.orgA.orgID) {
			t.Fatalf("attacker planted a SCIM link in their own org: %+v", l)
		}
	}
}

// The de-provision kill switch is global, so the takeover has a denial-of-
// service form that needs no follow-up request: POST active:false.
func TestCrossTenantAdoption_ActiveFalse_DoesNotSuspendVictim(t *testing.T) {
	app := newTestApp(t)
	victimID := seedVictimInOrgB(t, app)

	ctx := context.Background()
	sessionID := uuid.NewString()
	now := time.Now().UTC()
	if err := app.repo.CreateSession(ctx, domain.NewSession{
		ID:        sessionID,
		UserID:    victimID,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed victim session: %v", err)
	}

	active := false
	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": victimEmail,
		"active":   active,
	})
	if resp.StatusCode != 409 {
		t.Fatalf("status: got %d want 409", resp.StatusCode)
	}
	assertNoOrgAFootprint(t, app, victimID)

	s, err := app.repo.GetSessionByID(ctx, sessionID)
	if err != nil || s == nil {
		t.Fatalf("victim's session was flushed by a foreign SCIM key (err=%v)", err)
	}
}

// --- positive controls: the flows SCIM legitimately needs -----------------

// First-time provisioning of an address nobody holds must still work — that is
// the whole point of a provisioning API.
func TestProvisionBrandNewUser_StillSucceeds(t *testing.T) {
	app := newTestApp(t)
	const email = "brand-new@alpha.example"

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":    []string{CoreUserSchema},
		"userName":   email,
		"externalId": "okta-new",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("status: got %d want 201", resp.StatusCode)
	}
	resp.Body.Close() //nolint:errcheck

	ctx := context.Background()
	u, err := app.repo.GetUserByEmail(ctx, email)
	if err != nil || u == nil {
		t.Fatalf("user not created: %v", err)
	}
	m, err := app.repo.GetMembershipByOrgUser(ctx, app.orgA.orgID, u.ID)
	if err != nil || m == nil {
		t.Fatalf("membership not created: %v", err)
	}
}

// Re-POSTing someone who is already this org's member is normal IdP behaviour
// (re-provisioning after a de-provision) and must still be adopted.
func TestReProvisionExistingMember_StillAdopts(t *testing.T) {
	app := newTestApp(t)
	const email = "already-ours@alpha.example"

	first := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": email,
	})
	if first.StatusCode != 201 {
		t.Fatalf("first POST: got %d want 201", first.StatusCode)
	}
	first.Body.Close() //nolint:errcheck

	// Second POST, no externalId — the branch that must fall through to
	// adoption because the user already holds a membership in this org.
	second := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": email,
	})
	defer second.Body.Close() //nolint:errcheck
	if second.StatusCode != 201 {
		t.Fatalf("re-provision: got %d want 201", second.StatusCode)
	}
}

// A suspended member is still this org's own user; re-provisioning them (the
// reason SCIM sends active:true) must not be mistaken for a foreign adoption.
func TestReProvisionSuspendedMember_StillAdopts(t *testing.T) {
	app := newTestApp(t)
	const email = "offboarded@alpha.example"
	ctx := context.Background()

	create := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": email,
	})
	if create.StatusCode != 201 {
		t.Fatalf("create: got %d want 201", create.StatusCode)
	}
	create.Body.Close() //nolint:errcheck

	u, err := app.repo.GetUserByEmail(ctx, email)
	if err != nil || u == nil {
		t.Fatalf("user lookup: %v", err)
	}
	m, err := app.repo.GetMembershipByOrgUser(ctx, app.orgA.orgID, u.ID)
	if err != nil || m == nil {
		t.Fatalf("membership lookup: %v", err)
	}
	suspended := domain.MembershipSuspended
	if _, err := app.repo.UpdateMembership(ctx, m.ID, domain.UpdateMembership{Status: &suspended}); err != nil {
		t.Fatalf("suspend membership: %v", err)
	}

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": email,
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != 201 {
		t.Fatalf("re-provision suspended member: got %d want 201", resp.StatusCode)
	}
}

// An org that has VERIFIED a domain has proved control of that namespace, so
// it may claim an address under it even for an account it has never seen —
// the same proof plugins/organizations requires for domain auto-join.
func TestAdoptUnderVerifiedDomain_Allowed(t *testing.T) {
	app := newTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const email = "stray@claimed-by-alpha.example"

	// A pre-existing global account with no membership anywhere.
	u, err := app.repo.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed stray user: %v", err)
	}
	if _, err := app.repo.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
		ID:                uuid.NewString(),
		OrganizationID:    app.orgA.orgID,
		Domain:            "claimed-by-alpha.example",
		Status:            domain.DomainVerified,
		VerificationToken: "tok",
		CreatedAt:         now,
	}); err != nil {
		t.Fatalf("seed verified domain: %v", err)
	}

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": email,
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != 201 {
		t.Fatalf("verified-domain adoption: got %d want 201", resp.StatusCode)
	}
	m, err := app.repo.GetMembershipByOrgUser(ctx, app.orgA.orgID, u.ID)
	if err != nil || m == nil {
		t.Fatalf("membership not created under verified domain: %v", err)
	}
}

// A domain claim that is still PENDING proves nothing — DNS was never checked.
func TestAdoptUnderPendingDomain_Refused(t *testing.T) {
	app := newTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const email = "stray@unproven-by-alpha.example"

	u, err := app.repo.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed stray user: %v", err)
	}
	if _, err := app.repo.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
		ID:                uuid.NewString(),
		OrganizationID:    app.orgA.orgID,
		Domain:            "unproven-by-alpha.example",
		Status:            domain.DomainPending,
		VerificationToken: "tok",
		CreatedAt:         now,
	}); err != nil {
		t.Fatalf("seed pending domain: %v", err)
	}

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": email,
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != 409 {
		t.Fatalf("pending-domain adoption: got %d want 409", resp.StatusCode)
	}
	m, err := app.repo.GetMembershipByOrgUser(ctx, app.orgA.orgID, u.ID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m != nil {
		t.Fatalf("membership created on an unverified domain claim: %+v", m)
	}
}
