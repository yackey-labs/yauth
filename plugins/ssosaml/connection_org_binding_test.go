package ssosaml

// Regression suite for the missing binding between a SAML SsoConnection and
// the organization it belongs to.
//
// registerSamlACS resolves a connection, verifies the SAMLResponse against
// THAT connection's configured IdP certificate, and hands
// (provider, extID, email) to resolveOrJITUser. resolveOrJITUser never reads
// conn.OrganizationID, and the provider namespace it looks up is
// "saml:" + IssuerKeyFromEntityID(cfg.IdpEntityID) — keyed by the IdP entity
// ID the connection's own admin typed in, not by the connection or the org.
//
// Nothing enforces that an entity ID is unique across connections, or that
// the admin creating a connection has any claim to it: the entity ID lives
// inside the opaque encrypted config blob and has no DB constraint. So a
// second connection can name a first connection's entity ID while supplying
// its OWN signing certificate, and every identity federated under the first
// connection becomes reachable through the second:
//
//   1. Org A federates alice@example.com through its IdP. An ExternalIdentity
//      row is written under "saml:<idp-A-entity-id>" / her NameID.
//   2. An attacker signs up, POSTs /api/auth/organizations to become OWNER of
//      org B (registerCreate is gated only by RequireAuthHuma), and creates a
//      SAML connection whose idp_entity_id is byte-identical to org A's but
//      whose idp_x509_cert is their own self-signed cert, with
//      idp_initiated_sso_allowed=true, jit_provisioning_enabled=false and
//      allow_account_adoption=false.
//   3. They mint a SAMLResponse with their own key, Issuer set to that entity
//      ID and NameID alice@example.com, and POST it to the public ACS with
//      RelayState "cid:<connB>". ParseResponse verifies it against connB's
//      cert — the attacker's — and validateAssertion compares Issuer to
//      cfg.IdpEntityID, which the attacker chose. Both pass.
//   4. The provider key collides with org A's namespace, the existing-link
//      branch returns alice's user id after only a Banned check (before the
//      JIT gate, before the adoption gate), upsertMembership puts her in org
//      B, and auth.IssueSession Set-Cookies HER session to the attacker.
//
// The same missing check is what lets a case-variant address fork an
// identity: GetUserByEmail is byte-exact (yauth_users.email is TEXT UNIQUE
// and the query is `WHERE email = $1`), while emailpassword and magiclink
// lowercase everything, so an assertion carrying "Alice@example.com" misses
// alice@example.com, never reaches the adoption gate, and takes the CREATE
// branch instead.
//
// The refusals below assert on STATE — no session row, no Set-Cookie, no
// membership, no second user row — because a status code alone would not
// notice a session issued and then dropped. Each is paired with a positive
// control so a future "fix" cannot pass by breaking federation outright.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// --- helpers ----------------------------------------------------------

// joinOrg makes the user an active member of an organization — the
// relationship a connection's org has with the people it is entitled to
// federate.
func joinOrg(t *testing.T, f *e2eFixture, orgID, userID string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := f.repo.CreateMembership(context.Background(), domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: userID,
		Role: auth.RoleMember, Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

func sessionCountFor(t *testing.T, f *e2eFixture, userID string) int64 {
	t.Helper()
	uid := userID
	_, total, err := f.repo.ListSessions(context.Background(), domain.ListSessionsFilters{UserID: &uid, Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	return total
}

func accountsHolding(t *testing.T, f *e2eFixture, email string) int {
	t.Helper()
	users, _, err := f.repo.ListUsers(context.Background(), "", 1000, 0)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	n := 0
	for _, u := range users {
		if u != nil && strings.EqualFold(u.Email, email) {
			n++
		}
	}
	return n
}

// rogueOrg stands up a SECOND organization whose SAML connection claims the
// fixture IdP's entity ID while trusting a certificate the rogue operator
// controls. It returns the org, the connection, and the fake IdP that holds
// the matching private key.
//
// Everything here is reachable through the public admin API by any signed-up
// user: create an org (you are its OWNER), then POST a connection to it. The
// entity ID is a free-text field inside the encrypted config blob with no
// uniqueness constraint anywhere.
func rogueOrg(t *testing.T, f *e2eFixture, collidingEntityID string) (domain.Organization, domain.SsoConnection, *fakeIDP, *saml.ServiceProvider) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	org, err := f.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Rogue", Slug: "rogue",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create rogue org: %v", err)
	}

	// A second IdP with its own keypair, told to sign its assertions under the
	// VICTIM connection's entity ID.
	rogueIDP := newFakeIDP(t)
	rogueIDP.entityID = collidingEntityID
	rogueIDP.idp.MetadataURL = mustParseURL(collidingEntityID)

	cfg := SamlConnectionConfig{
		IdpEntityID:             collidingEntityID, // byte-identical to org A's
		IdpSsoURL:               rogueIDP.srv.URL + "/sso",
		IdpX509Cert:             rogueIDP.certPEM, // ...but the rogue's own cert
		AssertionSignedRequired: true,
		ResponseSignedRequired:  true,
		IdpInitiatedSsoAllowed:  true,  // no AuthnRequest needed
		AllowAccountAdoption:    false, // not even asking to adopt
		AttributeMappings: AttributeMappings{
			Email:      "urn:oid:0.9.2342.19200300.100.1.3",
			ExternalID: DefaultExternalIDFromNameID,
		},
	}
	raw, err := marshalSamlConfig(f.plugin.cfg.EncryptionKey, cfg)
	if err != nil {
		t.Fatalf("marshal rogue config: %v", err)
	}
	conn, err := f.repo.CreateSsoConnection(ctx, domain.NewSsoConnection{
		ID:                     uuid.NewString(),
		OrganizationID:         org.ID,
		Kind:                   domain.ConnectionKindSamlSP,
		Name:                   "Rogue SAML",
		Status:                 domain.ConnectionStatusActive,
		Config:                 raw,
		JitProvisioningEnabled: false, // JIT is OFF — nothing should be provisioned
		DefaultRoleOnJit:       auth.RoleMember,
		CreatedAt:              now,
		UpdatedAt:              now,
	})
	if err != nil {
		t.Fatalf("create rogue connection: %v", err)
	}

	sp, err := buildServiceProvider(&cfg, f.srv.URL, conn.ID)
	if err != nil {
		t.Fatalf("build rogue sp: %v", err)
	}
	rogueIDP.sp = sp
	rogueIDP.registeredSP = sp.Metadata()
	return org, conn, rogueIDP, sp
}

// --- the takeover -----------------------------------------------------

// TestSamlACS_RogueOrgConnectionCannotAssumeAnotherOrgsFederatedUser is the
// cross-tenant account takeover. Alice federates into org A; a connection in
// an unrelated org B, signed by an unrelated key, then presents her NameID and
// is handed her session.
func TestSamlACS_RogueOrgConnectionCannotAssumeAnotherOrgsFederatedUser(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	// --- Org A: one legitimate federated login. ---
	res := driveACS(t, f)
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		t.Fatalf("setup: org A login failed: %d %s", res.StatusCode, body)
	}
	_ = res.Body.Close()

	alice, err := f.repo.GetUserByEmail(ctx, theAssertedEmail)
	if err != nil || alice == nil {
		t.Fatalf("setup: alice was not provisioned: %v", err)
	}
	if ident, err := f.repo.GetExternalIdentityByProviderAndExternalID(ctx, providerKey(f), theAssertedEmail); err != nil || ident == nil {
		t.Fatalf("setup: no external identity for alice: %v", err)
	}
	sessionsBefore := sessionCountFor(t, f, alice.ID)

	// --- Org B: a rogue connection claiming org A's IdP entity ID. ---
	rogueOrgRow, rogueConn, rogueIDP, rogueSP := rogueOrg(t, f, f.idp.entityID)

	respB64, _ := rogueIDP.signedResponseFor(t, rogueSP, "", "")
	form := url.Values{
		"SAMLResponse": {respB64},
		"RelayState":   {"cid:" + rogueConn.ID},
	}
	acs, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatalf("rogue acs: %v", err)
	}
	defer func() { _ = acs.Body.Close() }()
	body, _ := io.ReadAll(acs.Body)

	if acs.StatusCode == http.StatusFound || acs.StatusCode == http.StatusOK {
		t.Errorf("rogue connection was accepted: status=%d body=%s", acs.StatusCode, body)
	}
	for _, c := range acs.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Errorf("alice's session cookie was handed to the rogue connection's caller")
		}
	}
	if got := sessionCountFor(t, f, alice.ID); got != sessionsBefore {
		t.Errorf("the rogue connection created %d session(s) for alice", got-sessionsBefore)
	}
	if m, err := f.repo.GetMembershipByOrgUser(ctx, rogueOrgRow.ID, alice.ID); err == nil && m != nil {
		t.Errorf("alice was made a %s of the rogue organization", m.Role)
	}
}

// POSITIVE CONTROL for the takeover: org A's OWN connection must keep signing
// alice in on the very same link. The existing-link branch is the one the
// refusal above narrows, and narrowing it too far would lock out every user
// who has ever federated.
func TestSamlACS_HomeOrgConnectionStillSignsInItsOwnFederatedUser(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	res := driveACS(t, f) // first login: JITs alice and mints her org A membership
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		t.Fatalf("first login: %d %s", res.StatusCode, body)
	}
	_ = res.Body.Close()

	alice, err := f.repo.GetUserByEmail(ctx, theAssertedEmail)
	if err != nil || alice == nil {
		t.Fatalf("alice was not provisioned: %v", err)
	}
	if m, err := f.repo.GetMembershipByOrgUser(ctx, f.org.ID, alice.ID); err != nil || m == nil {
		t.Fatalf("first login did not mint alice's membership in the connection's org: %v", err)
	}

	res2 := driveACS(t, f) // second login: resolves purely on the link
	defer func() { _ = res2.Body.Close() }()
	if res2.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res2.Body)
		t.Fatalf("a member of the connection's org was refused on her established link: %d %s", res2.StatusCode, body)
	}
	if sessionCountFor(t, f, alice.ID) < 2 {
		t.Fatalf("the second login issued no session")
	}
}

// POSITIVE CONTROL for the adoption branch: an operator who opts in to
// adoption, for someone who is already a member of the connection's
// organization, must still get the migration they asked for.
func TestSamlACS_MemberOfTheConnectionOrgStillLogsIn(t *testing.T) {
	f := newE2E(t)
	setAdoption(t, f, true)
	victim := seedVictim(t, f)
	joinOrg(t, f, f.org.ID, victim.ID)

	res := driveACS(t, f)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("adoption of an existing org member was refused: %d %s", res.StatusCode, body)
	}
	ident, err := f.repo.GetExternalIdentityByProviderAndExternalID(context.Background(), providerKey(f), theAssertedEmail)
	if err != nil || ident == nil || ident.UserID != victim.ID {
		t.Fatalf("the member's account was not linked: %+v (err=%v)", ident, err)
	}
	if sessionCountFor(t, f, victim.ID) == 0 {
		t.Fatalf("a legitimate adoption issued no session")
	}
}

// TestSamlACS_CaseVariantEmailDoesNotCreateAShadowAccount: the adoption gate
// is byte-exact, so an IdP asserting the same address in different case walks
// straight past it into the CREATE branch — producing a SECOND global account
// holding the same identity, stored with email_verified=true, on a connection
// whose allow_account_adoption is explicitly off.
func TestSamlACS_CaseVariantEmailDoesNotCreateAShadowAccount(t *testing.T) {
	f := newE2E(t) // AllowAccountAdoption defaults to false
	victim := seedVictim(t, f)

	// Same address, different bytes.
	f.idp.overrideEmail = "Alice@example.com"

	res := driveACS(t, f)
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)

	if n := accountsHolding(t, f, theAssertedEmail); n != 1 {
		t.Errorf("%d accounts now hold %s — a case-variant assertion forked the identity (acs: %d %s)",
			n, theAssertedEmail, res.StatusCode, body)
	}
	// And it must not have quietly signed anyone in as the new shadow account.
	if res.StatusCode == http.StatusFound {
		t.Errorf("a case-variant assertion signed in past allow_account_adoption=false")
	}
	if n := sessionCountFor(t, f, victim.ID); n != 0 {
		t.Errorf("%d session row(s) created for the real account", n)
	}
}
