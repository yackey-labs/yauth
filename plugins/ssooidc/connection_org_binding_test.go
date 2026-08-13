// Regression suite for the missing binding between an SsoConnection and the
// organization it belongs to.
//
// registerSsoCallback resolves a connection, verifies the id_token against
// THAT connection's IdP, and then hands (provider, sub, email) to
// resolveOrJITUser. resolveOrJITUser never reads conn.OrganizationID. Two
// consequences fall out of that omission, both reachable from the public
// GET /api/auth/sso/callback:
//
//   - The existing-link branch (the first thing the function does) returns
//     u.ID after nothing but a Banned check. It runs BEFORE the
//     `if !conn.JitProvisioningEnabled` gate, and the caller then calls
//     upsertMembership unconditionally for an org-scoped connection. So any
//     user already linked in the "oidc:<issuer>" namespace — linked through a
//     DIFFERENT organization's connection to the same corporate IdP, or
//     through a global one — gets signed in through an invite-only
//     organization and minted a membership at that org's
//     default_role_on_jit. The org's jit_provisioning_enabled=false is not
//     consulted on that path at all.
//
//   - The adoption branch binds a pre-existing local account to an IdP
//     subject on the strength of the id_token's email_verified claim alone
//     (#82). That claim is written by whoever operates the IdP the connection
//     points at, and any authenticated user can create an organization and
//     wire a connection to an IdP they control. So "the IdP said it verified
//     victim@corp.example" is an attacker-controlled statement, and the
//     victim's session cookie lands in the attacker's browser. The connection
//     having an organization is the one piece of context that could have
//     said "this IdP has no relationship to this person" — and it is unused.
//
// Every refusal below is paired with a positive control, because the two
// shapes a careless fix breaks are (a) org-less GLOBAL connections, which
// mint no membership and must keep working for every "Sign in with <IdP>"
// install, and (b) first-time JIT of a user with no local account, which
// takes over nothing.
//
// Assertions are on state — session rows, membership rows, external-identity
// rows, the number of user rows — not just on the status code. A link written
// here is permanent: the existing-link branch finds it on every later attempt
// and never revisits any gate.
package ssooidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// --- helpers ----------------------------------------------------------

// providerFor is the ExternalIdentity provider namespace the callback derives
// from the connection's discovery URL. Note it is keyed by ISSUER, not by
// connection or organization — which is exactly why a link made through one
// org's connection is found by another's.
func providerFor(idp *fakeIDP) string {
	return "oidc:" + IssuerKeyFromDiscoveryURL(idp.issuer+"/.well-known/openid-configuration")
}

// linkUser pre-creates the (provider, sub) link that the first branch of
// resolveOrJITUser resolves on.
func linkUser(t *testing.T, r repo.Repository, idp *fakeIDP, userID, sub string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateExternalIdentity(context.Background(), domain.NewExternalIdentity{
		ID:          uuid.NewString(),
		UserID:      userID,
		Provider:    providerFor(idp),
		ExternalID:  sub,
		LinkedAt:    now,
		LastLoginAt: now,
	}); err != nil {
		t.Fatalf("pre-create external identity: %v", err)
	}
}

// joinOrg makes the user an active member of the connection's organization —
// the relationship the refusals below are missing.
func joinOrg(t *testing.T, r repo.Repository, orgID, userID string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: userID,
		Role: auth.RoleMember, Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

// claimDomainFor seeds an OrganizationDomain row in the given state. Claiming
// is self-assertion — the status is what says whether DNS ever backed it up.
func claimDomainFor(t *testing.T, r repo.Repository, orgID, dom string, status domain.DomainStatus) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: uuid.NewString(), OrganizationID: orgID, Domain: dom,
		Status: status, VerificationToken: "tok-" + dom,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed organization domain: %v", err)
	}
}

// verifyDomainFor seeds a DNS-verified domain claim — the second trust anchor
// the predicate accepts, and the same one the HRD selector already demands.
func verifyDomainFor(t *testing.T, r repo.Repository, orgID, dom string) {
	t.Helper()
	claimDomainFor(t, r, orgID, dom, domain.DomainVerified)
}

// membershipIn returns the user's membership row in the org, or nil.
func membershipIn(t *testing.T, r repo.Repository, orgID, userID string) *domain.Membership {
	t.Helper()
	m, err := r.GetMembershipByOrgUser(context.Background(), orgID, userID)
	if err != nil {
		return nil
	}
	return m
}

// setJIT rewrites the fixture connection's jit_provisioning_enabled flag.
func setJIT(t *testing.T, r repo.Repository, connID string, enabled bool) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.UpdateSsoConnection(context.Background(), connID, domain.UpdateSsoConnection{
		JitProvisioningEnabled: &enabled, UpdatedAt: &now,
	}); err != nil {
		t.Fatalf("update connection jit flag: %v", err)
	}
}

// accountsHolding counts user rows whose address equals the given one
// case-insensitively — the shape a shadow account takes.
func accountsHolding(t *testing.T, r repo.Repository, email string) int {
	t.Helper()
	users, _, err := r.ListUsers(context.Background(), "", 1000, 0)
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

// beginLoginConn is beginLogin driven by ?connection_id= instead of ?org=, so
// a global (org-less) connection can be exercised.
func beginLoginConn(t *testing.T, srv *httptest.Server, connID string) (state, nonce string) {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(srv.URL + "/sso/login?connection_id=" + url.QueryEscape(connID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login: %d %s", resp.StatusCode, body)
	}
	loc, _ := resp.Location()
	return loc.Query().Get("state"), loc.Query().Get("nonce")
}

// --- the refusals -----------------------------------------------------

// The hostile-IdP takeover. The attacker owns an organization (any
// authenticated user can create one) and wires its connection to an IdP they
// control; the IdP asserts the victim's address with email_verified=true,
// which is the ONLY gate on adoption. The victim has no membership in that
// organization and no verified organization domain vouches for the address —
// there is nothing tying this identity to this org — and the callback signs
// the attacker into the victim's account anyway.
func TestSsoCallback_RefusesAdoptionWhenUserIsNotInTheConnectionOrg(t *testing.T) {
	const victimEmail = "victim@corp.example"
	_, srv, r, conn, idp := setupForLogin(t)

	victim := seedExistingUser(t, r, victimEmail)

	idp.emailUnverified = false // the attacker's IdP happily "verifies" it
	idp.overrideEmail = victimEmail
	idp.overrideExtraSub = "attacker-owned-sub"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403, got %d %s", resp.StatusCode, body)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Errorf("the victim's session cookie was handed to the caller")
		}
	}
	if n := sessionCountFor(t, r, victim.ID); n != 0 {
		t.Errorf("%d session row(s) created for the victim", n)
	}
	// The link is the worst of it: once written, the existing-link branch
	// resolves on it forever and never looks at the address or the org again.
	if ident := ssoLinkFor(t, r, idp, "attacker-owned-sub"); ident != nil {
		t.Errorf("the victim's account was LINKED to the attacker's IdP subject (%s -> %s)", ident.ID, ident.UserID)
	}
	if m := membershipIn(t, r, conn.OrganizationID, victim.ID); m != nil {
		t.Errorf("the victim was made a %s of the connection's organization", m.Role)
	}
}

// POSITIVE CONTROL for the case above: the identical adoption, with the one
// thing that makes it legitimate — the account is already an active member of
// the connection's organization, so the org's admin-wired IdP is entitled to
// speak for it. This must keep returning 200 with a session and a link.
func TestSsoCallback_AdoptsWhenUserIsAMemberOfTheConnectionOrg(t *testing.T) {
	const email = "member@corp.example"
	_, srv, r, conn, idp := setupForLogin(t)

	existing := seedExistingUser(t, r, email)
	joinOrg(t, r, conn.OrganizationID, existing.ID)

	idp.overrideEmail = email
	idp.overrideExtraSub = "member-sub-1"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("a member of the connection's org was refused: %d %s", resp.StatusCode, body)
	}
	ident := ssoLinkFor(t, r, idp, "member-sub-1")
	if ident == nil || ident.UserID != existing.ID {
		t.Fatalf("the member's account was not linked: %+v", ident)
	}
	if sessionCountFor(t, r, existing.ID) == 0 {
		t.Fatalf("a legitimate adoption issued no session")
	}
}

// The invite-only bypass. The organization has switched JIT provisioning OFF —
// its stated policy is that only invited accounts get in. A user who is
// already linked in this issuer's namespace (through some other org's
// connection to the same corporate IdP, or through a global one) loads the
// PUBLIC login route pointed at this org and is signed in and given a
// membership, because the existing-link branch returns before the JIT gate is
// ever read.
func TestSsoCallback_JitDisabledDoesNotMintMembershipForAnExistingLink(t *testing.T) {
	const outsiderEmail = "outsider@elsewhere.example"
	_, srv, r, conn, idp := setupForLogin(t)

	outsider := seedExistingUser(t, r, outsiderEmail)
	linkUser(t, r, idp, outsider.ID, "outsider-sub-1") // link made elsewhere
	setJIT(t, r, conn.ID, false)                       // org is invite-only

	idp.overrideEmail = outsiderEmail
	idp.overrideExtraSub = "outsider-sub-1"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403 for an outsider at a JIT-disabled org, got %d %s", resp.StatusCode, body)
	}
	if m := membershipIn(t, r, conn.OrganizationID, outsider.ID); m != nil {
		t.Errorf("an invite-only organization minted a %s membership for a non-member", m.Role)
	}
	if n := sessionCountFor(t, r, outsider.ID); n != 0 {
		t.Errorf("%d session row(s) issued into an invite-only organization", n)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Errorf("a session cookie was issued into an invite-only organization")
		}
	}
}

// POSITIVE CONTROL for the case above: the same established link, for a user
// who IS a member of the org, must still sign in after JIT is switched off.
// Turning off JIT provisioning is not supposed to lock out the people already
// provisioned.
func TestSsoCallback_JitDisabledStillSignsInAnEstablishedMember(t *testing.T) {
	const memberEmail = "established@corp.example"
	_, srv, r, conn, idp := setupForLogin(t)

	member := seedExistingUser(t, r, memberEmail)
	joinOrg(t, r, conn.OrganizationID, member.ID)
	linkUser(t, r, idp, member.ID, "established-sub-1")
	setJIT(t, r, conn.ID, false)

	idp.overrideEmail = memberEmail
	idp.overrideExtraSub = "established-sub-1"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("an established member was locked out by jit_provisioning_enabled=false: %d %s", resp.StatusCode, body)
	}
	if sessionCountFor(t, r, member.ID) == 0 {
		t.Fatalf("an established member got no session")
	}
}

// The case-variant shadow account. yauth_users.email is byte-exact UNIQUE and
// GetUserByEmail is `WHERE email = $1`, while emailpassword and magiclink
// lowercase everything they touch. The callback passes the email claim through
// verbatim, so an IdP asserting "Victim@corp.example" misses
// victim@corp.example entirely, never reaches the adoption gate, and takes the
// CREATE branch — a second global account holding the same address, with
// email_verified inherited from the IdP.
func TestSsoCallback_CaseVariantEmailDoesNotCreateAShadowAccount(t *testing.T) {
	const victimEmail = "victim@corp.example"
	_, srv, r, conn, idp := setupForLogin(t)

	victim := seedExistingUser(t, r, victimEmail)
	joinOrg(t, r, conn.OrganizationID, victim.ID) // even a legitimate member

	idp.overrideEmail = "Victim@corp.example" // same address, different bytes
	idp.overrideExtraSub = "case-variant-sub"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if n := accountsHolding(t, r, victimEmail); n != 1 {
		t.Errorf("%d accounts now hold %s — a case-variant assertion forked the identity (callback: %d %s)",
			n, victimEmail, resp.StatusCode, body)
	}
	if ident := ssoLinkFor(t, r, idp, "case-variant-sub"); ident != nil && ident.UserID != victim.ID {
		t.Errorf("the case-variant assertion linked to a different account (%s) than the real one (%s)", ident.UserID, victim.ID)
	}
}

// POSITIVE CONTROL for the second anchor: an organization that has DNS-verified
// the account's own email domain may self-serve it in without a prior
// invitation. This is the escape hatch for the behaviour break the predicate
// introduces — an install whose users federate into an org through a shared
// corporate IdP with no invitation now gets a 403 until either an admin adds
// them or the org verifies its domain — so it must be exercised, not assumed.
// The row has to be VERIFIED and owned by THIS org: anyone can claim a domain,
// only DNS proves it.
func TestSsoCallback_AdoptsWhenTheOrgHasVerifiedTheEmailDomain(t *testing.T) {
	const email = "newjoiner@corp.example"
	_, srv, r, conn, idp := setupForLogin(t)

	existing := seedExistingUser(t, r, email) // no membership at all
	verifyDomainFor(t, r, conn.OrganizationID, "corp.example")

	idp.overrideEmail = email
	idp.overrideExtraSub = "domain-vouched-sub"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("an org that verified the account's email domain was refused: %d %s", resp.StatusCode, body)
	}
	ident := ssoLinkFor(t, r, idp, "domain-vouched-sub")
	if ident == nil || ident.UserID != existing.ID {
		t.Fatalf("the domain-vouched account was not linked: %+v", ident)
	}
	if sessionCountFor(t, r, existing.ID) == 0 {
		t.Fatalf("a domain-vouched adoption issued no session")
	}
	if m := membershipIn(t, r, conn.OrganizationID, existing.ID); m == nil {
		t.Fatalf("a domain-vouched adoption did not mint the org membership")
	}
}

// And the negative half of the same anchor: a domain row that exists but has
// NOT been verified vouches for nobody. Claiming a domain is unauthenticated
// self-assertion; only the DNS TXT check turns it into a trust anchor.
func TestSsoCallback_UnverifiedOrgDomainDoesNotVouchForAnAccount(t *testing.T) {
	const email = "pending@corp.example"
	_, srv, r, conn, idp := setupForLogin(t)

	victim := seedExistingUser(t, r, email)
	claimDomainFor(t, r, conn.OrganizationID, "corp.example", domain.DomainPending)

	idp.overrideEmail = email
	idp.overrideExtraSub = "pending-domain-sub"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("an UNVERIFIED domain claim was accepted as proof: %d %s", resp.StatusCode, body)
	}
	if ident := ssoLinkFor(t, r, idp, "pending-domain-sub"); ident != nil {
		t.Errorf("an unverified domain claim linked the account: %+v", ident)
	}
	if n := sessionCountFor(t, r, victim.ID); n != 0 {
		t.Errorf("%d session row(s) issued on an unverified domain claim", n)
	}
}

// POSITIVE CONTROL for the org predicate as a whole: a GLOBAL (org-less)
// connection is wired by an install admin, mints no membership, and has no
// organization to check against. It must short-circuit to "allowed" — every
// single-IdP "Sign in with <IdP>" deployment depends on this path binding a
// pre-existing local account.
func TestSsoCallback_GlobalConnectionStillBindsAPreExistingAccount(t *testing.T) {
	const email = "solo@corp.example"
	p, srv, r, _, idp := setupForLogin(t)

	globalConn, err := SeedConnection(context.Background(), r, p.cfg.EncryptionKey, SeedConnectionInput{
		OrganizationID:         "", // global — no org to belong to
		Name:                   "Global IdP",
		JitProvisioningEnabled: true,
		OIDC: OidcConnectionConfig{
			DiscoveryURL: idp.issuer + "/.well-known/openid-configuration",
			ClientID:     "rp-1",
			ClientSecret: "rp-secret",
		},
	})
	if err != nil {
		t.Fatalf("seed global connection: %v", err)
	}

	existing := seedExistingUser(t, r, email)
	idp.overrideEmail = email
	idp.overrideExtraSub = "global-sub-1"

	state, nonce := beginLoginConn(t, srv, globalConn.ID)
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("a global org-less connection was refused: %d %s", resp.StatusCode, body)
	}
	ident := ssoLinkFor(t, r, idp, "global-sub-1")
	if ident == nil || ident.UserID != existing.ID {
		t.Fatalf("global connection did not bind the pre-existing account: %+v", ident)
	}
	if sessionCountFor(t, r, existing.ID) == 0 {
		t.Fatalf("global connection issued no session")
	}
}

// POSITIVE CONTROL for the CREATE branch: a brand-new employee with no local
// account is still JIT-provisioned into the org. Creating an account takes
// nothing over, so it was never the problem, and breaking it stops onboarding.
func TestSsoCallback_FirstTimeJitOfANewUserStillWorks(t *testing.T) {
	const email = "newhire@corp.example"
	_, srv, r, conn, idp := setupForLogin(t)

	idp.overrideEmail = email
	idp.overrideExtraSub = "newhire-sub-1"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("first-time JIT was refused: %d %s", resp.StatusCode, body)
	}
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("no JIT user created: %v", err)
	}
	if m := membershipIn(t, r, conn.OrganizationID, u.ID); m == nil {
		t.Fatalf("first-time JIT did not mint the org membership")
	}
}
