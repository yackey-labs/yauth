// Regression suite for SSO account adoption on an unverified email.
//
// resolveOrJITUser is handed the id_token's email_verified claim, and used it
// only when CREATING a user. When an existing account matched by email it
// linked and signed in without ever consulting it — the same hole the oauth
// plugin's callback had until #81.
//
// SSO connections being admin-wired per organization is thinner mitigation
// than it sounds: an IdP that permits self-registration with unverified
// addresses lets an attacker register victim@corp.example there and be bound
// to the victim's existing yauth account.
//
// Each case asserts the REFUSAL where it counts — no session, no cookie, and
// no external-identity row a later login could ride in on — and is paired with
// the two branches that must keep working.
package ssooidc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// ssoLinkFor returns the external-identity row for the fixture IdP's subject,
// or nil when none was written.
func ssoLinkFor(t *testing.T, r repo.Repository, idp *fakeIDP, sub string) *domain.ExternalIdentity {
	t.Helper()
	provider := "oidc:" + IssuerKeyFromDiscoveryURL(idp.issuer+"/.well-known/openid-configuration")
	ident, err := r.GetExternalIdentityByProviderAndExternalID(context.Background(), provider, sub)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil
		}
		t.Fatalf("GetExternalIdentityByProviderAndExternalID: %v", err)
	}
	return ident
}

// sessionCountFor counts live session rows for a user.
func sessionCountFor(t *testing.T, r repo.Repository, userID string) int64 {
	t.Helper()
	uid := userID
	_, total, err := r.ListSessions(context.Background(), domain.ListSessionsFilters{UserID: &uid, Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	return total
}

// seedExistingUser puts an account in the store that the IdP did NOT create —
// the victim of the takeover.
func seedExistingUser(t *testing.T, r repo.Repository, email string) domain.User {
	t.Helper()
	now := time.Now().UTC()
	u, err := r.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed existing user: %v", err)
	}
	return u
}

// The takeover: the attacker self-registers the victim's address at an IdP
// that does not verify addresses, and the callback binds them to the victim's
// existing account. Refusing means 403, no cookie, no session, and no link.
func TestSsoCallback_RefusesUnverifiedEmailAdoption(t *testing.T) {
	const victimEmail = "victim@corp.example"
	_, srv, r, _, idp := setupForLogin(t)

	victim := seedExistingUser(t, r, victimEmail)
	before := sessionCountFor(t, r, victim.ID)

	idp.emailUnverified = true
	idp.overrideEmail = victimEmail
	idp.overrideExtraSub = "attacker-sub-1"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d %s", resp.StatusCode, body)
	}

	// No cookie.
	for _, c := range resp.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Fatalf("a refused adoption still set a session cookie")
		}
	}
	// No session row — the cookie check alone would miss a session issued
	// and then dropped on the floor.
	if got := sessionCountFor(t, r, victim.ID); got != before {
		t.Fatalf("a refused adoption created %d session(s) for the victim", got-before)
	}
	// No link. This is the one that matters most: a link written here would
	// be found by the FIRST branch of resolveOrJITUser on the next attempt,
	// which never looks at email_verified at all.
	if ident := ssoLinkFor(t, r, idp, "attacker-sub-1"); ident != nil {
		t.Fatalf("a refused adoption still wrote an external identity: %+v", ident)
	}
	// The victim's account is untouched.
	after, err := r.GetUserByEmail(context.Background(), victimEmail)
	if err != nil || after == nil {
		t.Fatalf("victim account disappeared: %v", err)
	}
	if after.ID != victim.ID {
		t.Fatalf("victim account was replaced: %q → %q", victim.ID, after.ID)
	}
}

// Positive control for the refusal: the SAME adoption succeeds when the IdP
// says it verified the address, so the check above is the verification gate
// and not a broken adoption path.
func TestSsoCallback_AdoptsOnVerifiedEmail(t *testing.T) {
	const email = "verified@corp.example"
	_, srv, r, conn, idp := setupForLogin(t)

	existing := seedExistingUser(t, r, email)
	// RE-SCOPED: email_verified alone no longer authorises binding a
	// pre-existing account — the account must also have a tie to the
	// connection's organization, because email_verified is written by whoever
	// runs the IdP the connection points at. The membership is what makes this
	// adoption legitimate rather than a takeover.
	joinOrg(t, r, conn.OrganizationID, existing.ID)

	idp.emailUnverified = false
	idp.overrideEmail = email
	idp.overrideExtraSub = "verified-sub-1"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("verified adoption refused: %d %s", resp.StatusCode, body)
	}
	if ident := ssoLinkFor(t, r, idp, "verified-sub-1"); ident == nil || ident.UserID != existing.ID {
		t.Fatalf("verified adoption did not link the existing account: %+v", ident)
	}
	if sessionCountFor(t, r, existing.ID) == 0 {
		t.Fatalf("verified adoption issued no session")
	}
}

// The create-new-user branch is deliberately untouched: an unverified address
// takes over nothing when no account exists here, and it must land with
// email_verified=false rather than inheriting the IdP's word.
func TestSsoCallback_UnverifiedEmailStillJITsANewUser(t *testing.T) {
	const email = "newcomer@corp.example"
	_, srv, r, _, idp := setupForLogin(t)

	idp.emailUnverified = true
	idp.overrideEmail = email
	idp.overrideExtraSub = "newcomer-sub-1"

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("JIT of a brand-new user was refused: %d %s", resp.StatusCode, body)
	}
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("expected a JIT user, got %v", err)
	}
	if u.EmailVerified {
		t.Errorf("an unverified provider address must not land as email_verified=true")
	}
	if ident := ssoLinkFor(t, r, idp, "newcomer-sub-1"); ident == nil {
		t.Fatalf("JIT user was not linked")
	}
}

// An already-linked account signs in on its link, not on the email claim, so
// an IdP that stops reporting email_verified must not lock out users it
// legitimately provisioned earlier. This pins that the fix did not widen into
// the existing-link branch.
func TestSsoCallback_ExistingLinkUnaffectedByUnverifiedEmail(t *testing.T) {
	const email = "linked@corp.example"
	_, srv, _, _, idp := setupForLogin(t)

	// First login: verified, creates and links the user.
	idp.overrideEmail = email
	idp.overrideExtraSub = "linked-sub-1"
	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("first login: %d %s", resp.StatusCode, body)
	}
	_ = resp.Body.Close()

	// Second login on the same link, with the IdP no longer verifying.
	idp.emailUnverified = true
	state, nonce = beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp2 := callback(t, srv, state)
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("an established link was refused: %d %s", resp2.StatusCode, body)
	}
}
