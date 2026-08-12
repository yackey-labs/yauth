package ssosaml

// A first SAML login that finds an EXISTING yauth account with the asserted
// email adopts it: it links that account to the IdP subject and signs the
// caller in. #81 closed this in plugins/oauth and #82 in plugins/ssooidc by
// requiring the id_token's email_verified claim. SAML has no such claim, so
// this connection carries an explicit opt-in instead — see
// SamlConnectionConfig.AllowAccountAdoption.

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// theAssertedEmail is the address the fixture IdP puts in every assertion.
const theAssertedEmail = "alice@example.com"

// setAdoption rewrites the fixture connection's stored config with
// AllowAccountAdoption set as requested.
func setAdoption(t *testing.T, f *e2eFixture, allow bool) {
	t.Helper()
	cfg, err := unmarshalSamlConfig(f.plugin.cfg.EncryptionKey, f.conn.Config)
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	cfg.AllowAccountAdoption = allow
	raw, err := marshalSamlConfig(f.plugin.cfg.EncryptionKey, cfg)
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	now := time.Now().UTC()
	updated, err := f.repo.UpdateSsoConnection(context.Background(), f.conn.ID, domain.UpdateSsoConnection{
		Config: &raw, UpdatedAt: &now,
	})
	if err != nil {
		t.Fatalf("update connection: %v", err)
	}
	f.conn = updated
}

// seedVictim creates a pre-existing local account holding the address the IdP
// is about to assert. This is the account an adoption takes over.
func seedVictim(t *testing.T, f *e2eFixture) domain.User {
	t.Helper()
	now := time.Now().UTC()
	u, err := f.repo.CreateUser(context.Background(), domain.NewUser{
		ID:            uuid.NewString(),
		Email:         theAssertedEmail,
		EmailVerified: true,
		Role:          "user",
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	return u
}

// driveACS runs a full SP-initiated login and POSTs the signed assertion.
func driveACS(t *testing.T, f *e2eFixture) *http.Response {
	t.Helper()
	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	res, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatalf("acs: %v", err)
	}
	return res
}

// providerKey is the ExternalIdentity provider string the SAML callback uses.
func providerKey(f *e2eFixture) string {
	return "saml:" + IssuerKeyFromEntityID(f.idp.entityID)
}

// TestSamlAdoption_RefusedByDefault is the regression. The assertions are on
// STATE, and the link is the one that matters most: if an ExternalIdentity row
// is written, the FIRST branch of resolveOrJITUser finds it on every later
// attempt and never reaches the adoption gate again — one slip is permanent.
func TestSamlAdoption_RefusedByDefault(t *testing.T) {
	f := newE2E(t) // AllowAccountAdoption defaults to false
	victim := seedVictim(t, f)

	res := driveACS(t, f)
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode == http.StatusFound {
		t.Errorf("adoption: ACS returned 302 (signed in) for a pre-existing account")
	}
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Errorf("adoption: a session cookie was issued")
		}
	}

	ctx := context.Background()
	if ident, err := f.repo.GetExternalIdentityByProviderAndExternalID(ctx, providerKey(f), theAssertedEmail); err == nil && ident != nil {
		t.Errorf("adoption: the victim's account was LINKED to the IdP subject (identity %s -> user %s)", ident.ID, ident.UserID)
	}

	// No session row either — the cookie check above only sees what was
	// written to the response.
	if sessions, _, err := f.repo.ListSessions(ctx, domain.ListSessionsFilters{UserID: &victim.ID, Limit: 10}); err == nil && len(sessions) > 0 {
		t.Errorf("adoption: %d session row(s) created for the victim", len(sessions))
	}

	// And no org membership was minted off the back of it.
	if m, err := f.repo.GetMembershipByOrgUser(ctx, f.org.ID, victim.ID); err == nil && m != nil {
		t.Errorf("adoption: the victim was made a %s of the connection's organization", m.Role)
	}
}

// TestSamlAdoption_AllowedWhenOptedIn is the control: an operator who has
// decided their IdP is authoritative for the addresses it asserts flips the
// flag and the migration works.
func TestSamlAdoption_AllowedWhenOptedIn(t *testing.T) {
	f := newE2E(t)
	setAdoption(t, f, true)
	victim := seedVictim(t, f)

	res := driveACS(t, f)
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode != http.StatusFound {
		t.Fatalf("opted-in adoption: status=%d, want 302", res.StatusCode)
	}
	ident, err := f.repo.GetExternalIdentityByProviderAndExternalID(context.Background(), providerKey(f), theAssertedEmail)
	if err != nil || ident == nil {
		t.Fatalf("opted-in adoption: no link created: %v", err)
	}
	if ident.UserID != victim.ID {
		t.Fatalf("opted-in adoption: linked to %s, want the existing account %s", ident.UserID, victim.ID)
	}
}

// TestSamlAdoption_FirstTimeProvisioningUnaffected pins the boundary: with the
// flag OFF, a user who has no account here is still JIT-provisioned and signed
// in. Creating an account takes nothing over, so it was never the problem, and
// breaking it would make the default unusable.
func TestSamlAdoption_FirstTimeProvisioningUnaffected(t *testing.T) {
	f := newE2E(t) // flag off, and NO pre-existing account

	res := driveACS(t, f)
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode != http.StatusFound {
		t.Fatalf("jit provisioning: status=%d, want 302", res.StatusCode)
	}
	u, err := f.repo.GetUserByEmail(context.Background(), theAssertedEmail)
	if err != nil || u == nil {
		t.Fatalf("jit provisioning: user not created: %v", err)
	}
}

// TestSamlAdoption_EstablishedLinkStillSignsIn pins the other boundary: once a
// link exists, sign-in resolves on the LINK and never consults the address, so
// turning the flag off later does not lock anyone out.
func TestSamlAdoption_EstablishedLinkStillSignsIn(t *testing.T) {
	f := newE2E(t)
	setAdoption(t, f, true)
	seedVictim(t, f)

	res := driveACS(t, f) // establishes the link
	res.Body.Close()      //nolint:errcheck

	setAdoption(t, f, false) // operator turns it back off

	res2 := driveACS(t, f)
	defer res2.Body.Close() //nolint:errcheck
	if res2.StatusCode != http.StatusFound {
		t.Fatalf("established link: status=%d after adoption was disabled, want 302", res2.StatusCode)
	}
}

// TestSamlAdoption_ConfigRoundTrip pins that the flag survives the stored-config
// codec — a silently-dropped field would default the gate open on every read.
func TestSamlAdoption_ConfigRoundTrip(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 7)
	}
	in := SamlConnectionConfig{
		IdpEntityID:             "urn:idp:test",
		IdpSsoURL:               "https://idp.test/sso",
		IdpX509Cert:             "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
		AssertionSignedRequired: true,
		ResponseSignedRequired:  true,
		AllowAccountAdoption:    true,
		AttributeMappings:       DefaultAttributeMappings(),
	}
	raw, err := marshalSamlConfig(key, in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := unmarshalSamlConfig(key, raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.AllowAccountAdoption {
		t.Fatalf("allow_account_adoption did not survive the config codec")
	}
	pub, err := peekSamlConfigPublic(raw)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !pub.AllowAccountAdoption {
		t.Fatalf("allow_account_adoption not visible to the admin read path")
	}
	_ = auth.RoleMember
}
