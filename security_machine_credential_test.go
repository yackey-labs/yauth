// Regression suite for "a machine credential carries its human's authority".
//
// Two separate confusions live in the X-Api-Key path, and both are reachable
// through the real router:
//
//  1. ORG-SCOPED KEY -> GLOBAL ADMIN. plugins/apikey/resolver.go builds the
//     service-account AuthUser with `User: *creator` — the whole user row of
//     the human who minted the key, global Role included — and puts the KEY's
//     own role/permissions on au.Principal. middleware.ResolveAdmin then tests
//     `au.User.Role != "admin"`, refuses IsDelegated(), and (only when
//     AllowAdminMachineCallers is false) refuses machine methods. It never
//     reads au.Principal. So a deployment that turns
//     plugins.admin.allow_machine_callers on — the documented way to let its
//     own automation reach /admin/* — hands every org-scoped key minted by an
//     admin the full global admin surface: list, ban, impersonate, delete any
//     user in any org. The key's own role ("viewer") and its empty permission
//     list, both capped at mint time by the org handler, are simply not
//     consulted. An org-scoped credential carries ORG authority; the creator
//     row on it exists for audit attribution, not for authorization.
//
//  2. USER-SCOPED KEY -> CREDENTIAL LIFECYCLE. The user-scoped path builds a
//     domain.NewUserPrincipal, so Kind is "user" and Delegated is false: it
//     passes apikey.requireUserPrincipal and middleware.RequireUserPrincipalHuma,
//     which refuse only service accounts and delegated tokens. A key leaked
//     from a build log therefore mints MORE user-scoped keys (so revoking the
//     leaked one leaves the replacements live), enrols the attacker's own
//     passkey — a permanent authenticator on the victim's account which, since
//     passkey.Config.SatisfiesMFA defaults true, also stands down the victim's
//     second factor and launders the machine credential into a cookie session
//     that isMachineMethod cannot see — and starts a TOTP enrolment. Those are
//     the routes that CHANGE how the account authenticates; a bearer of the
//     account's machine credential must not be able to reach them.
//
// Every refusal here is paired with a positive control, because the cheap
// wrong fix for (1) is "refuse service accounts everywhere" (which locks
// org-scoped keys out of the /organizations/* routes they exist to serve) and
// the cheap wrong fix for (2) is "refuse X-Api-Key on every authed route"
// (which breaks the user-scoped key's whole reason to exist).
//
// Shared harness helpers (secHarness, secKeyCall, secRegister, ...) live in
// security_refresh_issuer_test.go.
package yauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/admin"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/plugins/organizations"
	"github.com/yackey-labs/yauth/plugins/passkey"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newMachineCredHarness boots the full plugin set this batch spans. It cannot
// reuse newSecHarness because AllowAdminMachineCallers is a YAuthConfig field
// the shared helper does not expose, and the whole point of case (1) is what
// happens once an operator turns it on.
func newMachineCredHarness(t *testing.T, allowMachineCallers bool) *secHarness {
	t.Helper()

	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.RateLimit = yauth.RateLimitConfig{}
	cfg.AllowAdminMachineCallers = allowMachineCallers

	var mfaKey [32]byte
	copy(mfaKey[:], "machine-credential-regression-key")
	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: mfaKey, Issuer: "yauth-test"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}
	passkeyPlugin, err := passkey.New(passkey.Config{
		RPID:      "localhost",
		RPOrigins: []string{"http://localhost:3000"},
	})
	if err != nil {
		t.Fatalf("passkey.New: %v", err)
	}

	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte(secJWTSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 12,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
			Mailer:            secNullMailer{},
		})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(admin.New()).
		WithPlugin(organizations.New(organizations.Config{})).
		WithPlugin(mfaPlugin).
		WithPlugin(passkeyPlugin).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &secHarness{srv: srv, repo: r}
}

// machineCredFixture is alice — a GLOBAL admin who owns org-ci — plus the
// three credentials the cases compare: two org-scoped keys (one capped at
// role=viewer, one at role=admin) and her own user-scoped key.
type machineCredFixture struct {
	h         *secHarness
	aliceID   string
	orgID     string
	viewerKey string // org-scoped, key role = viewer, permissions []
	adminKey  string // org-scoped, key role = admin
	userKey   string // alice's personal, user-scoped key
	cookie    *http.Cookie
}

func newMachineCredFixture(t *testing.T, allowMachineCallers bool) *machineCredFixture {
	t.Helper()
	h := newMachineCredHarness(t, allowMachineCallers)
	ctx := context.Background()
	now := time.Now().UTC()

	alice := secRegister(t, h, "alice@test.local")

	// Promote alice to GLOBAL admin. This is the role the org key must not
	// inherit — and the role her own user-scoped key legitimately carries.
	adminRole := "admin"
	if _, err := h.repo.UpdateUser(ctx, alice, domain.UpdateUser{
		Role: &adminRole, UpdatedAt: &now,
	}); err != nil {
		t.Fatalf("promote alice to admin: %v", err)
	}

	const orgID = "org-ci"
	if _, err := h.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: orgID, Name: "CI Org", Slug: "ci-org", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if _, err := h.repo.CreateMembership(ctx, domain.NewMembership{
		OwnerRoleAuthorized: true, // fixture seeds state directly, bypassing the handler layer
		ID:                  "m-org-ci",
		OrganizationID:      orgID,
		UserID:              alice,
		Role:                auth.RoleOwner,
		Status:              domain.MembershipActive,
		CreatedAt:           now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create membership: %v", err)
	}

	mintOrg := func(id, role string) string {
		t.Helper()
		gen, err := apikey.GenerateKey("yak")
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		org, r := orgID, role
		if err := h.repo.CreateAPIKey(ctx, domain.NewAPIKey{
			ID: id, OrganizationID: &org, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
			Name: id, Role: &r, Scopes: json.RawMessage(`[]`),
			CreatedAt: now, CreatedByUserID: alice,
		}); err != nil {
			t.Fatalf("create org api key %s: %v", id, err)
		}
		return gen.Plaintext
	}

	userGen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	uid := alice
	if err := h.repo.CreateAPIKey(ctx, domain.NewAPIKey{
		ID: "k-alice-cli", UserID: &uid, KeyPrefix: userGen.Prefix, KeyHash: userGen.Hash,
		Name: "alice-cli", Scopes: json.RawMessage(`[]`),
		CreatedAt: now, CreatedByUserID: alice,
	}); err != nil {
		t.Fatalf("create user api key: %v", err)
	}

	raw, _, err := auth.IssueSession(ctx, h.repo, alice, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	return &machineCredFixture{
		h:         h,
		aliceID:   alice,
		orgID:     orgID,
		viewerKey: mintOrg("k-viewer-ci", auth.RoleViewer),
		adminKey:  mintOrg("k-admin-ci", auth.RoleAdmin),
		userKey:   userGen.Plaintext,
		cookie:    &http.Cookie{Name: "yauth_session", Value: raw},
	}
}

// secCookieCall is secKeyCall's sibling for a real human session — the
// positive-control side of every case below.
func secCookieCall(t *testing.T, method, u string, c *http.Cookie, body any) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, u, rdr)
	req.AddCookie(c)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// ---------------------------------------------------------------------------
// 1. An org-scoped key must never carry its creator's GLOBAL admin role
// ---------------------------------------------------------------------------

// The deployment has opted machine callers into /admin/* — the documented way
// to let its own automation administer users. That opt-in is about credentials
// that really do carry the human's global role. An org key is not one: its
// authority is the org row and the role stamped on the key.
func TestOrgScopedKey_NeverReachesGlobalAdminRoutes(t *testing.T) {
	f := newMachineCredFixture(t, true)

	for _, tc := range []struct{ name, key string }{
		{"role=viewer", f.viewerKey},
		{"role=admin", f.adminKey},
	} {
		code, body := secKeyCall(t, http.MethodGet, f.h.url("/admin/users"), tc.key, nil)
		if code != http.StatusForbidden {
			t.Errorf("org-scoped key (%s) minted by a global admin reached GET /admin/users: %d %s",
				tc.name, code, body)
		}
	}

	// The sharpest consequence: the same key can act ON a human account.
	code, body := secKeyCall(t, http.MethodPost,
		f.h.url("/admin/users/"+f.aliceID+"/ban"), f.viewerKey,
		map[string]any{"reason": "pivot"})
	if code != http.StatusForbidden {
		t.Errorf("org-scoped key reached POST /admin/users/{id}/ban: %d %s", code, body)
	}
	after, err := f.h.repo.GetUserByID(context.Background(), f.aliceID)
	if err != nil {
		t.Fatalf("re-read alice: %v", err)
	}
	if after.Banned {
		t.Errorf("an org-scoped API key banned a global admin's account")
	}
}

// CONTROL A: the opt-in keeps its meaning for a credential that genuinely
// carries the human's global role. Alice's own user-scoped key still
// administers.
func TestUserScopedKey_StillReachesAdminRoutesWithOptIn(t *testing.T) {
	f := newMachineCredFixture(t, true)

	code, body := secKeyCall(t, http.MethodGet, f.h.url("/admin/users"), f.userKey, nil)
	if code != http.StatusOK {
		t.Fatalf("alice's own user-scoped key was refused /admin/users under the opt-in: %d %s", code, body)
	}
}

// CONTROL B: everything the org key exists to serve is untouched. An
// admin-role org key still administers its OWN organization.
func TestOrgScopedKey_StillServesItsOwnOrganization(t *testing.T) {
	f := newMachineCredFixture(t, true)

	code, body := secKeyCall(t, http.MethodGet,
		f.h.url("/organizations/"+f.orgID+"/api-keys"), f.adminKey, nil)
	if code != http.StatusOK {
		t.Fatalf("admin-role org key was refused its own org's routes: %d %s", code, body)
	}
}

// ---------------------------------------------------------------------------
// 2. A user-scoped key must not run the account's credential lifecycle
// ---------------------------------------------------------------------------

// A leaked X-Api-Key that can mint more X-Api-Keys is a persistence
// primitive: revoking the leaked key leaves every replacement live.
func TestUserScopedKey_CannotMintAnotherAPIKey(t *testing.T) {
	f := newMachineCredFixture(t, false)
	ctx := context.Background()

	before, err := f.h.repo.ListAPIKeysByUserID(ctx, f.aliceID)
	if err != nil {
		t.Fatalf("list alice's keys: %v", err)
	}

	code, body := secKeyCall(t, http.MethodPost, f.h.url("/api-keys"), f.userKey,
		map[string]any{"name": "second-key"})
	if code != http.StatusForbidden {
		t.Errorf("a user-scoped API key minted another API key: %d %s", code, body)
	}
	if strings.Contains(body, `"secret"`) {
		t.Errorf("a plaintext key secret was handed to a machine credential: %s", body)
	}
	after, err := f.h.repo.ListAPIKeysByUserID(ctx, f.aliceID)
	if err != nil {
		t.Fatalf("re-list alice's keys: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("a key row was persisted despite the refusal: %d → %d", len(before), len(after))
	}
}

// CONTROL: alice at her keyboard still mints keys, and her key still READS
// her key list — only the lifecycle write is refused to the machine.
func TestUserScopedKey_ReadPathsAndSessionMintingUnchanged(t *testing.T) {
	f := newMachineCredFixture(t, false)

	code, body := secKeyCall(t, http.MethodGet, f.h.url("/api-keys"), f.userKey, nil)
	if code != http.StatusOK {
		t.Fatalf("user-scoped key was refused GET /api-keys: %d %s", code, body)
	}

	code, body = secCookieCall(t, http.MethodPost, f.h.url("/api-keys"), f.cookie,
		map[string]any{"name": "from-my-browser"})
	if code != http.StatusCreated {
		t.Fatalf("a real session was refused POST /api-keys: %d %s", code, body)
	}
	if !strings.Contains(body, `"secret"`) {
		t.Fatalf("session mint returned no secret: %s", body)
	}
}

// The other half of the persistence primitive: the leaked key revoking the
// owner's legitimate keys. Whoever holds the machine credential must not be
// able to take the human's own credentials away.
func TestUserScopedKey_CannotRevokeTheOwnersKeys(t *testing.T) {
	f := newMachineCredFixture(t, false)
	ctx := context.Background()
	now := time.Now().UTC()

	// Two more of alice's own keys: one the machine credential will try to
	// revoke, one reserved for the control so the control cannot fail merely
	// because the refusal did not hold.
	for _, id := range []string{"k-alice-laptop", "k-alice-desktop"} {
		gen, err := apikey.GenerateKey("yak")
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		uid := f.aliceID
		if err := f.h.repo.CreateAPIKey(ctx, domain.NewAPIKey{
			ID: id, UserID: &uid, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
			Name: id, Scopes: json.RawMessage(`[]`),
			CreatedAt: now, CreatedByUserID: f.aliceID,
		}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}

	code, body := secKeyCall(t, http.MethodDelete, f.h.url("/api-keys/k-alice-laptop"), f.userKey, nil)
	if code != http.StatusForbidden {
		t.Errorf("a user-scoped API key revoked another of the owner's keys: %d %s", code, body)
	}
	if _, err := f.h.repo.GetAPIKeyByIDAndUser(ctx, "k-alice-laptop", f.aliceID); err != nil {
		t.Errorf("alice's key row was deleted by a machine credential: %v", err)
	}

	// CONTROL: alice at her keyboard still revokes her own key.
	code, body = secCookieCall(t, http.MethodDelete, f.h.url("/api-keys/k-alice-desktop"), f.cookie, nil)
	if code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("a real session was refused DELETE /api-keys/{id}: %d %s", code, body)
	}
}

// Enrolling a passkey is enrolling a permanent authenticator. Since
// Config.SatisfiesMFA defaults true, the planted passkey also logs in past the
// victim's TOTP and yields a cookie whose Method is "" — the machine-caller
// restriction laundered into a human session.
func TestUserScopedKey_CannotEnrolAPasskey(t *testing.T) {
	f := newMachineCredFixture(t, false)

	code, body := secKeyCall(t, http.MethodPost,
		f.h.url("/passkeys/register/begin"), f.userKey, nil)
	if code != http.StatusForbidden {
		t.Errorf("a user-scoped API key started passkey enrolment: %d %s", code, body)
	}
	if strings.Contains(body, "challenge") {
		t.Errorf("CredentialCreation options were handed to a machine credential: %s", body)
	}
}

// Owning the second factor is how an attacker survives the victim's password
// reset, so /mfa/totp/setup + /confirm are off-limits to a machine credential
// too. The account has no verified factor yet, so mfa's own requireStepUp
// returns nil and the route guards are the only thing standing there.
//
// The assertion that matters is the persisted one: after driving the whole
// enrolment with nothing but the leaked key, alice must still have no verified
// TOTP secret.
func TestUserScopedKey_CannotEnrolTOTP(t *testing.T) {
	f := newMachineCredFixture(t, false)
	ctx := context.Background()

	code, body := secKeyCall(t, http.MethodPost, f.h.url("/mfa/totp/setup"), f.userKey, nil)
	if code != http.StatusForbidden {
		t.Errorf("a user-scoped API key began TOTP enrolment: %d %s", code, body)
	}
	if strings.Contains(body, "otpauth") {
		t.Errorf("a TOTP secret was handed to a machine credential: %s", body)
	}

	// Today setup answers 200 — carry the enrolment through to confirm so the
	// end state (an attacker-held second factor on alice's account) is what
	// gets asserted, not just a status line.
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(body), &setup); err == nil && setup.Secret != "" {
		code, body = secKeyCall(t, http.MethodPost, f.h.url("/mfa/totp/confirm"), f.userKey,
			map[string]any{"code": totpCodeFor(t, setup.Secret, time.Now().UTC().Add(-30*time.Second))})
		if code != http.StatusForbidden {
			t.Errorf("a user-scoped API key confirmed a TOTP enrolment: %d %s", code, body)
		}
	}

	verified := true
	if row, err := f.h.repo.GetTOTPByUserID(ctx, f.aliceID, &verified); err == nil {
		t.Errorf("a verified TOTP factor was installed on alice's account by an API-key caller (row %s)", row.ID)
	}
}

// totpCodeFor returns the RFC 6238 code for the given instant. Enrolment is
// confirmed with the PRIOR step's code (still inside the ±1-step window) so a
// code minted straight afterwards belongs to a later, unspent step.
func totpCodeFor(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	return code
}

// CONTROL: alice at her keyboard still enrols both factors.
func TestSessionCallerStillEnrolsPasskeyAndTOTP(t *testing.T) {
	f := newMachineCredFixture(t, false)

	code, body := secCookieCall(t, http.MethodPost, f.h.url("/passkeys/register/begin"), f.cookie, nil)
	if code != http.StatusOK {
		t.Fatalf("a real session was refused passkey enrolment: %d %s", code, body)
	}
	if !strings.Contains(body, "challenge") {
		t.Fatalf("passkey begin returned no challenge: %s", body)
	}

	code, body = secCookieCall(t, http.MethodPost, f.h.url("/mfa/totp/setup"), f.cookie, nil)
	if code != http.StatusOK {
		t.Fatalf("a real session was refused TOTP enrolment: %d %s", code, body)
	}
	if !strings.Contains(body, "otpauth") {
		t.Fatalf("totp setup returned no secret: %s", body)
	}
}

// A session cookie is not proof that the person holding it still holds the
// account's second factor — that is exactly what a stolen cookie is not.
// Enrolling a passkey on an account that already has a verified TOTP factor
// therefore has to present that factor, the way /mfa/totp/delete and
// /mfa/backup-codes/regenerate already do: without it, the cheapest way past a
// victim's MFA is to enrol a passkey (which satisfies MFA by default) and
// never be asked for a code again.
func TestPasskeyRegisterBegin_RequiresStepUpWhenTOTPEnrolled(t *testing.T) {
	f := newMachineCredFixture(t, false)
	enrolTOTPFromSession(t, f)

	// Same session, no X-MFA-Code: enrolling another authenticator must be
	// stepped up.
	code, body := secCookieCall(t, http.MethodPost, f.h.url("/passkeys/register/begin"), f.cookie, nil)
	if code != http.StatusForbidden {
		t.Fatalf("passkey enrolment on an MFA-enrolled account skipped step-up: %d %s", code, body)
	}
	if strings.Contains(body, "challenge") {
		t.Fatalf("CredentialCreation options issued without step-up: %s", body)
	}
}

// POSITIVE CONTROL for the step-up gate, and the one that stops the cheap
// wrong fix: refusing register/begin outright once a factor is enrolled would
// satisfy the test above while making passkeys unreachable for exactly the
// users who care most about them. A CURRENT code must still enrol, and a wrong
// one must not — the gate has to grade the code, not merely notice a factor.
func TestPasskeyRegisterBegin_CorrectStepUpCodeStillEnrols(t *testing.T) {
	f := newMachineCredFixture(t, false)
	secret := enrolTOTPFromSession(t, f)

	code, body := secCookieCallWithHeaders(t, http.MethodPost, f.h.url("/passkeys/register/begin"),
		f.cookie, map[string]string{"X-MFA-Code": "000000"})
	if code != http.StatusForbidden {
		t.Fatalf("a wrong X-MFA-Code was accepted for passkey enrolment: %d %s", code, body)
	}
	if strings.Contains(body, "challenge") {
		t.Fatalf("CredentialCreation options issued on a wrong code: %s", body)
	}

	code, body = secCookieCallWithHeaders(t, http.MethodPost, f.h.url("/passkeys/register/begin"),
		f.cookie, map[string]string{"X-MFA-Code": totpCodeFor(t, secret, time.Now().UTC())})
	if code != http.StatusOK {
		t.Fatalf("a correct X-MFA-Code was refused passkey enrolment: %d %s", code, body)
	}
	if !strings.Contains(body, "challenge") {
		t.Fatalf("stepped-up passkey begin returned no challenge: %s", body)
	}
}

// enrolTOTPFromSession runs alice's normal browser enrolment (setup +
// confirm) and returns the shared secret, asserting a verified row landed.
func enrolTOTPFromSession(t *testing.T, f *machineCredFixture) string {
	t.Helper()
	code, body := secCookieCall(t, http.MethodPost, f.h.url("/mfa/totp/setup"), f.cookie, nil)
	if code != http.StatusOK {
		t.Fatalf("totp setup: %d %s", code, body)
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(body), &setup); err != nil || setup.Secret == "" {
		t.Fatalf("decode totp setup: %v (body=%s)", err, body)
	}
	// Confirm with the PRIOR step's code so the CURRENT step is still unspent
	// and can be used for the step-up above.
	code, body = secCookieCall(t, http.MethodPost, f.h.url("/mfa/totp/confirm"), f.cookie,
		map[string]any{"code": totpCodeFor(t, setup.Secret, time.Now().UTC().Add(-30*time.Second))})
	if code != http.StatusOK {
		t.Fatalf("totp confirm: %d %s", code, body)
	}
	verified := true
	if _, err := f.h.repo.GetTOTPByUserID(context.Background(), f.aliceID, &verified); err != nil {
		t.Fatalf("expected a verified TOTP factor after confirm: %v", err)
	}
	return setup.Secret
}

// secCookieCallWithHeaders is secCookieCall for a bodyless POST that carries
// extra request headers — the X-MFA-Code step-up, here.
func secCookieCallWithHeaders(t *testing.T, method, u string, c *http.Cookie, hdrs map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	req.AddCookie(c)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// ---------------------------------------------------------------------------
// 3. Rotation must not turn a short-lived key into a permanent one
// ---------------------------------------------------------------------------

// The rotate handler rebuilds domain.NewAPIKey from the old row carrying
// Name/Scopes/Role/OrganizationID and NOT ExpiresAt, so a CI credential
// deliberately issued for 72h comes back with a NULL expiry — and because the
// response field is omitempty, nothing in the 201 body looks wrong.
func TestRotateOrgAPIKey_PreservesExpiry(t *testing.T) {
	f := newMachineCredFixture(t, false)
	ctx := context.Background()
	now := time.Now().UTC()
	expiry := now.Add(72 * time.Hour)

	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	org, role := f.orgID, auth.RoleViewer
	if err := f.h.repo.CreateAPIKey(ctx, domain.NewAPIKey{
		ID: "k-short-lived", OrganizationID: &org, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
		Name: "short-lived", Role: &role, Scopes: json.RawMessage(`[]`),
		ExpiresAt: &expiry, CreatedAt: now, CreatedByUserID: f.aliceID,
	}); err != nil {
		t.Fatalf("create short-lived org key: %v", err)
	}

	code, body := secCookieCall(t, http.MethodPost,
		f.h.url("/organizations/"+f.orgID+"/api-keys/k-short-lived/rotate"), f.cookie, nil)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, body)
	}

	var out struct {
		APIKey struct {
			ID        string     `json:"id"`
			ExpiresAt *time.Time `json:"expires_at"`
		} `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode rotate response: %v (body=%s)", err, body)
	}

	fresh, err := f.h.repo.GetAPIKeyByIDAndOrg(ctx, out.APIKey.ID, f.orgID)
	if err != nil {
		t.Fatalf("read rotated key: %v", err)
	}
	if fresh.ExpiresAt == nil {
		t.Fatalf("rotating a key expiring at %s produced a key that NEVER expires", expiry.Format(time.RFC3339))
	}
	if delta := fresh.ExpiresAt.Sub(expiry); delta > time.Minute || delta < -time.Minute {
		t.Fatalf("rotated key expiry %s is not the original %s",
			fresh.ExpiresAt.Format(time.RFC3339), expiry.Format(time.RFC3339))
	}
}
