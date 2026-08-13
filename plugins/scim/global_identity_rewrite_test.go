// global_identity_rewrite_test.go — regression suite for the SCIM /Users
// write paths rewriting, duplicating and demoting a GLOBAL identity on the
// authority of a single org-scoped API key.
//
// plugins/scim/auth.go binds a SCIM key to exactly one organization, and that
// is the only thing it binds. Everything downstream of it in users.go then
// reaches straight into global state:
//
//   - handlePutUser / handlePatchUser gate on requireUserInOrg, which passes on
//     the MERE EXISTENCE of a membership row, and then call
//     repo.UpdateUser(user.ID, {Email:&newEmail}) — that column is
//     yauth_users.email, the GLOBAL login identity used by
//     plugins/emailpassword's forgot-password lookup. The only check in the way
//     is "is this address taken by someone else"; an address nobody holds
//     sails through. email_verified is left true, no session is flushed, and
//     the old address is never told. An org-A admin can therefore point a
//     member's login at an address they control and redeem a password reset —
//     inheriting that member's GLOBAL role and every other org they belong to.
//     handleCreateUser already refuses exactly this via requireAdoptable
//     (the #83 cross-tenant guard); PUT and PATCH never learned about it.
//
//   - No SCIM write path lowercases userName. yauth_users.email is UNIQUE over
//     plain TEXT and GetUserByEmail is `WHERE email = $1`, so a mixed-case
//     variant of an existing address MISSES the lookup entirely — which means
//     requireAdoptable, the collision check, and idempotency all silently
//     do not run, and a second global user row is minted with
//     EmailVerified:true.
//
//   - The PATCH `active` branch does `if err := json.Unmarshal(...); err == nil`
//     and DISCARDS the error. Entra ID sends active as the STRING "False", and
//     it also sends the fully-qualified attribute path
//     urn:ietf:params:scim:schemas:core:2.0:User:active, which lands in the
//     tolerate-and-ignore default branch. Either way newActive stays nil, the
//     whole lifecycle block is skipped, and the handler answers 200 with a body
//     showing an active user. The IdP records a completed deprovision;
//     the sessions, the refresh tokens and the account all survive.
//
//   - handleCreateUser writes Role:&auth.RoleMember onto an EXISTING
//     membership, so a routine IdP re-sync silently demotes every org admin.
//     The organizations API refuses precisely this write.
//
// The refusal cases below are paired with positive controls proving the flows
// SCIM legitimately needs still work: a rename inside a namespace the org has
// VERIFIED, a routine profile-sync PUT that must NOT burn credentials, a
// well-formed active:false deprovision, and a re-POST that reactivates a
// suspended member.
package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// --- fixtures ------------------------------------------------------------

// seedGlobalUser creates a user row directly (no SCIM involved) so a test can
// give it a GLOBAL role SCIM would never assign.
func seedGlobalUser(t *testing.T, app *testApp, email, role string) *domain.User {
	t.Helper()
	now := time.Now().UTC()
	u, err := app.repo.CreateUser(context.Background(), domain.NewUser{
		ID:            uuid.NewString(),
		Email:         email,
		Role:          role,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatalf("seed global user %s: %v", email, err)
	}
	return &u
}

// joinOrg gives userID a membership in orgID at the given role/status,
// bypassing the handler layer the way the other fixtures in this package do.
func joinOrg(t *testing.T, app *testApp, orgID, userID, role string, status domain.MembershipStatus) *domain.Membership {
	t.Helper()
	now := time.Now().UTC()
	m, err := app.repo.CreateMembership(context.Background(), domain.NewMembership{
		OwnerRoleAuthorized: true, // fixture: seeds state directly
		ID:                  uuid.NewString(),
		OrganizationID:      orgID,
		UserID:              userID,
		Role:                role,
		Status:              status,
		JoinedAt:            &now,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	if err != nil {
		t.Fatalf("join org: %v", err)
	}
	return &m
}

// seedVerifiedDomain has orgID prove control of a DNS namespace — the same
// proof requireAdoptable already accepts on the POST path.
func seedVerifiedDomain(t *testing.T, app *testApp, orgID, dom string) {
	t.Helper()
	if _, err := app.repo.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID:                uuid.NewString(),
		OrganizationID:    orgID,
		Domain:            dom,
		Status:            domain.DomainVerified,
		VerificationToken: "tok-" + uuid.NewString()[:8],
		CreatedAt:         time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed verified domain %s: %v", dom, err)
	}
}

// liveCredentials plants one session and one refresh token on a user so a test
// can assert whether the kill switch actually fired.
type liveCredentials struct {
	sessionID string
	tokenHash string
}

func seedLiveCredentials(t *testing.T, app *testApp, userID string) liveCredentials {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	c := liveCredentials{sessionID: uuid.NewString(), tokenHash: "hash-" + uuid.NewString()}
	if err := app.repo.CreateSession(ctx, domain.NewSession{
		ID:        c.sessionID,
		UserID:    userID,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := app.repo.CreateRefreshToken(ctx, domain.NewRefreshToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: c.tokenHash,
		FamilyID:  uuid.NewString(),
		Scopes:    json.RawMessage(`["openid"]`),
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	return c
}

func (c liveCredentials) assertAlive(t *testing.T, app *testApp) {
	t.Helper()
	ctx := context.Background()
	s, err := app.repo.GetSessionByID(ctx, c.sessionID)
	if err != nil || s == nil {
		t.Fatalf("session was flushed but nothing legitimate changed (err=%v)", err)
	}
	tok, err := app.repo.GetRefreshTokenByHash(ctx, c.tokenHash)
	if err != nil || tok == nil {
		t.Fatalf("refresh token disappeared (err=%v)", err)
	}
	if tok.Revoked {
		t.Fatalf("refresh token was revoked but nothing legitimate changed")
	}
}

func (c liveCredentials) assertBurned(t *testing.T, app *testApp) {
	t.Helper()
	ctx := context.Background()
	s, err := app.repo.GetSessionByID(ctx, c.sessionID)
	if err == nil && s != nil {
		t.Fatalf("session %s survived — a rewritten/deprovisioned identity can still ride the old cookie", c.sessionID)
	}
	tok, err := app.repo.GetRefreshTokenByHash(ctx, c.tokenHash)
	if err == nil && tok != nil && !tok.Revoked {
		t.Fatalf("refresh token survived un-revoked — the account is still mintable via /token")
	}
}

func mustUser(t *testing.T, app *testApp, id string) *domain.User {
	t.Helper()
	u, err := app.repo.GetUserByID(context.Background(), id)
	if err != nil || u == nil {
		t.Fatalf("get user %s: %v", id, err)
	}
	return u
}

func mustMembership(t *testing.T, app *testApp, orgID, userID string) *domain.Membership {
	t.Helper()
	m, err := app.repo.GetMembershipByOrgUser(context.Background(), orgID, userID)
	if err != nil || m == nil {
		t.Fatalf("membership (%s,%s) missing: %v", orgID, userID, err)
	}
	return m
}

// --- S1: PUT rewrites the GLOBAL login email -----------------------------

// A member of org A who also holds a global role (and memberships elsewhere)
// must not have their login identity repointed at an address org A cannot
// prove it controls. Redeeming a password reset at the new address is a full
// account takeover, and nothing in the current handler stands in the way.
func TestPut_CannotRepointGlobalLoginEmailOutsideOrgNamespace(t *testing.T) {
	app := newTestApp(t)
	const victimEmail = "victim@corp.example"
	const attackerEmail = "attacker@evil.example"

	victim := seedGlobalUser(t, app, victimEmail, "admin")
	joinOrg(t, app, app.orgA.orgID, victim.ID, auth.RoleMember, domain.MembershipActive)
	// The victim's real home: org B, where they are an owner.
	joinOrg(t, app, app.orgB.orgID, victim.ID, auth.RoleAdmin, domain.MembershipActive)
	creds := seedLiveCredentials(t, app, victim.ID)

	resp := app.do(t, "PUT", userPath(app.orgA.orgID, victim.ID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": attackerEmail,
		"emails":   []map[string]any{{"value": attackerEmail, "primary": true}},
	})
	defer resp.Body.Close() //nolint:errcheck

	// What actually matters: the login identity.
	u := mustUser(t, app, victim.ID)
	if u.Email != victimEmail {
		t.Errorf("GLOBAL login email was rewritten by an org-scoped SCIM key: got %q want %q — "+
			"a forgot-password at %s now takes over a global %q account",
			u.Email, victimEmail, attackerEmail, u.Role)
	}
	if !u.EmailVerified {
		t.Errorf("email_verified was cleared on a refused rewrite")
	}
	byAttacker, err := app.repo.GetUserByEmail(context.Background(), attackerEmail)
	if err == nil && byAttacker != nil {
		t.Errorf("GetUserByEmail(%q) now resolves to user %s — the password-reset path is live on the attacker's address",
			attackerEmail, byAttacker.ID)
	}
	creds.assertAlive(t, app)

	if resp.StatusCode != http.StatusConflict && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d want 409 (or 403) — SCIM must refuse a rename into a namespace this org has not verified", resp.StatusCode)
	}
}

// POSITIVE CONTROL + the second half of the same defect. A rename INSIDE a
// namespace org A has verified is a legitimate IdP operation and must keep
// working — but because it repoints the login identity it must also burn the
// live credentials, or the old holder keeps riding the old cookie.
//
// It deliberately does NOT assert email_verified is cleared. Clearing it buys
// nothing here (forgot-password never consults email_verified —
// plugins/emailpassword/handlers.go registerForgotPassword) while costing a
// lot (RequireEmailVerification gates /login, and SCIM sends no verification
// mail, so a legitimately renamed employee would be locked out with no way to
// fix it). handleCreateUser already trusts SCIM-supplied addresses the same
// way. The namespace guard is the control that matters.
func TestPut_RenameUnderVerifiedDomain_SucceedsAndBurnsCredentials(t *testing.T) {
	app := newTestApp(t)
	const dom = "alpha-corp.example"
	const oldEmail = "old.name@alpha-corp.example"
	const newEmail = "new.name@alpha-corp.example"

	seedVerifiedDomain(t, app, app.orgA.orgID, dom)
	user := seedGlobalUser(t, app, oldEmail, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	creds := seedLiveCredentials(t, app, user.ID)

	resp := app.do(t, "PUT", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": newEmail,
		"emails":   []map[string]any{{"value": newEmail, "primary": true}},
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200 — a rename under a VERIFIED domain is the flow SCIM exists to serve", resp.StatusCode)
	}

	u := mustUser(t, app, user.ID)
	if u.Email != newEmail {
		t.Fatalf("email: got %q want %q", u.Email, newEmail)
	}
	creds.assertBurned(t, app)
}

// POSITIVE CONTROL. The overwhelmingly common PUT is a profile sync that
// re-sends the same userName. It must not be mistaken for a rename: no
// credential must be burned and email_verified must survive, or every IdP sync
// would log the whole workforce out.
func TestPut_RoutineProfileSync_LeavesCredentialsAlone(t *testing.T) {
	app := newTestApp(t)
	const email = "steady@alpha.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	creds := seedLiveCredentials(t, app, user.ID)

	resp := app.do(t, "PUT", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreUserSchema},
		"userName":    email,
		"emails":      []map[string]any{{"value": email, "primary": true}},
		"displayName": "Steady Eddie",
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	u := mustUser(t, app, user.ID)
	if u.Email != email {
		t.Fatalf("email changed on a no-op sync: %q", u.Email)
	}
	if !u.EmailVerified {
		t.Errorf("email_verified cleared on a no-op profile sync")
	}
	if u.DisplayName == nil || *u.DisplayName != "Steady Eddie" {
		t.Errorf("displayName not applied: %v", u.DisplayName)
	}
	creds.assertAlive(t, app)
}

// --- S6: PATCH userName "" --------------------------------------------------

// An empty userName is not a rename, it is a corrupt payload: EqualFold("",
// email) is false, GetUserByEmail("") misses, and UpdateUser writes an empty
// GLOBAL email — a permanent lockout, and the next such PATCH collides on the
// unique index and 500s.
func TestPatch_EmptyUserNameIsRejected(t *testing.T) {
	app := newTestApp(t)
	const email = "hollow@alpha.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)

	resp := app.do(t, "PATCH", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey, map[string]any{
		"schemas":    []string{PatchOpSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "userName", "value": ""}},
	})
	defer resp.Body.Close() //nolint:errcheck

	u := mustUser(t, app, user.ID)
	if u.Email != email {
		t.Errorf("GLOBAL login email was blanked to %q — the account can never be reached again", u.Email)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

// --- S3: PATCH active, the Entra shapes -------------------------------------

// The invariant is "never answer 200 having done nothing". users.go threw the
// unmarshal error away, so ANY non-bool left newActive nil, the entire
// lifecycle block was skipped, and the handler still answered 200 — the IdP
// marked the user deprovisioned while the account, its sessions and its
// refresh tokens lived on.
//
// The values below are genuinely ambiguous: "0"/"1" are JSON strings that
// happen to look numeric, "yes" is not a boolean in any SCIM dialect, and a
// bare number is not one either. Guessing wrong on `active` either suspends an
// account globally and kills every session, or drops a deprovision on the
// floor. So these fail closed with 400 invalidValue.
//
// The alpha strings "true"/"false" are NOT in this table — see
// TestPatch_ActiveEntraStringForm_*, which pin that they are honoured.
func TestPatch_ActiveNonBooleanValueIsRejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"string_zero", `"0"`},
		{"string_one", `"1"`},
		{"string_yes", `"yes"`},
		{"number_zero", `0`},
		{"object", `{"value":false}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newTestApp(t)
			email := tc.name + "@alpha.example"
			user := seedGlobalUser(t, app, email, "user")
			joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
			creds := seedLiveCredentials(t, app, user.ID)

			resp := app.do(t, "PATCH", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey,
				`{"schemas":["`+PatchOpSchema+`"],"Operations":[{"op":"replace","path":"active","value":`+tc.raw+`}]}`)
			defer resp.Body.Close() //nolint:errcheck

			if resp.StatusCode == http.StatusOK {
				u := mustUser(t, app, user.ID)
				m := mustMembership(t, app, app.orgA.orgID, user.ID)
				t.Fatalf("PATCH active:%s answered 200 while doing nothing: suspended_at=%v membership=%q — "+
					"the IdP records a completed deprovision and the account stays live", tc.raw, u.SuspendedAt, m.Status)
			}
			body := decodeJSON(t, resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status: got %d want 400", resp.StatusCode)
			}
			if body["scimType"] != "invalidValue" {
				t.Fatalf("scimType: got %v want invalidValue (RFC 7644 §3.5.2)", body["scimType"])
			}
			// A rejected op must not half-apply.
			creds.assertAlive(t, app)
		})
	}
}

// Entra ID sends active as the JSON STRING "False" — this repo's own guide,
// docs/scim/entra.md, tells operators to configure
// `Switch([IsSoftDeleted], , "False", "True", "True", "False") -> active`,
// which produces exactly that. Answering 400 would honour the letter of the
// spec while converting a silent deprovision failure into a hard sync failure
// for every deployment that followed the shipped instructions. The alpha
// strings are unambiguous, so the right answer is to make the deprovision
// actually happen.
func TestPatch_ActiveEntraStringForm_False_Deprovisions(t *testing.T) {
	app := newTestApp(t)
	const email = "entra.string@alpha.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	creds := seedLiveCredentials(t, app, user.ID)

	resp := app.do(t, "PATCH", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey,
		`{"schemas":["`+PatchOpSchema+`"],"Operations":[{"op":"replace","path":"active","value":"False"}]}`)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if mustUser(t, app, user.ID).SuspendedAt == nil {
		t.Errorf(`active:"False" answered 200 without suspending — the IdP recorded a completed deprovision`)
	}
	if m := mustMembership(t, app, app.orgA.orgID, user.ID); m.Status != domain.MembershipSuspended {
		t.Errorf("membership status: got %q want %q", m.Status, domain.MembershipSuspended)
	}
	creds.assertBurned(t, app)
}

// POSITIVE CONTROL for the same leniency: the string "true" on an
// already-active user is a benign no-op, not a 400 and not a suspension.
func TestPatch_ActiveEntraStringForm_True_IsBenign(t *testing.T) {
	app := newTestApp(t)
	const email = "entra.string.true@alpha.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	creds := seedLiveCredentials(t, app, user.ID)

	resp := app.do(t, "PATCH", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey,
		`{"schemas":["`+PatchOpSchema+`"],"Operations":[{"op":"replace","path":"active","value":"true"}]}`)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if u := mustUser(t, app, user.ID); u.SuspendedAt != nil {
		t.Errorf(`active:"true" suspended the account — the string form was parsed backwards`)
	}
	if m := mustMembership(t, app, app.orgA.orgID, user.ID); m.Status != domain.MembershipActive {
		t.Errorf("membership status: got %q want %q", m.Status, domain.MembershipActive)
	}
	creds.assertAlive(t, app)
}

// The fully-qualified attribute path is legal SCIM and Entra sends it. It
// currently falls into the "unknown path — quietly tolerate" default branch, so
// the deprovision is dropped on the floor with a 200.
func TestPatch_ActiveFullyQualifiedPath_Deprovisions(t *testing.T) {
	app := newTestApp(t)
	const email = "fqpath@alpha.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	creds := seedLiveCredentials(t, app, user.ID)

	resp := app.do(t, "PATCH", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey, map[string]any{
		"schemas": []string{PatchOpSchema},
		"Operations": []map[string]any{
			{"op": "replace", "path": "urn:ietf:params:scim:schemas:core:2.0:User:active", "value": false},
		},
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	u := mustUser(t, app, user.ID)
	if u.SuspendedAt == nil {
		t.Errorf("fully-qualified active:false was ignored: the account is still live while the IdP recorded a deprovision")
	}
	m := mustMembership(t, app, app.orgA.orgID, user.ID)
	if m.Status != domain.MembershipSuspended {
		t.Errorf("membership status: got %q want %q", m.Status, domain.MembershipSuspended)
	}
	creds.assertBurned(t, app)
}

// POSITIVE CONTROL. The canonical shape — path "active", a real JSON bool —
// must keep deprovisioning, kill switch and all.
func TestPatch_ActiveBooleanFalse_StillDeprovisions(t *testing.T) {
	app := newTestApp(t)
	const email = "canonical@alpha.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleMember, domain.MembershipActive)
	creds := seedLiveCredentials(t, app, user.ID)

	resp := app.do(t, "PATCH", userPath(app.orgA.orgID, user.ID), app.orgA.apiKey, map[string]any{
		"schemas":    []string{PatchOpSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if mustUser(t, app, user.ID).SuspendedAt == nil {
		t.Fatalf("canonical active:false stopped suspending the account")
	}
	if m := mustMembership(t, app, app.orgA.orgID, user.ID); m.Status != domain.MembershipSuspended {
		t.Fatalf("membership status: got %q want suspended", m.Status)
	}
	creds.assertBurned(t, app)
}

// --- S2: case-variant userName walks past every uniqueness check -------------

// yauth_users.email is unique over plain TEXT and GetUserByEmail is an exact
// match, so "Victim@..." never finds "victim@...". requireAdoptable — the whole
// cross-tenant guard — is therefore never reached, and org A gets a second
// global account for org B's user, EmailVerified:true, with an org-A
// membership attached.
func TestPost_CaseVariantOfForeignAddress_HitsAdoptionGuard(t *testing.T) {
	app := newTestApp(t)
	const lower = "victim@corpb.example"
	const mixed = "Victim@CorpB.example"
	ctx := context.Background()

	victim := seedGlobalUser(t, app, lower, "admin")
	joinOrg(t, app, app.orgB.orgID, victim.ID, auth.RoleAdmin, domain.MembershipActive)

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": mixed,
	})
	defer resp.Body.Close() //nolint:errcheck

	// No second identity for the same address, in any case.
	if dup, err := app.repo.GetUserByEmail(ctx, mixed); err == nil && dup != nil && dup.ID != victim.ID {
		t.Errorf("a SECOND global user row %s was created for %q while %q already belongs to %s — "+
			"two accounts, one human, and the cross-tenant guard never ran", dup.ID, mixed, lower, victim.ID)
	}
	if m, err := app.repo.GetMembershipByOrgUser(ctx, app.orgA.orgID, victim.ID); err == nil && m != nil {
		t.Errorf("victim was enrolled in the attacker's org: %+v", m)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status: got %d want 409 from requireAdoptable", resp.StatusCode)
	}
}

// The same blind spot inside one org: two POSTs differing only in case create
// two accounts for one person, and the second is not idempotent at all.
func TestPost_CaseVariantOfOwnMember_IsIdempotent(t *testing.T) {
	app := newTestApp(t)
	const mixed = "Dave.Grohl@alpha.example"
	const lower = "dave.grohl@alpha.example"

	first := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": mixed,
	})
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first POST: got %d want 201", first.StatusCode)
	}
	firstID := decodeJSON(t, first)["id"].(string)

	second := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": lower,
	})
	defer second.Body.Close() //nolint:errcheck
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("re-POST with different case: got %d want 201 (adoption of the same account)", second.StatusCode)
	}
	secondID := decodeJSON(t, second)["id"].(string)
	if secondID != firstID {
		t.Fatalf("two user rows for one address: %s (%q) and %s (%q) — userName is never normalised, so nothing matched",
			firstID, mixed, secondID, lower)
	}
	u := mustUser(t, app, firstID)
	if u.Email != lower {
		t.Errorf("stored login email is %q; SCIM is the only credential path that does not lower-case, "+
			"so this row can never be matched by GetUserByEmail from the password or magic-link flows", u.Email)
	}
}

// --- S4: a routine re-sync demotes the org's own admins ---------------------

// handleCreateUser writes Role:&auth.RoleMember onto an existing membership.
// Roles are set through the organizations API, which refuses exactly this
// write; SCIM has no business overriding it on every re-sync.
func TestPost_ReSync_DoesNotDemoteExistingOrgAdmin(t *testing.T) {
	app := newTestApp(t)
	const email = "org.admin@alpha.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleAdmin, domain.MembershipActive)

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": email,
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("re-sync of an existing member: got %d want 201", resp.StatusCode)
	}
	m := mustMembership(t, app, app.orgA.orgID, user.ID)
	if m.Role != auth.RoleAdmin {
		t.Fatalf("org role demoted %q → %q by a routine SCIM re-sync", auth.RoleAdmin, m.Role)
	}
}

// POSITIVE CONTROL. Not writing Role must not turn into not writing the
// membership at all: a re-POST of a suspended member is how an IdP
// re-provisions someone, and it must still flip them back to active.
func TestPost_ReSync_StillReactivatesSuspendedMember(t *testing.T) {
	app := newTestApp(t)
	const email = "returning@alpha.example"

	user := seedGlobalUser(t, app, email, "user")
	joinOrg(t, app, app.orgA.orgID, user.ID, auth.RoleAdmin, domain.MembershipSuspended)

	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas": []string{CoreUserSchema}, "userName": email, "active": true,
	})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("re-provision: got %d want 201", resp.StatusCode)
	}
	m := mustMembership(t, app, app.orgA.orgID, user.ID)
	if m.Status != domain.MembershipActive {
		t.Fatalf("membership status: got %q want active — re-provisioning stopped working", m.Status)
	}
	if m.Role != auth.RoleAdmin {
		t.Fatalf("org role demoted %q → %q on re-provision", auth.RoleAdmin, m.Role)
	}
}
