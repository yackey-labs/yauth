// key_permissions_test.go — regression suite for "SCIM ignores the API key's
// role and permissions".
//
// authenticate() bound a key to its org (and, after #83, refused cross-tenant
// subjects) but never read rec.Role or rec.Scopes. Org API keys are minted with
// a role bounded by the creator and an explicit permission subset
// (plugins/organizations.validateServiceAccountRole /
// validateServiceAccountPermissions), and the organizations plugin honoured the
// role — SCIM honoured neither. So a key minted at role="viewer" with
// permissions ["members:view"], the shape an operator picks when they want a
// read-only directory sync, held the entire SCIM write surface: provision
// users, rewrite a global login email (→ password-reset takeover), suspend an
// account and flush its sessions, delete the membership.
//
// Every case below asserts the REFUSAL ON STATE, not on the response envelope:
// after a 403 the user row, the membership row and the suspension flags must be
// byte-for-byte what they were, and a refused POST must leave no user behind. A
// handler that answered 403 and wrote anyway would pass a status-code
// assertion and fail these.
//
// Paired with positive controls: the read-only key must still read (or the
// "fix" is just an outage), and an admin key must still do everything.
package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- fixtures -----------------------------------------------------------

// keySpec describes an org-scoped API key to mint for a test.
type keySpec struct {
	role  string   // "" means the row carries no role
	perms []string // nil means the row carries no permission list
}

// seedKey mints an extra org-scoped API key against an existing org and
// returns its plaintext bearer. Distinct hex per call so several keys can
// coexist in one repo (GetAPIKeyByPrefix is keyed on the prefix).
func seedKey(t *testing.T, r repo.Repository, orgID, createdBy string, n int, spec keySpec) string {
	t.Helper()
	prefix := fmt.Sprintf("%08x", 0xbeef0000+n)
	secret := fmt.Sprintf("%032x", 0xfeed0000+n)

	input := domain.NewAPIKey{
		ID:              uuid.NewString(),
		OrganizationID:  &orgID,
		KeyPrefix:       prefix,
		KeyHash:         hashSecret(secret),
		Name:            fmt.Sprintf("scoped key %d", n),
		CreatedAt:       time.Now().UTC(),
		CreatedByUserID: createdBy,
	}
	if spec.role != "" {
		role := spec.role
		input.Role = &role
	}
	if spec.perms != nil {
		raw, err := json.Marshal(spec.perms)
		if err != nil {
			t.Fatalf("marshal perms: %v", err)
		}
		input.Scopes = raw
	}
	if err := r.CreateAPIKey(context.Background(), input); err != nil {
		t.Fatalf("create api key: %v", err)
	}
	return "yak_" + prefix + "_" + secret
}

// userSnapshot is the state a refused SCIM write must not have touched.
type userSnapshot struct {
	email            string
	suspendedAt      *time.Time
	suspendedReason  *string
	membershipStatus domain.MembershipStatus
	membershipRole   string
	membershipExists bool
}

func snapshotUser(t *testing.T, r repo.Repository, orgID, userID string) userSnapshot {
	t.Helper()
	ctx := context.Background()
	u, err := r.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("snapshot user %s: %v", userID, err)
	}
	snap := userSnapshot{
		email:           u.Email,
		suspendedAt:     u.SuspendedAt,
		suspendedReason: u.SuspendedReason,
	}
	m, err := r.GetMembershipByOrgUser(ctx, orgID, userID)
	if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("snapshot membership: %v", err)
	}
	if m != nil {
		snap.membershipExists = true
		snap.membershipStatus = m.Status
		snap.membershipRole = m.Role
	}
	return snap
}

// assertUnchanged fails when any field of the user's persisted state moved.
func assertUnchanged(t *testing.T, r repo.Repository, orgID, userID string, want userSnapshot, what string) {
	t.Helper()
	got := snapshotUser(t, r, orgID, userID)
	if got.email != want.email {
		t.Fatalf("%s: login email was rewritten despite refusal: %q -> %q", what, want.email, got.email)
	}
	if (got.suspendedAt == nil) != (want.suspendedAt == nil) {
		t.Fatalf("%s: suspension state changed despite refusal (want suspendedAt nil=%v, got nil=%v)",
			what, want.suspendedAt == nil, got.suspendedAt == nil)
	}
	if (got.suspendedReason == nil) != (want.suspendedReason == nil) {
		t.Fatalf("%s: suspension reason changed despite refusal", what)
	}
	if got.membershipExists != want.membershipExists {
		t.Fatalf("%s: membership existence changed despite refusal (want %v, got %v)",
			what, want.membershipExists, got.membershipExists)
	}
	if got.membershipStatus != want.membershipStatus || got.membershipRole != want.membershipRole {
		t.Fatalf("%s: membership changed despite refusal: %+v -> %+v", what, want, got)
	}
}

// newAppWithConfig mirrors newTestApp but lets a test set scim.Config.
func newAppWithConfig(t *testing.T, cfg Config) *testApp {
	t.Helper()
	r := memrepo.New()
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	p := New(cfg).(*scimPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return &testApp{srv: srv, repo: r, orgA: seedTenant(t, r, "alpha"), orgB: seedTenant(t, r, "beta")}
}

// --- the refusals -------------------------------------------------------

// TestScim_ViewerKeyWithMembersView_CannotWrite is the finding, verbatim: a key
// minted at role=viewer with permissions ["members:view"] must read and only
// read. Each write is checked against persisted state, not the status line.
func TestScim_ViewerKeyWithMembersView_CannotWrite(t *testing.T) {
	app := newTestApp(t)
	victim := seedScimUser(t, app, "victim@alpha.example")
	before := snapshotUser(t, app.repo, app.orgA.orgID, victim)

	readOnly := seedKey(t, app.repo, app.orgA.orgID, app.orgA.adminID, 1,
		keySpec{role: "viewer", perms: []string{"members:view"}})

	// Positive control first: the key must still be able to READ, or the fix
	// is an outage wearing a security fix's clothes.
	if resp := app.do(t, "GET", usersPath(app.orgA.orgID), readOnly, nil); resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		t.Fatalf("read-only key must still list users: got %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}
	if resp := app.do(t, "GET", userPath(app.orgA.orgID, victim), readOnly, nil); resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		t.Fatalf("read-only key must still fetch a user: got %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Each write is its own subtest so ALL of them are exercised on a run
	// where the gate is missing — a Fatalf chain would only ever report the
	// first, and "the first one 403s" is not the claim being made.

	t.Run("provision", func(t *testing.T) {
		const freshEmail = "smuggled@alpha.example"
		resp := app.do(t, "POST", usersPath(app.orgA.orgID), readOnly, map[string]any{
			"schemas":  []string{CoreUserSchema},
			"userName": freshEmail,
			"emails":   []map[string]any{{"value": freshEmail, "primary": true}},
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST /Users with a members:view key: want 403, got %d", resp.StatusCode)
		}
		if u, err := app.repo.GetUserByEmail(context.Background(), freshEmail); err == nil && u != nil {
			t.Fatalf("POST was refused but the user was created anyway: %s", u.ID)
		}
	})

	// Attribute rewrite — the password-reset takeover primitive.
	t.Run("rewrite login email", func(t *testing.T) {
		resp := app.do(t, "PUT", userPath(app.orgA.orgID, victim), readOnly, map[string]any{
			"schemas":  []string{CoreUserSchema},
			"userName": "attacker@evil.example",
			"emails":   []map[string]any{{"value": "attacker@evil.example", "primary": true}},
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("PUT /Users/{id}: want 403, got %d", resp.StatusCode)
		}
		assertUnchanged(t, app.repo, app.orgA.orgID, victim, before, "PUT")
	})

	// Deprovisioning via PATCH active:false — global suspend + session flush.
	t.Run("deprovision via active:false", func(t *testing.T) {
		resp := app.do(t, "PATCH", userPath(app.orgA.orgID, victim), readOnly, map[string]any{
			"schemas":    []string{PatchOpSchema},
			"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("PATCH active:false: want 403, got %d", resp.StatusCode)
		}
		assertUnchanged(t, app.repo, app.orgA.orgID, victim, before, "PATCH active:false")
	})

	// Groups are role assignment — the same write authority, and the
	// self-promotion route out of a read-only key.
	t.Run("promote via Groups", func(t *testing.T) {
		resp := app.do(t, "PATCH", groupsPath(app.orgA.orgID)+"/role:admin", readOnly, map[string]any{
			"schemas": []string{PatchOpSchema},
			"Operations": []map[string]any{{
				"op":    "add",
				"path":  "members",
				"value": []map[string]any{{"value": victim}},
			}},
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("PATCH /Groups/role:admin: want 403, got %d", resp.StatusCode)
		}
		assertUnchanged(t, app.repo, app.orgA.orgID, victim, before, "PATCH /Groups (self-promotion)")
	})

	// DELETE goes last: it is the one that, if it slips through, destroys the
	// fixture the earlier subtests assert against.
	t.Run("deprovision via DELETE", func(t *testing.T) {
		resp := app.do(t, "DELETE", userPath(app.orgA.orgID, victim), readOnly, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("DELETE /Users/{id}: want 403, got %d", resp.StatusCode)
		}
		assertUnchanged(t, app.repo, app.orgA.orgID, victim, before, "DELETE")
	})
}

// TestScim_RoleWithoutScopes_IsHonoured proves the role alone is enough to
// refuse: a key minted at role=viewer and NO permission list must not write,
// even though it declares no scopes to narrow.
func TestScim_RoleWithoutScopes_IsHonoured(t *testing.T) {
	app := newTestApp(t)
	victim := seedScimUser(t, app, "roleonly@alpha.example")
	before := snapshotUser(t, app.repo, app.orgA.orgID, victim)

	viewer := seedKey(t, app.repo, app.orgA.orgID, app.orgA.adminID, 2, keySpec{role: "viewer"})

	resp := app.do(t, "DELETE", userPath(app.orgA.orgID, victim), viewer, nil)
	if resp.StatusCode != http.StatusForbidden {
		defer resp.Body.Close()
		t.Fatalf("viewer-role key DELETE: want 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	assertUnchanged(t, app.repo, app.orgA.orgID, victim, before, "viewer-role DELETE")
}

// TestScim_ScopesNarrowAnAdminRole proves the scope list is enforced in its own
// right, not merely as a proxy for the role: an ADMIN-role key whose operator
// listed only members:view is read-only. This is the case that made
// APIKey.Scopes a documented control that did nothing.
func TestScim_ScopesNarrowAnAdminRole(t *testing.T) {
	app := newTestApp(t)
	victim := seedScimUser(t, app, "narrowed@alpha.example")
	before := snapshotUser(t, app.repo, app.orgA.orgID, victim)

	narrowed := seedKey(t, app.repo, app.orgA.orgID, app.orgA.adminID, 3,
		keySpec{role: "admin", perms: []string{"members:view"}})

	if resp := app.do(t, "GET", usersPath(app.orgA.orgID), narrowed, nil); resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		t.Fatalf("narrowed admin key must still read: got %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	resp := app.do(t, "PATCH", userPath(app.orgA.orgID, victim), narrowed, map[string]any{
		"schemas":    []string{PatchOpSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	})
	if resp.StatusCode != http.StatusForbidden {
		defer resp.Body.Close()
		t.Fatalf("admin key scoped to members:view must not deprovision: want 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	assertUnchanged(t, app.repo, app.orgA.orgID, victim, before, "scoped-admin PATCH active:false")
}

// TestScim_ScopedKeyWithFullLifecycle_CanWrite is the positive control for the
// permission mapping: a key that lists exactly the four member-lifecycle
// permissions works end to end. Without it a bug that refuses everything would
// pass every case above.
func TestScim_ScopedKeyWithFullLifecycle_CanWrite(t *testing.T) {
	app := newTestApp(t)
	full := seedKey(t, app.repo, app.orgA.orgID, app.orgA.adminID, 4, keySpec{
		role:  "admin",
		perms: []string{"members:view", "members:invite", "members:change_role", "members:remove"},
	})

	const email = "provisioned@alpha.example"
	resp := app.do(t, "POST", usersPath(app.orgA.orgID), full, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
	})
	if resp.StatusCode != http.StatusCreated {
		defer resp.Body.Close()
		t.Fatalf("fully-scoped key POST /Users: want 201, got %d", resp.StatusCode)
	}
	uid := decodeJSON(t, resp)["id"].(string)

	resp = app.do(t, "DELETE", userPath(app.orgA.orgID, uid), full, nil)
	if resp.StatusCode != http.StatusNoContent {
		defer resp.Body.Close()
		t.Fatalf("fully-scoped key DELETE /Users/{id}: want 204, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	if m, _ := app.repo.GetMembershipByOrgUser(context.Background(), app.orgA.orgID, uid); m != nil {
		t.Fatalf("DELETE succeeded but membership survived")
	}
}

// --- the grandfathering decision ---------------------------------------

// TestScim_UnscopedKey_IsGrandfatheredByDefault documents the upgrade
// behaviour deliberately: a key with NEITHER a role NOR permissions — the shape
// every SCIM key minted before this change has, because the setup docs never
// asked for either — keeps working. Refusing it would silently stop
// deprovisioning across every existing integration on a routine version bump.
func TestScim_UnscopedKey_IsGrandfatheredByDefault(t *testing.T) {
	app := newTestApp(t)
	legacy := seedKey(t, app.repo, app.orgA.orgID, app.orgA.adminID, 5, keySpec{})

	const email = "legacy-provisioned@alpha.example"
	resp := app.do(t, "POST", usersPath(app.orgA.orgID), legacy, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
	})
	if resp.StatusCode != http.StatusCreated {
		defer resp.Body.Close()
		t.Fatalf("unscoped legacy key must still provision by default: want 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestScim_UnscopedKey_RefusedWhenRequireKeyPermissions is the other half: the
// one-line opt-in an operator flips once every SCIM key has been re-minted.
func TestScim_UnscopedKey_RefusedWhenRequireKeyPermissions(t *testing.T) {
	app := newAppWithConfig(t, Config{RequireKeyPermissions: true})
	legacy := seedKey(t, app.repo, app.orgA.orgID, app.orgA.adminID, 6, keySpec{})

	const email = "refused@alpha.example"
	resp := app.do(t, "POST", usersPath(app.orgA.orgID), legacy, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
	})
	if resp.StatusCode != http.StatusForbidden {
		defer resp.Body.Close()
		t.Fatalf("RequireKeyPermissions must refuse an unscoped key: want 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	if u, err := app.repo.GetUserByEmail(context.Background(), email); err == nil && u != nil {
		t.Fatalf("refused POST created the user anyway: %s", u.ID)
	}

	// Reads are refused too — an unscoped key holds nothing under strict mode.
	resp = app.do(t, "GET", usersPath(app.orgA.orgID), legacy, nil)
	if resp.StatusCode != http.StatusForbidden {
		defer resp.Body.Close()
		t.Fatalf("RequireKeyPermissions must refuse unscoped reads: want 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
