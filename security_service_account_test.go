// Regression suite for the service-account (org-scoped API key) authorization
// bypass.
//
// plugins/apikey's resolver synthesises an AuthUser whose User is the human
// who MINTED the key — carried so audit trails keep a human breadcrumb — and
// every org gate then resolved membership for that human. A key bound to
// org-ci with role=member therefore passed org-admin gates, reached every
// other org its creator belonged to, and could mint a new admin service
// account inside one of them. The key's own organization_id and role had
// never once informed an authorization decision.
//
// Cases assert the REFUSAL (403, and no credential created) and are paired
// with positive controls: an admin-role key still administers its own org,
// and a user-scoped key behaves exactly as before.
//
// Shared harness helpers live in security_refresh_issuer_test.go.
package yauth_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/organizations"
)

type secOrgFixture struct {
	h        *secHarness
	aliceID  string
	memberCI string // org-ci, role=member
	adminCI  string // org-ci, role=admin
	userKey  string // alice's user-scoped key (no org binding)
}

// newSecOrgFixture builds alice as OWNER of both org-ci and org-finance, then
// mints the three credentials the cases compare: a least-privilege service
// account, an admin service account, and alice's own user-scoped key.
func newSecOrgFixture(t *testing.T) *secOrgFixture {
	t.Helper()
	h := newSecHarness(t, func(b *yauth.YAuthBuilder) *yauth.YAuthBuilder {
		return b.
			WithPlugin(apikey.New(apikey.Config{})).
			WithPlugin(organizations.New(organizations.Config{}))
	})
	ctx := context.Background()
	alice := secRegister(t, h, "alice@test.local")

	now := time.Now().UTC()
	for _, o := range []struct{ id, name, slug string }{
		{"org-ci", "CI Org", "ci-org"},
		{"org-finance", "Finance Org", "finance-org"},
	} {
		if _, err := h.repo.CreateOrganization(ctx, domain.NewOrganization{
			ID: o.id, Name: o.name, Slug: o.slug, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("create org %s: %v", o.id, err)
		}
		if _, err := h.repo.CreateMembership(ctx, domain.NewMembership{
			OwnerRoleAuthorized: true, // test fixture: seeds state directly, bypassing the handler layer
			ID:                  "m-" + o.id,
			OrganizationID:      o.id,
			UserID:              alice,
			Role:                auth.RoleOwner,
			Status:              domain.MembershipActive,
			CreatedAt:           now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("create membership %s: %v", o.id, err)
		}
	}

	mintOrgKey := func(id, orgID, role string) string {
		gen, err := apikey.GenerateKey("yak")
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		org, r := orgID, role
		if err := h.repo.CreateAPIKey(ctx, domain.NewAPIKey{
			ID: id, OrganizationID: &org, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
			Name: id, Role: &r, CreatedAt: now, CreatedByUserID: alice,
		}); err != nil {
			t.Fatalf("create api key %s: %v", id, err)
		}
		return gen.Plaintext
	}

	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	uid := alice
	if err := h.repo.CreateAPIKey(ctx, domain.NewAPIKey{
		ID: "k-user", UserID: &uid, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
		Name: "alice-cli", CreatedAt: now, CreatedByUserID: alice,
	}); err != nil {
		t.Fatalf("create user key: %v", err)
	}

	return &secOrgFixture{
		h:        h,
		aliceID:  alice,
		memberCI: mintOrgKey("k-member-ci", "org-ci", auth.RoleMember),
		adminCI:  mintOrgKey("k-admin-ci", "org-ci", auth.RoleAdmin),
		userKey:  gen.Plaintext,
	}
}

// The key says role=member. The route needs org admin. It used to answer 200
// because the gate resolved the membership of alice, the key's creator, who
// owns the org.
func TestServiceAccountKey_RoleOnTheKeyBindsTheGate(t *testing.T) {
	f := newSecOrgFixture(t)

	code, body := secKeyCall(t, http.MethodGet, f.h.url("/organizations/org-ci/api-keys"), f.memberCI, nil)
	if code != http.StatusForbidden {
		t.Fatalf("role=member key reached an org-admin route: %d %s", code, body)
	}

	// Positive control: an admin-role key bound to the SAME org still works,
	// so the gate reads the key's role rather than refusing service accounts
	// wholesale.
	code, body = secKeyCall(t, http.MethodGet, f.h.url("/organizations/org-ci/api-keys"), f.adminCI, nil)
	if code != http.StatusOK {
		t.Fatalf("role=admin key was refused its own org: %d %s", code, body)
	}
}

// The key is bound to org-ci. org-finance is a different tenant, and the only
// thing connecting them was the creator's membership in both.
func TestServiceAccountKey_CannotReachAnotherOrg(t *testing.T) {
	f := newSecOrgFixture(t)

	for _, key := range []struct{ name, k string }{
		{"member", f.memberCI},
		{"admin", f.adminCI},
	} {
		code, body := secKeyCall(t, http.MethodGet, f.h.url("/organizations/org-finance/api-keys"), key.k, nil)
		if code != http.StatusForbidden {
			t.Fatalf("%s key bound to org-ci reached org-finance: %d %s", key.name, code, body)
		}
	}
}

// The full escalation: mint a NEW admin service account inside an org the key
// is not bound to. The refusal has to be checked against the store, not just
// the status line — a key that got created and then errored would still be a
// live credential.
func TestServiceAccountKey_CannotMintKeysInAnotherOrg(t *testing.T) {
	f := newSecOrgFixture(t)

	code, body := secKeyCall(t, http.MethodPost, f.h.url("/organizations/org-finance/api-keys"),
		f.memberCI, map[string]any{"name": "pivot", "role": "admin"})
	if code != http.StatusForbidden {
		t.Fatalf("org-ci key minted into org-finance: %d %s", code, body)
	}
	if strings.Contains(body, "secret") {
		t.Fatalf("a key secret was returned by a refused mint: %s", body)
	}
	keys, err := f.h.repo.ListAPIKeysByOrgID(context.Background(), "org-finance")
	if err != nil {
		t.Fatalf("list org-finance keys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("a key was created in org-finance despite the refusal: %d keys", len(keys))
	}
}

// A service account must not act on its creator's PERSONAL account. The
// sharpest case is the personal key routes: minting a user-scoped key would
// hand the machine a credential with no org binding at all, which resolves as
// the human everywhere.
func TestServiceAccountKey_CannotUseCreatorsPersonalKeyRoutes(t *testing.T) {
	f := newSecOrgFixture(t)

	code, body := secKeyCall(t, http.MethodGet, f.h.url("/api-keys"), f.adminCI, nil)
	if code != http.StatusForbidden {
		t.Fatalf("service account listed its creator's personal keys: %d %s", code, body)
	}

	before, err := f.h.repo.ListAPIKeysByUserID(context.Background(), f.aliceID)
	if err != nil {
		t.Fatalf("list alice's keys: %v", err)
	}
	code, body = secKeyCall(t, http.MethodPost, f.h.url("/api-keys"), f.adminCI,
		map[string]any{"name": "pivot-to-human"})
	if code != http.StatusForbidden {
		t.Fatalf("service account minted a user-scoped key as its creator: %d %s", code, body)
	}
	after, err := f.h.repo.ListAPIKeysByUserID(context.Background(), f.aliceID)
	if err != nil {
		t.Fatalf("list alice's keys: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("a personal key was created despite the refusal: %d → %d", len(before), len(after))
	}
}

// Nothing above may change how a user-scoped key behaves: it is the user, and
// it always was. This is the guard against "fixing" the finding by refusing
// API keys in general.
func TestUserScopedKey_UnchangedByServiceAccountScoping(t *testing.T) {
	f := newSecOrgFixture(t)

	// Alice owns org-ci, so her key passes the org-admin gate.
	code, body := secKeyCall(t, http.MethodGet, f.h.url("/organizations/org-ci/api-keys"), f.userKey, nil)
	if code != http.StatusOK {
		t.Fatalf("alice's user-scoped key was refused her own org: %d %s", code, body)
	}
	// ... in both her orgs.
	code, body = secKeyCall(t, http.MethodGet, f.h.url("/organizations/org-finance/api-keys"), f.userKey, nil)
	if code != http.StatusOK {
		t.Fatalf("alice's user-scoped key was refused org-finance: %d %s", code, body)
	}
	// ... and on her personal key routes.
	code, body = secKeyCall(t, http.MethodGet, f.h.url("/api-keys"), f.userKey, nil)
	if code != http.StatusOK {
		t.Fatalf("alice's user-scoped key was refused her personal keys: %d %s", code, body)
	}
}
