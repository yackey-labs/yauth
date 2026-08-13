package apikey

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
)

// seedOrgKey provisions a creator with the given role/must-change state plus an
// org-scoped API key they created, and returns the plaintext key.
func seedOrgKey(t *testing.T, r *fakeRepo, creatorRole string, creatorMustChange bool) string {
	t.Helper()
	now := time.Now().UTC()
	creator := domain.User{
		ID:                 uuid.NewString(),
		Email:              uuid.NewString() + "@example.com",
		Role:               creatorRole,
		MustChangePassword: creatorMustChange,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	r.putUser(creator)

	gen := mustGenerateKey(t)
	orgID := uuid.NewString()
	role := "admin"
	r.putKey(domain.APIKey{
		ID:              uuid.NewString(),
		OrganizationID:  &orgID,
		KeyPrefix:       gen.Prefix,
		KeyHash:         gen.Hash,
		Name:            "ci-runner",
		Scopes:          []byte("[]"),
		Role:            &role,
		CreatedAt:       now,
		CreatedByUserID: creator.ID,
	})
	return gen.Plaintext
}

// orgKeyRequest is a request carrying the org-scoped key in X-Api-Key.
func orgKeyRequest(plaintext string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, plaintext)
	return req
}

func orgKeyMiddleware(r *fakeRepo, allowMachine bool) *middleware.Middleware {
	h := newFakeHost(r)
	return middleware.New(r, middleware.Config{
		CookieName:               "yauth_session",
		AllowAdminMachineCallers: allowMachine,
	}, newResolver(h, "yak"))
}

func orgKeyOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// End to end through the REAL resolver: an org-scoped API key minted by an
// admin must not reach a RequireAdmin route while AllowAdminMachineCallers is
// false. The resolver copies the creator's full user row (role included) onto
// the synthesised AuthUser, so the role check alone does not stop it — the
// machine-caller gate has to.
func TestOrgScopedKey_DoesNotReachAdminRoutesByDefault(t *testing.T) {
	r := newFakeRepo()
	key := seedOrgKey(t, r, "admin", false)
	mw := orgKeyMiddleware(r, false)

	rec := httptest.NewRecorder()
	mw.RequireAdmin(orgKeyOK()).ServeHTTP(rec, orgKeyRequest(key))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org-scoped key created by an admin reached RequireAdmin: got %d, want 403 (body=%q)",
			rec.Code, rec.Body.String())
	}
}

// This test used to assert the opposite — "the documented opt-in still admits
// it", 200 — and in doing so it PINNED a privilege escalation. The opt-in is
// an operator's decision to trust machine credentials that carry the human's
// GLOBAL role; an org-scoped key is not one of those. It resolves to an
// AuthUser whose User row is the creator (carried for audit) while the
// authority the operator actually granted — the key's own role and permission
// list, capped at mint time — sits on the Principal that ResolveAdmin never
// read. So flipping allow_machine_callers on handed every org key an admin
// had ever minted, role "viewer" and permissions [] included, the whole
// /admin/* surface: list, ban, impersonate, delete any user in any org.
//
// There is no configuration under which that is right, so the refusal is now
// unconditional. See TestUserScopedKey_AdminAndMustChangeUnchanged for the
// credential that the opt-in does still admit.
func TestOrgScopedKey_NeverReachesAdminRoutesEvenWithOptIn(t *testing.T) {
	r := newFakeRepo()
	key := seedOrgKey(t, r, "admin", false)
	mw := orgKeyMiddleware(r, true)

	rec := httptest.NewRecorder()
	mw.RequireAdmin(orgKeyOK()).ServeHTTP(rec, orgKeyRequest(key))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("AllowAdminMachineCallers=true admitted an org-scoped key: got %d, want 403 (body=%q)",
			rec.Code, rec.Body.String())
	}
}

// The other direction, end to end: the key's creator owing a password rotation
// is the HUMAN's problem, not the integration's. RequireAuth must not 403 the
// org key with must_change_password.
func TestOrgScopedKey_NotGatedByCreatorMustChangePassword(t *testing.T) {
	r := newFakeRepo()
	key := seedOrgKey(t, r, "user", true)
	mw := orgKeyMiddleware(r, false)

	rec := httptest.NewRecorder()
	mw.RequireAuth(orgKeyOK()).ServeHTTP(rec, orgKeyRequest(key))
	if rec.Code != http.StatusOK {
		t.Fatalf("org-scoped key blocked by its creator's must_change_password: got %d, want 200 (body=%q)",
			rec.Code, rec.Body.String())
	}
}

// A user-scoped key from the same plugin is unaffected in both directions.
func TestUserScopedKey_AdminAndMustChangeUnchanged(t *testing.T) {
	r := newFakeRepo()
	now := time.Now().UTC()
	admin := domain.User{
		ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Role: "admin",
		MustChangePassword: true, CreatedAt: now, UpdatedAt: now,
	}
	r.putUser(admin)
	gen := mustGenerateKey(t)
	r.putKey(domain.APIKey{
		ID: uuid.NewString(), UserID: &admin.ID, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
		Name: "personal", Scopes: []byte("[]"), CreatedAt: now, CreatedByUserID: admin.ID,
	})

	rec := httptest.NewRecorder()
	orgKeyMiddleware(r, false).RequireAdmin(orgKeyOK()).ServeHTTP(rec, orgKeyRequest(gen.Plaintext))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("user-scoped api-key on RequireAdmin (default): got %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	orgKeyMiddleware(r, true).RequireAdmin(orgKeyOK()).ServeHTTP(rec, orgKeyRequest(gen.Plaintext))
	if rec.Code != http.StatusOK {
		t.Fatalf("user-scoped api-key on RequireAdmin (opt-in, must-change creator): got %d, want 200 (body=%q)",
			rec.Code, rec.Body.String())
	}
}
