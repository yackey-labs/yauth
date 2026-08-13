package middleware

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// serviceAccountAU builds the AuthUser shape the org-scoped API key path in
// plugins/apikey produces: the User is the FULL record of the human who
// created the key (role included), the Method is service-account, and the
// Principal is a ServiceAccount.
func serviceAccountAU(t *testing.T, r *fakeRepo, creatorRole string, creatorMustChange bool) *domain.AuthUser {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	creator, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Role: creatorRole,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	creator.MustChangePassword = creatorMustChange
	orgID := uuid.NewString()
	orgRole := "admin"
	return &domain.AuthUser{
		User:        creator,
		Method:      domain.AuthMethodServiceAccount,
		ActiveOrgID: &orgID,
		OrgRole:     &orgRole,
		Principal:   domain.NewServiceAccountPrincipal(orgID, uuid.NewString(), creator.ID),
	}
}

func serviceAccountMW(t *testing.T, r *fakeRepo, au *domain.AuthUser, allowMachine bool) *Middleware {
	t.Helper()
	hit := &fakeResolver{name: "api-key", recognized: true, user: au}
	return New(r, Config{CookieName: "yauth_session", AllowAdminMachineCallers: allowMachine}, hit)
}

// isMachineMethod is the single predicate behind BOTH the admin machine-caller
// gate and the must-change gate. service-account is a machine credential (an
// org-scoped API key); omitting it from this switch broke both gates at once.
func TestIsMachineMethod_ServiceAccount(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{domain.AuthMethodCookie, false},
		{"", false},
		{domain.AuthMethodBearer, true},
		{domain.AuthMethodAPIKey, true},
		{domain.AuthMethodServiceAccount, true},
	}
	for _, tc := range cases {
		if got := isMachineMethod(tc.method); got != tc.want {
			t.Errorf("isMachineMethod(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}

// The serious direction: an org-scoped API key created by an admin must NOT
// reach an admin route when AllowAdminMachineCallers is false. The credential
// carries the creator's role, so without the machine classification the
// role=="admin" check passes and the machine-caller gate never fires.
func TestResolveAdmin_ServiceAccountRefusedByDefault(t *testing.T) {
	r := newFakeRepo()
	au := serviceAccountAU(t, r, "admin", false)
	mw := serviceAccountMW(t, r, au, false)

	got, err := mw.ResolveAdmin(newAPIKeyRequest())
	if err == nil {
		t.Fatalf("service-account admin key passed ResolveAdmin with AllowAdminMachineCallers=false: %+v", got)
	}
	if !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
}

// ...and RequireAdmin renders that as a 403.
func TestRequireAdmin_ServiceAccountRefusedByDefault(t *testing.T) {
	r := newFakeRepo()
	au := serviceAccountAU(t, r, "admin", false)
	mw := serviceAccountMW(t, r, au, false)

	rec := doCookie(mw.RequireAdmin(okHandler()), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("service-account admin key: expected 403, got %d (body=%q)", rec.Code, rec.Body.String())
	}
}

// INVERTED (was TestResolveAdmin_ServiceAccountAllowedWhenOptedIn, asserting
// 200). That test pinned a privilege escalation: the opt-in exists so an
// operator can trust machine credentials that carry the human's GLOBAL role —
// a bearer token, a user-scoped key — and an org-scoped key is not one. Its
// AuthUser.User is the creator, carried for audit, while the authority the
// operator granted (the key's own role and permission list) lives on the
// Principal that ResolveAdmin never consulted. Turning the flag on therefore
// gave every org key an admin had minted the full /admin/* surface.
//
// The refusal is now unconditional; the flag keeps its meaning for the
// credentials it was actually about — see
// TestUserScopedKey_AdminAndMustChangeUnchanged in the apikey package's
// orgkey_admin_gate_test.go.
func TestResolveAdmin_ServiceAccountRefusedEvenWhenOptedIn(t *testing.T) {
	r := newFakeRepo()
	au := serviceAccountAU(t, r, "admin", false)
	mw := serviceAccountMW(t, r, au, true)

	got, err := mw.ResolveAdmin(newAPIKeyRequest())
	if err == nil {
		t.Fatalf("AllowAdminMachineCallers=true admitted a service account: %+v", got)
	}
	if !errors.Is(err, yautherr.ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	if rec := doCookie(mw.RequireAdmin(okHandler()), ""); rec.Code != http.StatusForbidden {
		t.Fatalf("AllowAdminMachineCallers=true: expected 403, got %d (body=%q)", rec.Code, rec.Body.String())
	}
}

// A non-admin creator is still refused for the ordinary reason (role), with or
// without the opt-in — the machine gate is not the only thing standing there.
func TestResolveAdmin_ServiceAccountNonAdminCreatorStillForbidden(t *testing.T) {
	for _, allow := range []bool{false, true} {
		r := newFakeRepo()
		au := serviceAccountAU(t, r, "user", false)
		mw := serviceAccountMW(t, r, au, allow)
		if _, err := mw.ResolveAdmin(newAPIKeyRequest()); !errors.Is(err, yautherr.ErrForbidden) {
			t.Fatalf("allowMachine=%v: want ErrForbidden, got %v", allow, err)
		}
	}
}

// The second direction: must-change is a password concept, so a service
// account must never be gated by it. Classified as human, the org key inherited
// the CREATOR's must_change_password flag and a machine integration started
// 403ing on a human's password state.
func TestMustRotatePassword_ServiceAccountNotGated(t *testing.T) {
	flagged := domain.User{ID: "u1", MustChangePassword: true}
	au := &domain.AuthUser{
		User:      flagged,
		Method:    domain.AuthMethodServiceAccount,
		Principal: domain.NewServiceAccountPrincipal("org", "key", "u1"),
	}
	if MustRotatePassword(au) {
		t.Fatal("service-account caller must not be gated by must_change_password")
	}
}

// End of the wire, not just the predicate: RequireAuth must let a
// service-account caller through even when the key's creator owes a rotation.
func TestRequireAuth_ServiceAccountNotGatedByCreatorMustChange(t *testing.T) {
	r := newFakeRepo()
	au := serviceAccountAU(t, r, "user", true)
	mw := serviceAccountMW(t, r, au, false)

	rec := doCookie(mw.RequireAuth(okHandler()), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("service-account caller with a must-change creator: expected 200, got %d (body=%q)",
			rec.Code, rec.Body.String())
	}
}

// RETARGETED. This used to drive a SERVICE ACCOUNT through RequireAdmin with
// the opt-in on, which is now refused unconditionally (see
// TestResolveAdmin_ServiceAccountRefusedEvenWhenOptedIn) — so that vehicle no
// longer reaches the gate under test. The carve-out it asserts is still
// correct and still worth pinning: must_change_password is a PASSWORD concept
// and no machine credential should be gated on a human's password state.
//
// The vehicle is now a user-scoped API key, which the opt-in does still admit.
// The same carve-out is covered for service accounts on the paths still open
// to them by TestRequireAuth_ServiceAccountNotGatedByCreatorMustChange and
// TestMustRotatePassword_ServiceAccountNotGated above.
func TestRequireAdmin_MachineCallerNotGatedByOwnerMustChange(t *testing.T) {
	r := newFakeRepo()
	au := serviceAccountAU(t, r, "admin", true)
	// Same admin-owned credential, but user-scoped: Method api-key, plain user
	// principal — the shape plugins/apikey builds for a personal key.
	au.Method = domain.AuthMethodAPIKey
	au.ActiveOrgID, au.OrgRole = nil, nil
	au.Principal = domain.NewUserPrincipal(au.User.ID)
	mw := serviceAccountMW(t, r, au, true)

	rec := doCookie(mw.RequireAdmin(okHandler()), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("user-scoped admin key (opt-in) with a must-change owner: expected 200, got %d (body=%q)",
			rec.Code, rec.Body.String())
	}
}

// newAPIKeyRequest is a bare request; the fakeResolver ignores it, but
// ResolveAdmin needs a non-nil *http.Request.
func newAPIKeyRequest() *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	return req
}
