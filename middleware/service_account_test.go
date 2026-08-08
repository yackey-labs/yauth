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

// The opt-in still works: AllowAdminMachineCallers=true admits the org key,
// exactly as it admits bearer and api-key callers.
func TestResolveAdmin_ServiceAccountAllowedWhenOptedIn(t *testing.T) {
	r := newFakeRepo()
	au := serviceAccountAU(t, r, "admin", false)
	mw := serviceAccountMW(t, r, au, true)

	if _, err := mw.ResolveAdmin(newAPIKeyRequest()); err != nil {
		t.Fatalf("AllowAdminMachineCallers=true: expected the org key through, got %v", err)
	}
	if rec := doCookie(mw.RequireAdmin(okHandler()), ""); rec.Code != http.StatusOK {
		t.Fatalf("AllowAdminMachineCallers=true: expected 200, got %d (body=%q)", rec.Code, rec.Body.String())
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

// And on the admin path with the opt-in on: the machine carve-out from the
// must-change gate applies to org keys the same way it applies to bearer.
func TestRequireAdmin_ServiceAccountNotGatedByCreatorMustChange(t *testing.T) {
	r := newFakeRepo()
	au := serviceAccountAU(t, r, "admin", true)
	mw := serviceAccountMW(t, r, au, true)

	rec := doCookie(mw.RequireAdmin(okHandler()), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("service-account admin key (opt-in) with a must-change creator: expected 200, got %d (body=%q)",
			rec.Code, rec.Body.String())
	}
}

// newAPIKeyRequest is a bare request; the fakeResolver ignores it, but
// ResolveAdmin needs a non-nil *http.Request.
func newAPIKeyRequest() *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	return req
}
