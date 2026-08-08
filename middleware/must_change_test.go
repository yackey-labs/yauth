package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// mustChangeFixture provisions a user with the given role, flips
// must_change_password on, and returns a raw session cookie token for them.
func mustChangeFixture(t *testing.T, r *fakeRepo, role string, must bool) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	u, err := r.CreateUser(ctx, domain.NewUser{
		ID:        uuid.NewString(),
		Email:     uuid.NewString() + "@example.com",
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if must {
		if err := r.SetUserMustChangePassword(ctx, u.ID, true); err != nil {
			t.Fatalf("SetUserMustChangePassword: %v", err)
		}
	}
	raw, _, err := auth.IssueSession(ctx, r, u.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	return raw
}

func doCookie(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "yauth_session", Value: token})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The net/http RequireAuth must apply the SAME must_change_password gate the
// huma RequireAuthHuma applies. Before this was wired, a consumer that
// protected its own routes the documented way (mux.Handle(...,
// ya.Middleware().RequireAuth(h))) got 200s for a locked-out account.
func TestRequireAuth_MustChangePassword403(t *testing.T) {
	r := newFakeRepo()
	tok := mustChangeFixture(t, r, "user", true)
	mw := New(r, Config{CookieName: "yauth_session"})

	rec := doCookie(mw.RequireAuth(okHandler()), tok)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("must-change cookie user: expected 403, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), MustChangePasswordDetail) {
		t.Fatalf("expected body to carry %q, got %q", MustChangePasswordDetail, rec.Body.String())
	}
}

// A normal user is untouched by the gate.
func TestRequireAuth_NormalUserUnaffected(t *testing.T) {
	r := newFakeRepo()
	tok := mustChangeFixture(t, r, "user", false)
	mw := New(r, Config{CookieName: "yauth_session"})

	rec := doCookie(mw.RequireAuth(okHandler()), tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("normal user: expected 200, got %d (body=%q)", rec.Code, rec.Body.String())
	}
}

// The escape hatch lets the host expose its own change-password / logout
// routes to a locked-out user.
func TestRequireAuthAllowMustChange_LetsThrough(t *testing.T) {
	r := newFakeRepo()
	tok := mustChangeFixture(t, r, "user", true)
	mw := New(r, Config{CookieName: "yauth_session"})

	var sawUser bool
	h := mw.RequireAuthAllowMustChange(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		au, ok := AuthUserFromContext(req.Context())
		sawUser = ok && au.User.MustChangePassword
		w.WriteHeader(http.StatusOK)
	}))

	rec := doCookie(h, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("AllowMustChange: expected 200, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if !sawUser {
		t.Fatal("AllowMustChange: expected the flagged AuthUser to reach the handler")
	}
	// It must still require an identity.
	rec2 := doCookie(h, "")
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("AllowMustChange with no cookie: expected 401, got %d", rec2.Code)
	}
}

// must_change_password is a password concept: machine credentials are never
// gated by RequireAuth, mirroring enforceMustChange's contract.
func TestRequireAuth_MachineCallersNotGated(t *testing.T) {
	r := newFakeRepo()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	u, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "machine@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u.MustChangePassword = true

	for _, method := range []string{domain.AuthMethodBearer, domain.AuthMethodAPIKey} {
		hit := &fakeResolver{
			name:       method,
			recognized: true,
			user:       &domain.AuthUser{User: u, Method: method},
		}
		mw := New(r, Config{CookieName: "yauth_session"}, hit)
		rec := doCookie(mw.RequireAuth(okHandler()), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s caller with must_change_password: expected 200, got %d (body=%q)",
				method, rec.Code, rec.Body.String())
		}
	}
}

// RequireAdmin has no exempt set, so the gate is unconditional there: a
// bootstrapped admin cannot reach the admin API until they rotate.
func TestRequireAdmin_MustChangePassword403(t *testing.T) {
	r := newFakeRepo()
	tok := mustChangeFixture(t, r, "admin", true)
	mw := New(r, Config{CookieName: "yauth_session"})

	rec := doCookie(mw.RequireAdmin(okHandler()), tok)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("must-change admin: expected 403, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), MustChangePasswordDetail) {
		t.Fatalf("expected body to carry %q, got %q", MustChangePasswordDetail, rec.Body.String())
	}
}

// A rotated admin still gets through, and the machine-caller carve-out holds
// for RequireAdmin too when AllowAdminMachineCallers is on.
func TestRequireAdmin_MustChangeCarveOuts(t *testing.T) {
	r := newFakeRepo()
	tok := mustChangeFixture(t, r, "admin", false)
	mw := New(r, Config{CookieName: "yauth_session"})
	if rec := doCookie(mw.RequireAdmin(okHandler()), tok); rec.Code != http.StatusOK {
		t.Fatalf("normal admin: expected 200, got %d", rec.Code)
	}

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	adminUser, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "machine-admin@example.com", Role: "admin",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	adminUser.MustChangePassword = true

	hit := &fakeResolver{
		name:       "bearer",
		recognized: true,
		user:       &domain.AuthUser{User: adminUser, Method: domain.AuthMethodBearer},
	}
	mw2 := New(r, Config{CookieName: "yauth_session", AllowAdminMachineCallers: true}, hit)
	if rec := doCookie(mw2.RequireAdmin(okHandler()), ""); rec.Code != http.StatusOK {
		t.Fatalf("bearer admin with must_change_password (opt-in): expected 200, got %d (body=%q)",
			rec.Code, rec.Body.String())
	}
}

// OptionalAuth is intentionally NOT gated — it authorizes nothing on its own.
func TestOptionalAuth_MustChangeNotGated(t *testing.T) {
	r := newFakeRepo()
	tok := mustChangeFixture(t, r, "user", true)
	mw := New(r, Config{CookieName: "yauth_session"})

	var got bool
	h := mw.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, got = AuthUserFromContext(req.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rec := doCookie(h, tok)
	if rec.Code != http.StatusOK || !got {
		t.Fatalf("OptionalAuth: expected 200 with injected user, got %d inject=%v", rec.Code, got)
	}
}
