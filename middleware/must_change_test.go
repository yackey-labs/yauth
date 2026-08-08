package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
)

// wantMustChangeBody is the exact RFC 9457 body huma.NewError produces for
// huma.WriteErr(api, ctx, 403, MustChangePasswordDetail) — field set and order
// from huma.ErrorModel, Type omitted because it is empty. The net/http gate
// must reproduce it byte for byte so a client sees ONE wire shape for this
// condition regardless of which middleware stack served the route.
const wantMustChangeBody = `{"title":"Forbidden","status":403,"detail":"password change required"}` + "\n"

// assertMustChangeProblem asserts a 403 problem+json must-change response.
func assertMustChangeProblem(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type: want application/problem+json, got %q", ct)
	}
	if got := rec.Body.String(); got != wantMustChangeBody {
		t.Errorf("body:\n got %q\nwant %q", got, wantMustChangeBody)
	}
}

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

	assertMustChangeProblem(t, doCookie(mw.RequireAuth(okHandler()), tok))
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

	assertMustChangeProblem(t, doCookie(mw.RequireAdmin(okHandler()), tok))
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

// The two stacks must produce the SAME wire response for the same condition.
// This drives a real huma operation through RequireAuthHuma and the net/http
// RequireAuth over the identical must-change session, then compares status,
// Content-Type and body bytes. If huma's ErrorModel ever changes shape, this
// fails instead of the two silently drifting apart.
func TestMustChangeGate_HumaAndNetHTTPAgreeByteForByte(t *testing.T) {
	r := newFakeRepo()
	tok := mustChangeFixture(t, r, "user", true)
	mw := New(r, Config{CookieName: "yauth_session"})

	// net/http side.
	netRec := doCookie(mw.RequireAuth(okHandler()), tok)

	// huma side: a trivial operation guarded by RequireAuthHuma.
	mux := http.NewServeMux()
	api := humaapi.New(mux)
	huma.Register(api, huma.Operation{
		OperationID: "mustChangeProbe",
		Method:      http.MethodGet,
		Path:        "/probe",
		Middlewares: huma.Middlewares{RequireAuthHuma(api, mw)},
	}, func(context.Context, *struct{}) (*struct{}, error) {
		return &struct{}{}, nil
	})
	humaReq := httptest.NewRequest(http.MethodGet, "/probe", nil)
	humaReq.AddCookie(&http.Cookie{Name: "yauth_session", Value: tok})
	humaRec := httptest.NewRecorder()
	mux.ServeHTTP(humaRec, humaReq)

	if humaRec.Code != netRec.Code {
		t.Fatalf("status mismatch: huma=%d net/http=%d", humaRec.Code, netRec.Code)
	}
	if got, want := netRec.Header().Get("Content-Type"), humaRec.Header().Get("Content-Type"); got != want {
		t.Errorf("Content-Type mismatch:\n net/http %q\n huma     %q", got, want)
	}
	if got, want := netRec.Body.String(), humaRec.Body.String(); got != want {
		t.Errorf("body mismatch:\n net/http %q\n huma     %q", got, want)
	}
	// And both match the constant the docs publish.
	if humaRec.Body.String() != wantMustChangeBody {
		t.Errorf("huma body drifted from the documented shape:\n got %q\nwant %q",
			humaRec.Body.String(), wantMustChangeBody)
	}
}
