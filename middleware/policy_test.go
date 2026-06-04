package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// activeOrg returns a *string for ergonomic AuthUser construction.
func sp(v string) *string { return &v }

func TestOrgPolicy_NoActiveOrgIsPassThrough(t *testing.T) {
	r := memrepo.New()
	enf := middleware.NewOrgPolicyEnforcer(r, middleware.PolicyGlobals{SessionTTL: time.Hour})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := enf.Wrap(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	au := &domain.AuthUser{User: domain.User{ID: "u1"}, Session: domain.Session{UserID: "u1", CreatedAt: time.Now().UTC()}}
	ctx := contextWithAuthUserForTest(req.Context(), au)
	h.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))
	if !called {
		t.Fatal("expected next handler to run when no active org")
	}
}

func TestOrgPolicy_IPAllowlistBlocks(t *testing.T) {
	r := memrepo.New()
	_, err := r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{
		OrganizationID: "o1",
		IPAllowlist:    []string{"10.0.0.0/8"},
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	enf := middleware.NewOrgPolicyEnforcer(r, middleware.PolicyGlobals{SessionTTL: time.Hour})
	called := false
	h := enf.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	au := &domain.AuthUser{
		User:        domain.User{ID: "u1"},
		Session:     domain.Session{UserID: "u1", CreatedAt: time.Now().UTC()},
		ActiveOrgID: sp("o1"),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:1234"
	req = req.WithContext(contextWithAuthUserForTest(req.Context(), au))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403; got %d", rec.Code)
	}
	if called {
		t.Fatal("next must NOT be called on block")
	}
}

func TestOrgPolicy_IPAllowlistPermits(t *testing.T) {
	r := memrepo.New()
	_, _ = r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{
		OrganizationID: "o1",
		IPAllowlist:    []string{"10.0.0.0/8"},
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	enf := middleware.NewOrgPolicyEnforcer(r, middleware.PolicyGlobals{SessionTTL: time.Hour})
	called := false
	h := enf.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	au := &domain.AuthUser{
		User:        domain.User{ID: "u1"},
		Session:     domain.Session{UserID: "u1", CreatedAt: time.Now().UTC()},
		ActiveOrgID: sp("o1"),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req = req.WithContext(contextWithAuthUserForTest(req.Context(), au))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200; got %d", rec.Code)
	}
	if !called {
		t.Fatal("next must be called when IP permitted")
	}
}

func TestOrgPolicy_IdleTimeoutBlocks(t *testing.T) {
	r := memrepo.New()
	_, _ = r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{
		OrganizationID:  "o1",
		IdleTimeoutSecs: i64ptrForTest(60), // 60s idle
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	})

	enf := middleware.NewOrgPolicyEnforcer(r, middleware.PolicyGlobals{SessionTTL: time.Hour})
	h := enf.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	old := time.Now().UTC().Add(-2 * time.Minute)
	au := &domain.AuthUser{
		User:        domain.User{ID: "u1"},
		Session:     domain.Session{UserID: "u1", CreatedAt: old},
		ActiveOrgID: sp("o1"),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req = req.WithContext(contextWithAuthUserForTest(req.Context(), au))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401; got %d", rec.Code)
	}
}

// contextWithAuthUserForTest mirrors the unexported test helper used by
// the middleware package's other test files — but since AuthUserFromContext
// is the only exported way to read the slot, we use the public injection
// path here by mounting RequireAuth in front of the wrapped handler.
//
// The simplest correct approach is to use middleware.New(repo, cfg) and a
// stub resolver — but for this focused per-org enforcement test we can
// short-circuit by calling the enforcer's Wrap with a context that already
// carries the AuthUser via WithValue under the package's ctxKey. The key
// is unexported, so we use the public seam: a small resolver-backed test
// middleware.
//
// For the policy enforcement tests above we instead use the package's
// internal helper exported solely for tests. To keep this file from
// touching internals, the helper below uses the OptionalAuth path with a
// stub resolver, which is the documented public way to attach AuthUser
// to the request context.
func contextWithAuthUserForTest(ctx context.Context, au *domain.AuthUser) context.Context {
	// Re-use the middleware's exported test helper: hydrate via a
	// resolver-backed pipeline by writing the AuthUser through the
	// public AuthUserFromContext path.
	return middleware.WithAuthUserForTest(ctx, au)
}

func i64ptrForTest(v int64) *int64 { return &v }
