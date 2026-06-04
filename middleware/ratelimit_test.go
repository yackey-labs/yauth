package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
)

// stubRateLimitRepo is a minimal RateLimitRepository test double. It
// records each (key, limit, window) tuple and returns whatever
// CheckRateLimitFn produces. Keeping it scoped to ratelimit_test.go
// avoids polluting the broader fakeRepo in middleware_test.go.
type stubRateLimitRepo struct {
	calls     []rlCall
	checkFunc func(key string, limit int, window time.Duration) (domain.RateLimitResult, error)
}

type rlCall struct {
	key    string
	limit  int
	window time.Duration
}

func (s *stubRateLimitRepo) CheckRateLimit(_ context.Context, key string, limit int, window time.Duration) (domain.RateLimitResult, error) {
	s.calls = append(s.calls, rlCall{key: key, limit: limit, window: window})
	if s.checkFunc != nil {
		return s.checkFunc(key, limit, window)
	}
	return domain.RateLimitResult{Allowed: true, Remaining: limit, RetryAfter: 0}, nil
}

func TestRateLimit_Allowed(t *testing.T) {
	stub := &stubRateLimitRepo{
		checkFunc: func(_ string, limit int, _ time.Duration) (domain.RateLimitResult, error) {
			return domain.RateLimitResult{Allowed: true, Remaining: limit - 1}, nil
		},
	}
	called := false
	h := RateLimit(stub, "login", 10, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("expected next handler to be called when allowed")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-RateLimit-Remaining"); got != "9" {
		t.Errorf("X-RateLimit-Remaining: want 9, got %q", got)
	}
	if got := rec.Header().Get("X-RateLimit-Limit"); got != "10" {
		t.Errorf("X-RateLimit-Limit: want 10, got %q", got)
	}

	if len(stub.calls) != 1 {
		t.Fatalf("expected 1 CheckRateLimit call, got %d", len(stub.calls))
	}
	if stub.calls[0].key != "login:203.0.113.5" {
		t.Errorf("key: want login:203.0.113.5, got %q", stub.calls[0].key)
	}
	if stub.calls[0].limit != 10 {
		t.Errorf("limit: want 10, got %d", stub.calls[0].limit)
	}
	if stub.calls[0].window != time.Minute {
		t.Errorf("window: want 1m, got %v", stub.calls[0].window)
	}
}

func TestRateLimit_Blocked(t *testing.T) {
	stub := &stubRateLimitRepo{
		checkFunc: func(_ string, _ int, _ time.Duration) (domain.RateLimitResult, error) {
			return domain.RateLimitResult{Allowed: false, Remaining: 0, RetryAfter: 30 * time.Second}, nil
		},
	}
	called := false
	h := RateLimit(stub, "register", 5, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if called {
		t.Fatalf("next handler must not run when blocked")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-RateLimit-Remaining"); got != "0" {
		t.Errorf("X-RateLimit-Remaining: want 0, got %q", got)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After: want 30, got %q", got)
	}
}

func TestRateLimit_RetryAfterMinimumOneSecond(t *testing.T) {
	stub := &stubRateLimitRepo{
		checkFunc: func(_ string, _ int, _ time.Duration) (domain.RateLimitResult, error) {
			return domain.RateLimitResult{Allowed: false, Remaining: 0, RetryAfter: 100 * time.Millisecond}, nil
		},
	}
	h := RateLimit(stub, "x", 1, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "10.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After should round up to 1, got %q", got)
	}
}

func TestRateLimit_DisabledWhenMaxZero(t *testing.T) {
	stub := &stubRateLimitRepo{}
	called := false
	h := RateLimit(stub, "noop", 0, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "10.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("next must run when limiter disabled")
	}
	if len(stub.calls) != 0 {
		t.Errorf("expected no CheckRateLimit call, got %d", len(stub.calls))
	}
}

func TestRateLimit_FailOpenOnRepoError(t *testing.T) {
	stub := &stubRateLimitRepo{
		checkFunc: func(_ string, _ int, _ time.Duration) (domain.RateLimitResult, error) {
			return domain.RateLimitResult{}, errBackend
		},
	}
	called := false
	h := RateLimit(stub, "login", 10, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("fail-open: next must run on repo error")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRateLimit_KeyPerClient(t *testing.T) {
	stub := &stubRateLimitRepo{}
	h := RateLimit(stub, "login", 10, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i, addr := range []string{"203.0.113.1:1000", "203.0.113.2:1000", "203.0.113.1:1001"} {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = addr
		h.ServeHTTP(httptest.NewRecorder(), req)
		_ = i
	}
	if len(stub.calls) != 3 {
		t.Fatalf("want 3 calls, got %d", len(stub.calls))
	}
	want := []string{"login:203.0.113.1", "login:203.0.113.2", "login:203.0.113.1"}
	for i, c := range stub.calls {
		if c.key != want[i] {
			t.Errorf("call %d key: want %q, got %q", i, want[i], c.key)
		}
	}
}

// errBackend is a sentinel used to drive the fail-open test; defining it
// here keeps the stub independent of yautherr.
var errBackend = stubErr("rate-limit backend down")

type stubErr string

func (s stubErr) Error() string { return string(s) }

// Compile-time guard: the stub must satisfy the repo interface this
// middleware actually consumes. (The full repo.Repository is too broad
// for this scoped test.)
var _ interface {
	CheckRateLimit(context.Context, string, int, time.Duration) (domain.RateLimitResult, error)
} = (*stubRateLimitRepo)(nil)
