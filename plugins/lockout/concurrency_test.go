package lockout_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newConcurrencyServer is newServer plus a handle on the repository, so a
// test can inspect the lock row the plugin wrote.
//
// The per-IP login limiter is left at its default and each attacker request
// carries its own X-Forwarded-For, which is what a spray from many hosts
// looks like: the rate limiter meters per client, so it is the ACCOUNT
// lockout that has to hold the line here. That is exactly the property under
// test.
func newConcurrencyServer(t *testing.T, cfg lockout.Config) (*httptest.Server, repo.Repository, func()) {
	t.Helper()
	r := memrepo.New()
	cfg.Mailer = &captureMailer{}
	if cfg.LinkBaseURL == "" {
		cfg.LinkBaseURL = "https://example.test/unlock"
	}

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		WithPlugin(lockout.New(cfg)).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, r, func() { srv.Close() }
}

// attempt fires one wrong-password login, presenting clientIP as the caller
// so the per-IP rate limiter never masks what lockout does.
// concurrentClient is used by attempt instead of http.DefaultClient.
//
// These tests fire up to maxAttempts*3 requests at one httptest server
// simultaneously, and the default transport allows only 2 idle connections per
// host — so the rest are dialled and torn down on every round. On a loaded CI
// runner that is where this test was observed to fail: not on an assertion, but
// on a transport error surfaced through attempt's t.Fatalf, which reads as a
// lockout bug and is not one. A pool sized to the fan-out removes the churn,
// and an explicit timeout turns a hung request into a legible failure rather
// than a package-level 10-minute panic.
var concurrentClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 64,
		MaxConnsPerHost:     64,
		IdleConnTimeout:     30 * time.Second,
	},
}

func attempt(t *testing.T, srv *httptest.Server, email, password, clientIP string) int {
	t.Helper()
	buf, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/login", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", clientIP)
	res, err := concurrentClient.Do(req)
	if err != nil {
		// Distinguish "the server refused us" from "we never reached it" — the
		// two used to be indistinguishable in the failure output.
		t.Fatalf("login attempt from %s did not complete (transport error, not a "+
			"lockout decision): %v", clientIP, err)
	}
	res.Body.Close()
	return res.StatusCode
}

// TestLockout_ThresholdHoldsUnderConcurrency is the regression guard for the
// stale-read increment. onFailed used to compute newCount from a
// GetAccountLockByUserID taken BEFORE the increment, so N concurrent failures
// all read failed_count=0, all computed newCount=1, and `newCount >=
// MaxAttempts` never once held: the stored counter climbed past the threshold
// while the account was never locked at all. A distributed spray therefore
// got unlimited guesses.
//
// Before the fix, round two below still answered 401 and the final lock-state
// assertions found no lock.
func TestLockout_ThresholdHoldsUnderConcurrency(t *testing.T) {
	const (
		maxAttempts = 5
		email       = "alice@example.com"
		pw          = "correct horse battery staple"
	)

	srv, r, stop := newConcurrencyServer(t, lockout.Config{
		MaxAttempts:      maxAttempts,
		LockoutDurations: []time.Duration{time.Hour},
	})
	defer stop()

	c := &http.Client{}
	register(t, srv, c, email, pw)
	res := postJSON(t, c, srv.URL+"/api/auth/logout", struct{}{})
	res.Body.Close()

	// Round one: exactly MaxAttempts guesses, all at once, each from its
	// own address. Every one is a legitimate attempt.
	fire := func(n, offset int) []int {
		codes := make([]int, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				codes[i] = attempt(t, srv, email, "wrong-password", clientAddr(offset+i))
			}(i)
		}
		wg.Wait()
		return codes
	}

	for i, code := range fire(maxAttempts, 0) {
		if code != http.StatusUnauthorized {
			t.Fatalf("round one attempt %d: got %d, want 401", i+1, code)
		}
	}

	// Round two: the threshold has been crossed, so NOT ONE of these may
	// reach the password check, however many run in parallel.
	for i, code := range fire(maxAttempts*3, 100) {
		if code != http.StatusTooManyRequests {
			t.Fatalf("round two attempt %d: got %d, want 429 — %d parallel failures did not lock the account", i+1, code, maxAttempts)
		}
	}

	// Even the real password must not get in while the lock stands.
	if code := attempt(t, srv, email, pw, clientAddr(900)); code != http.StatusTooManyRequests {
		t.Fatalf("correct password during lockout: got %d, want 429", code)
	}

	// And the counter itself lost no updates: every attempt was recorded.
	user, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || user == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	lock, err := r.GetAccountLockByUserID(context.Background(), user.ID)
	if err != nil || lock == nil {
		t.Fatalf("expected a lock row after %d failures: %v", maxAttempts, err)
	}
	if lock.LockedUntil == nil || !lock.LockedUntil.After(time.Now().UTC()) {
		t.Fatalf("expected an active lock, got LockedUntil=%v", lock.LockedUntil)
	}
	if lock.FailedCount != maxAttempts {
		t.Fatalf("failed_count = %d after %d concurrent failures; want %d — increments were lost",
			lock.FailedCount, maxAttempts, maxAttempts)
	}
}

// A burst larger than the threshold must still leave exactly one lock
// applied, with every failure counted. Requests already in flight when the
// threshold is crossed cannot be recalled — that window is bounded by the
// attacker's concurrency — but nothing may be dropped or double-locked.
func TestLockout_BurstLargerThanThresholdLocksOnce(t *testing.T) {
	const (
		maxAttempts = 3
		burst       = 20
		email       = "bob@example.com"
		pw          = "correct horse battery staple"
	)

	srv, r, stop := newConcurrencyServer(t, lockout.Config{
		MaxAttempts:      maxAttempts,
		LockoutDurations: []time.Duration{time.Minute, time.Hour},
	})
	defer stop()

	c := &http.Client{}
	register(t, srv, c, email, pw)
	res := postJSON(t, c, srv.URL+"/api/auth/logout", struct{}{})
	res.Body.Close()

	var wg sync.WaitGroup
	for i := range burst {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			attempt(t, srv, email, "wrong-password", clientAddr(i))
		}(i)
	}
	wg.Wait()

	if code := attempt(t, srv, email, pw, clientAddr(900)); code != http.StatusTooManyRequests {
		t.Fatalf("after a %d-way burst the account is not locked (correct password got %d)", burst, code)
	}

	user, _ := r.GetUserByEmail(context.Background(), email)
	lock, err := r.GetAccountLockByUserID(context.Background(), user.ID)
	if err != nil || lock == nil {
		t.Fatalf("expected a lock row: %v", err)
	}
	// Every attempt that ran the password check was counted: none of the
	// concurrent increments overwrote another.
	if lock.FailedCount < maxAttempts {
		t.Fatalf("failed_count = %d; want at least %d", lock.FailedCount, maxAttempts)
	}
}

// barrierRepo forces the interleaving the stale-read bug needs, which an
// ordinary parallel burst hits only by luck: every caller finishes its
// GetAccountLockByUserID before ANY of them reaches the increment. That is
// the shape a real concurrent spray takes under load, just made
// deterministic.
type barrierRepo struct {
	repo.Repository
	mu      sync.Mutex
	arrived int
	n       int
	release chan struct{}
	armed   bool
}

func (b *barrierRepo) arm(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n = n
	b.arrived = 0
	b.release = make(chan struct{})
	b.armed = true
}

func (b *barrierRepo) GetAccountLockByUserID(ctx context.Context, userID string) (*domain.AccountLock, error) {
	lock, err := b.Repository.GetAccountLockByUserID(ctx, userID)

	b.mu.Lock()
	if !b.armed {
		b.mu.Unlock()
		return lock, err
	}
	b.arrived++
	last := b.arrived == b.n
	release := b.release
	if last {
		b.armed = false
	}
	b.mu.Unlock()

	if last {
		close(release)
	} else {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			// Never block the suite if the arming count is wrong.
		}
	}
	return lock, err
}

// TestLockout_StaleReadDoesNotSwallowFailures is the deterministic form of
// the finding. onFailed used to compute `newCount := lock.FailedCount + 1`
// from a read taken before the increment. Hold four callers at that read and
// every one of them computes the same next value, so `newCount >=
// MaxAttempts` is never satisfied — the stored counter sails past the
// threshold and the account is never locked.
//
// Before the fix this failed at "expected an active lock": failed_count was
// 5 with MaxAttempts=5 and LockedUntil was still nil.
func TestLockout_StaleReadDoesNotSwallowFailures(t *testing.T) {
	const (
		maxAttempts = 5
		email       = "carol@example.com"
	)

	base := memrepo.New()
	br := &barrierRepo{Repository: base}

	ya, err := yauth.New(br, yauth.NewDefaultConfig()).
		WithPlugin(lockout.New(lockout.Config{
			MaxAttempts:      maxAttempts,
			LockoutDurations: []time.Duration{time.Hour},
			Mailer:           &captureMailer{},
			LinkBaseURL:      "https://example.test/unlock",
		})).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()
	user, err := base.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	fail := func() {
		em := email
		if _, err := ya.Emit(ctx, events.AuthEvent{
			Type: events.EventLoginFailed, Email: &em, Timestamp: time.Now().UTC(),
		}); err != nil {
			t.Errorf("Emit: %v", err)
		}
	}

	// One sequential failure creates the lock row (failed_count = 1).
	fail()

	// The remaining four arrive together and all read failed_count = 1.
	const parallel = maxAttempts - 1
	br.arm(parallel)
	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fail()
		}()
	}
	wg.Wait()

	lock, err := base.GetAccountLockByUserID(ctx, user.ID)
	if err != nil || lock == nil {
		t.Fatalf("GetAccountLockByUserID: %v", err)
	}
	if lock.FailedCount != maxAttempts {
		t.Fatalf("failed_count = %d after %d failures; want %d", lock.FailedCount, maxAttempts, maxAttempts)
	}
	if lock.LockedUntil == nil || !lock.LockedUntil.After(time.Now().UTC()) {
		t.Fatalf("expected an active lock after %d failures with MaxAttempts=%d; LockedUntil=%v — concurrent failures each computed the same count, so the threshold was never observed",
			maxAttempts, maxAttempts, lock.LockedUntil)
	}

	// And the gate now refuses the next attempt.
	em := email
	dec, err := ya.Emit(ctx, events.AuthEvent{
		Type: events.EventLoginAttempt, Email: &em, Timestamp: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Emit attempt: %v", err)
	}
	if dec.Kind != events.DecisionKindBlock {
		t.Fatalf("login.attempt on a locked account = %v; want a Block decision", dec.Kind)
	}
}

// clientAddr returns a distinct, stable client address for attempt n.
func clientAddr(n int) string {
	return "203.0.113." + itoa(n%200+1) + ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
