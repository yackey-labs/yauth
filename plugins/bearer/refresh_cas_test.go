package bearer_test

// Refresh-token rotation is a read-check-write with no transaction, no row
// lock and no compare-and-swap, so two concurrent uses of the SAME refresh
// token fork the family instead of tripping reuse detection.
//
// registerRefresh (handlers.go) reads the row with GetRefreshTokenByHash,
// tests stored.Revoked in Go, and only then calls RevokeRefreshToken. That
// last call is unconditional in both implementations —
// `UPDATE yauth_refresh_tokens SET revoked = true WHERE id = $1`
// (repo/pgxrepo/queries/oauth.sql) and memrepo's `t.Revoked = true` — so it
// reports success to BOTH callers and neither can tell rotation from
// collision. The sibling statement one line below, RevokeRefreshTokenFamily,
// already carries `AND revoked = false`.
//
// The consequence is the exact scenario rotation exists to detect. An attacker
// who copies a refresh token races the legitimate client; both are served, two
// rotatable branches of one family now exist, and because neither branch ever
// presents an already-revoked token again, the family-revocation trap never
// fires. The stolen branch rolls forward for the whole refresh TTL alongside
// the victim's, invisible.
//
// The interleaving is made deterministic by forkRepo, which holds both
// requests at the point where they have READ the row and not yet written it —
// the window that exists on every deployment, rather than one this test
// invents. The plugin's own fakeRepo cannot host this test: its maps carry no
// lock, so a genuine goroutine race there reports a Go data race instead of
// the defect. memrepo is mutex-guarded and is what the rest of the
// integration tests use.
//
// POSITIVE CONTROL: TestRefresh_SequentialRotationStillWorks drives the same
// harness one request at a time, so a "fix" that refuses concurrent-looking
// refreshes by breaking rotation outright cannot pass.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// forkRepo delegates everything to the real repo but parks the first n callers
// that look up targetHash until all n have arrived, so both in-flight refresh
// requests have completed their READ before either performs its WRITE.
type forkRepo struct {
	repo.Repository

	mu         sync.Mutex
	targetHash string
	n          int
	seen       int
	gate       chan struct{}
}

func newForkRepo(inner repo.Repository, n int) *forkRepo {
	return &forkRepo{Repository: inner, n: n, gate: make(chan struct{})}
}

// arm tells the repo which token hash to synchronise on.
func (f *forkRepo) arm(hash string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targetHash = hash
	f.seen = 0
	f.gate = make(chan struct{})
}

func (f *forkRepo) GetRefreshTokenByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	rt, err := f.Repository.GetRefreshTokenByHash(ctx, hash)

	f.mu.Lock()
	armed := f.targetHash != "" && hash == f.targetHash && err == nil
	var gate chan struct{}
	if armed {
		f.seen++
		gate = f.gate
		if f.seen == f.n {
			close(gate)
		}
	}
	f.mu.Unlock()

	if armed {
		select {
		case <-gate:
		case <-time.After(5 * time.Second):
			// Fail open rather than hang the test binary; the assertions
			// below will report what happened.
		}
	}
	return rt, err
}

type casHarness struct {
	srv  *httptest.Server
	repo repo.Repository
	fork *forkRepo
}

const (
	casEmail    = "rotator@example.com"
	casPassword = "correct horse battery staple"
	casSecret   = "test-secret-min-32-bytes-long-yes-yes"
)

func newCASHarness(t *testing.T, concurrent int) *casHarness {
	t.Helper()
	inner := memrepo.New()
	fr := newForkRepo(inner, concurrent)

	ya, err := yauth.New(fr, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte(casSecret)).
		WithPlugin(bearer.New(bearer.Config{})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx := context.Background()
	now := time.Now().UTC()
	u, err := inner.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: casEmail, Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	hash, err := auth.HashPassword(casPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := inner.UpsertPassword(ctx, domain.NewPassword{UserID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatalf("upsert password: %v", err)
	}
	return &casHarness{srv: srv, repo: inner, fork: fr}
}

type casTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *casHarness) issue(t *testing.T) casTokens {
	t.Helper()
	res, err := http.Post(h.srv.URL+"/api/auth/token", "application/json",
		strings.NewReader(`{"email":"`+casEmail+`","password":"`+casPassword+`"}`))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: status=%d", res.StatusCode)
	}
	var out casTokens
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	return out
}

// refresh posts one rotation and returns the status plus whatever tokens came
// back.
func (h *casHarness) refresh(t *testing.T, refreshToken string) (int, casTokens) {
	t.Helper()
	res, err := http.Post(h.srv.URL+"/api/auth/token/refresh", "application/json",
		strings.NewReader(`{"refresh_token":"`+refreshToken+`"}`))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer res.Body.Close()
	var out casTokens
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// TestRefresh_ConcurrentUseDoesNotForkFamily is the regression.
func TestRefresh_ConcurrentUseDoesNotForkFamily(t *testing.T) {
	h := newCASHarness(t, 2)
	pair := h.issue(t)

	h.fork.arm(auth.HashToken(pair.RefreshToken))

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		codes   []int
		minted  []string
		results = 2
	)
	for i := 0; i < results; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, out := h.refresh(t, pair.RefreshToken)
			mu.Lock()
			codes = append(codes, code)
			if out.RefreshToken != "" {
				minted = append(minted, out.RefreshToken)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("two concurrent uses of ONE refresh token produced %d successful rotations (statuses %v); exactly one must win and the other must be treated as reuse", ok, codes)
	}

	// The assertion that matters is the credential, not the status: after the
	// collision at most ONE rotatable branch of the family may exist.
	live := 0
	for _, raw := range minted {
		rt, err := h.repo.GetRefreshTokenByHash(context.Background(), auth.HashToken(raw))
		if err != nil {
			t.Fatalf("look up minted token: %v", err)
		}
		if !rt.Revoked {
			live++
		}
	}
	if live > 1 {
		t.Errorf("the family forked: %d live rotatable refresh tokens exist after one token was used twice — reuse detection can never fire on either branch", live)
	}

	// And the token that was presented must be revoked exactly once, by
	// whichever caller won.
	old, err := h.repo.GetRefreshTokenByHash(context.Background(), auth.HashToken(pair.RefreshToken))
	if err != nil {
		t.Fatalf("look up presented token: %v", err)
	}
	if !old.Revoked {
		t.Errorf("the presented refresh token is still live after rotation")
	}
}

// TestRefresh_SequentialRotationStillWorks is the POSITIVE CONTROL: with no
// concurrency, rotation must keep working and reuse of the spent token must
// still be caught.
func TestRefresh_SequentialRotationStillWorks(t *testing.T) {
	h := newCASHarness(t, 1)
	pair := h.issue(t)

	code, rotated := h.refresh(t, pair.RefreshToken)
	if code != http.StatusOK {
		t.Fatalf("control: a lone rotation must succeed, got %d", code)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == pair.RefreshToken {
		t.Fatalf("control: rotation must return a NEW refresh token, got %q", rotated.RefreshToken)
	}
	if code2, _ := h.refresh(t, rotated.RefreshToken); code2 != http.StatusOK {
		t.Fatalf("control: the rotated token must itself rotate, got %d", code2)
	}
	// Replaying the original must still be caught as reuse.
	if code3, out := h.refresh(t, pair.RefreshToken); code3 != http.StatusUnauthorized || out.RefreshToken != "" {
		t.Fatalf("control: replaying a spent refresh token must be refused, got %d %+v", code3, out)
	}
}
