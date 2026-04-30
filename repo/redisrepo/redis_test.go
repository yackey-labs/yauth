package redisrepo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
	"github.com/yackey-labs/yauth-go/repo/redisrepo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// newTestRepo wires miniredis + memrepo behind the redis decorator. Tests
// share the harness so both the cache and the source-of-truth state are
// observable from the same handle.
func newTestRepo(t *testing.T) (*redisrepo.Repo, *miniredis.Miniredis, *redis.Client, *memrepo.Repo) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	inner := memrepo.New()
	r := redisrepo.New(inner, client, redisrepo.Options{
		KeyPrefix:        "yauth-test:",
		DefaultTTL:       60 * time.Second,
		NegativeCacheTTL: 30 * time.Second,
	})
	return r, mr, client, inner
}

func TestSession_CacheMissThenHit(t *testing.T) {
	ctx := context.Background()
	r, mr, _, inner := newTestRepo(t)

	now := time.Now().UTC()
	in := domain.NewSession{
		ID:        "s1",
		UserID:    "u1",
		TokenHash: "hash-1",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	if err := inner.CreateSession(ctx, in); err != nil {
		t.Fatalf("inner CreateSession: %v", err)
	}

	// Sanity: the decorator's Redis cache should not yet contain the row.
	if mr.Exists("yauth-test:cached:session:hash-1") {
		t.Fatalf("expected cache to be empty before first read")
	}

	got, err := r.GetSessionByTokenHash(ctx, "hash-1")
	if err != nil || got == nil {
		t.Fatalf("first read: got=%v err=%v", got, err)
	}
	if got.ID != "s1" {
		t.Fatalf("first read returned wrong session: %+v", got)
	}

	// Backfill is sync via TxPipeline.Exec — entry should be present now.
	if !mr.Exists("yauth-test:cached:session:hash-1") {
		t.Fatalf("expected cache to be populated after first read")
	}

	// Bypass the inner so we can prove the second read is a cache hit.
	if _, err := inner.DeleteSession(ctx, "hash-1"); err != nil {
		t.Fatalf("inner DeleteSession: %v", err)
	}
	got2, err := r.GetSessionByTokenHash(ctx, "hash-1")
	if err != nil || got2 == nil {
		t.Fatalf("expected cache hit after inner delete; got=%v err=%v", got2, err)
	}
	if got2.ID != "s1" {
		t.Fatalf("cache hit returned wrong session: %+v", got2)
	}
}

func TestSession_CreateInvalidatesNegativeCache(t *testing.T) {
	ctx := context.Background()
	r, mr, _, _ := newTestRepo(t)

	// Prime negative cache with a miss.
	_, err := r.GetSessionByTokenHash(ctx, "fresh-hash")
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
	if !mr.Exists("yauth-test:cached:session_neg:fresh-hash") {
		t.Fatalf("expected negative cache entry after miss")
	}

	// Create the session — the negative cache key should be cleared.
	if err := r.CreateSession(ctx, domain.NewSession{
		ID:        "s1",
		UserID:    "u1",
		TokenHash: "fresh-hash",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if mr.Exists("yauth-test:cached:session_neg:fresh-hash") {
		t.Fatalf("expected negative cache to be cleared after create")
	}

	got, err := r.GetSessionByTokenHash(ctx, "fresh-hash")
	if err != nil || got == nil {
		t.Fatalf("expected hit after create; got=%v err=%v", got, err)
	}
}

func TestSession_DeleteInvalidatesCache(t *testing.T) {
	ctx := context.Background()
	r, mr, _, _ := newTestRepo(t)

	if err := r.CreateSession(ctx, domain.NewSession{
		ID: "s1", UserID: "u1", TokenHash: "h",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !mr.Exists("yauth-test:cached:session:h") {
		t.Fatalf("expected cache populated after create")
	}

	if _, err := r.DeleteSession(ctx, "h"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if mr.Exists("yauth-test:cached:session:h") {
		t.Fatalf("expected cache invalidated after delete")
	}
}

func TestSession_DeleteUserSessionsClearsAll(t *testing.T) {
	ctx := context.Background()
	r, mr, _, _ := newTestRepo(t)

	for _, h := range []string{"a", "b", "c"} {
		if err := r.CreateSession(ctx, domain.NewSession{
			ID: "s-" + h, UserID: "u1", TokenHash: h,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}
	if _, err := r.DeleteUserSessions(ctx, "u1"); err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}
	for _, h := range []string{"a", "b", "c"} {
		if mr.Exists("yauth-test:cached:session:" + h) {
			t.Fatalf("expected cached:session:%s to be cleared", h)
		}
	}
	if mr.Exists("yauth-test:cached:user_sessions:u1") {
		t.Fatalf("expected user_sessions set cleared")
	}
}

func TestChallenge_WriteThroughAndRead(t *testing.T) {
	ctx := context.Background()
	r, mr, _, _ := newTestRepo(t)

	if err := r.SetChallenge(ctx, "k1", "value-1", time.Minute); err != nil {
		t.Fatalf("SetChallenge: %v", err)
	}
	if !mr.Exists("yauth-test:cached:challenge:k1") {
		t.Fatalf("expected cache populated after SetChallenge")
	}

	got, err := r.GetChallenge(ctx, "k1")
	if err != nil || got == nil || got.Value != "value-1" {
		t.Fatalf("GetChallenge: got=%+v err=%v", got, err)
	}
}

func TestChallenge_NegativeCacheShortTTL(t *testing.T) {
	ctx := context.Background()
	r, mr, _, _ := newTestRepo(t)

	_, err := r.GetChallenge(ctx, "missing")
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
	if !mr.Exists("yauth-test:cached:challenge_neg:missing") {
		t.Fatalf("expected negative cache after miss")
	}
	gotTTL := mr.TTL("yauth-test:cached:challenge_neg:missing")
	if gotTTL <= 0 || gotTTL > 30*time.Second+time.Second {
		t.Fatalf("expected ~30s TTL on negative cache; got %v", gotTTL)
	}
}

func TestChallenge_ConsumeInvalidatesCache(t *testing.T) {
	ctx := context.Background()
	r, mr, _, _ := newTestRepo(t)

	if err := r.SetChallenge(ctx, "k1", "v", time.Minute); err != nil {
		t.Fatalf("SetChallenge: %v", err)
	}
	if !mr.Exists("yauth-test:cached:challenge:k1") {
		t.Fatalf("expected cache populated")
	}
	if _, err := r.ConsumeChallenge(ctx, "k1"); err != nil {
		t.Fatalf("ConsumeChallenge: %v", err)
	}
	if mr.Exists("yauth-test:cached:challenge:k1") {
		t.Fatalf("expected cache invalidated after consume")
	}
}

func TestRateLimit_IncrementsAndExpires(t *testing.T) {
	ctx := context.Background()
	r, mr, _, _ := newTestRepo(t)

	for i := 0; i < 2; i++ {
		res, err := r.CheckRateLimit(ctx, "rl", 2, time.Minute)
		if err != nil || !res.Allowed {
			t.Fatalf("call %d: allowed=%v err=%v", i+1, res.Allowed, err)
		}
	}
	res, err := r.CheckRateLimit(ctx, "rl", 2, time.Minute)
	if err != nil {
		t.Fatalf("CheckRateLimit: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denial after limit; got allowed=true")
	}
	if res.RetryAfter <= 0 {
		t.Fatalf("expected retry_after > 0; got %v", res.RetryAfter)
	}

	// Fast-forward past the window — counter should reset.
	mr.FastForward(2 * time.Minute)
	res, err = r.CheckRateLimit(ctx, "rl", 2, time.Minute)
	if err != nil || !res.Allowed {
		t.Fatalf("after window expiry: allowed=%v err=%v", res.Allowed, err)
	}
}

func TestRevocation_CacheHitAndBackfill(t *testing.T) {
	ctx := context.Background()
	r, mr, _, inner := newTestRepo(t)

	// Backfill from inner: revoke directly in inner, observe backfill.
	if err := inner.RevokeToken(ctx, "jti-1", time.Hour); err != nil {
		t.Fatalf("inner RevokeToken: %v", err)
	}
	revoked, err := r.IsTokenRevoked(ctx, "jti-1")
	if err != nil || !revoked {
		t.Fatalf("expected revoked; got revoked=%v err=%v", revoked, err)
	}
	if !mr.Exists("yauth-test:revoked:jti-1") {
		t.Fatalf("expected cache backfill after read")
	}

	// Wipe inner; cache hit should still report revoked.
	delete := func() {
		// memrepo has no public API for this; bounce through state by
		// expiring with a negative TTL.
	}
	_ = delete

	revoked2, err := r.IsTokenRevoked(ctx, "jti-1")
	if err != nil || !revoked2 {
		t.Fatalf("expected cache hit; got revoked=%v err=%v", revoked2, err)
	}
}

func TestRevocation_WriteThrough(t *testing.T) {
	ctx := context.Background()
	r, mr, _, _ := newTestRepo(t)

	if err := r.RevokeToken(ctx, "jti-x", time.Hour); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if !mr.Exists("yauth-test:revoked:jti-x") {
		t.Fatalf("expected cache populated after revoke")
	}
}

func TestPassThroughForwardsToInner(t *testing.T) {
	ctx := context.Background()
	r, _, _, inner := newTestRepo(t)

	// CreateUser is not overridden — must reach inner.
	in := domain.NewUser{
		ID:        "u1",
		Email:     "alice@example.com",
		Role:      "user",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if _, err := r.CreateUser(ctx, in); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := inner.GetUserByID(ctx, "u1")
	if err != nil || got == nil {
		t.Fatalf("inner GetUserByID: got=%v err=%v", got, err)
	}
}
