// Package redisrepo is a caching decorator that wraps another
// repo.Repository and uses Redis to accelerate hot-path reads (session
// lookup, challenge lookup, revocation checks) and to back fixed-window
// rate limiting.
//
// The inner repository is always the source of truth. Cache writes are
// best-effort: a Redis failure logs a warning and falls through to the
// inner repository. The decorator satisfies repo.Repository structurally
// by embedding the inner; only operations listed below override the inner:
//
//   - GetSessionByTokenHash    (read-through cache)
//   - CreateSession            (write-through)
//   - DeleteSession*           (invalidation)
//   - SetChallenge             (write-through)
//   - GetChallenge             (read-through)
//   - ConsumeChallenge         (invalidation)
//   - DeleteChallenge          (invalidation)
//   - CheckRateLimit           (Redis is the source of truth)
//   - RevokeToken              (write-through)
//   - IsTokenRevoked           (read-through)
//
// Everything else is forwarded to the inner repo via embedding.
package redisrepo

import (
	"context"
	"log"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth-go/repo"
)

// Default tunables for Options.
const (
	DefaultKeyPrefix       = "yauth:"
	DefaultDefaultTTL      = 60 * time.Second
	DefaultNegativeCacheTTL = 60 * time.Second
)

// Options tunes the decorator. Zero values pick documented defaults.
type Options struct {
	// KeyPrefix is prepended to every Redis key. Defaults to "yauth:".
	// Should end with a separator (":" by convention) to avoid collisions
	// when sharing a Redis instance.
	KeyPrefix string

	// DefaultTTL is the fallback TTL used when the inner record's
	// expires_at is not known to the read-through path. Defaults to 60s.
	DefaultTTL time.Duration

	// DisableNegativeCache turns off short-TTL negative caching of
	// not-found session/challenge/revocation lookups. Negative caching
	// blunts enumeration thrash on hot read paths but can also mask very
	// fresh writes for up to NegativeCacheTTL seconds.
	DisableNegativeCache bool

	// NegativeCacheTTL is the TTL applied to negative cache entries.
	// Defaults to 60s.
	NegativeCacheTTL time.Duration

	// Logger receives best-effort cache-failure messages. Nil = log.Default().
	Logger *log.Logger
}

func (o Options) withDefaults() Options {
	if o.KeyPrefix == "" {
		o.KeyPrefix = DefaultKeyPrefix
	}
	if o.DefaultTTL <= 0 {
		o.DefaultTTL = DefaultDefaultTTL
	}
	if o.NegativeCacheTTL <= 0 {
		o.NegativeCacheTTL = DefaultNegativeCacheTTL
	}
	return o
}

// Repo is the Redis caching decorator. It embeds repo.Repository so any
// method not explicitly overridden falls through to the inner backend.
type Repo struct {
	repo.Repository
	client *redis.Client
	opts   Options
}

// New returns a Repo that decorates inner with a Redis cache. client must
// be non-nil; Ping is not called here so callers can construct the
// decorator before Redis is reachable (the decorator degrades gracefully).
func New(inner repo.Repository, client *redis.Client, opts Options) *Repo {
	if inner == nil {
		panic("redisrepo: inner repo.Repository is nil")
	}
	if client == nil {
		panic("redisrepo: *redis.Client is nil")
	}
	return &Repo{
		Repository: inner,
		client:     client,
		opts:       opts.withDefaults(),
	}
}

// warn logs a best-effort cache failure without forcing the operation to fail.
func (r *Repo) warn(format string, args ...any) {
	if r.opts.Logger != nil {
		r.opts.Logger.Printf(format, args...)
		return
	}
	log.Printf("redisrepo: "+format, args...)
}

// remainingTTL returns the duration between expiresAt and now, clamped to
// at least one second. Returned for cache-write TTLs so a freshly-loaded
// row that's about to expire isn't cached for zero seconds (which go-redis
// treats as "no expiration").
func remainingTTL(expiresAt time.Time) time.Duration {
	d := time.Until(expiresAt)
	if d < time.Second {
		return time.Second
	}
	return d
}

// ctxOrBackground returns ctx if non-nil, else context.Background.
func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// compile-time check
var _ repo.Repository = (*Repo)(nil)
