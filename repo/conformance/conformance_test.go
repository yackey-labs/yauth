package conformance_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/conformance"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/repo/redisrepo"
)

// TestConformance runs the backend-agnostic repository conformance suite
// against the in-memory backend and the Redis-decorated stack. The pgx
// (Postgres) backend — the only persistent store — runs the same suite
// against a real database in repo/pgxrepo/repo_test.go (testcontainers).
func TestConformance(t *testing.T) {
	conformance.Suite{
		Name: "memrepo",
		New: func(t *testing.T) repo.Repository {
			return memrepo.New()
		},
	}.Run(t)

	// redisrepo decorating memrepo, backed by miniredis. Exercises every
	// pass-through operation as well as the cached hot paths.
	conformance.Suite{
		Name: "redisrepo+memrepo",
		New: func(t *testing.T) repo.Repository {
			t.Helper()
			mr := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			t.Cleanup(func() { _ = client.Close() })
			id := atomic.AddUint64(&redisCounter, 1)
			return redisrepo.New(memrepo.New(), client, redisrepo.Options{
				KeyPrefix: fmt.Sprintf("conf-%d:", id),
			})
		},
	}.Run(t)
}

var redisCounter uint64
