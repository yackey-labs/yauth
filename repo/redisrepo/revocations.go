package redisrepo

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RevokeToken writes through to the inner repo, then mirrors a marker key
// into Redis with the same TTL.
func (r *Repo) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	ctx = ctxOrBackground(ctx)
	if err := r.Repository.RevokeToken(ctx, jti, ttl); err != nil {
		return err
	}

	if ttl <= 0 {
		ttl = r.opts.DefaultTTL
	}
	pipe := r.client.TxPipeline()
	pipe.Set(ctx, r.revokedKey(jti), "1", ttl)
	pipe.Del(ctx, r.revokedNegKey(jti))
	if _, err := pipe.Exec(ctx); err != nil {
		r.warn("revoke token: cache write: %v", err)
	}
	return nil
}

// IsTokenRevoked is a read-through. Cache hits skip the inner repo
// entirely. Negative results are cached briefly to mitigate enumeration
// thrash on hot validation paths.
func (r *Repo) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	ctx = ctxOrBackground(ctx)

	if !r.opts.DisableNegativeCache {
		if exists, err := r.client.Exists(ctx, r.revokedNegKey(jti)).Result(); err == nil && exists > 0 {
			return false, nil
		}
	}

	if n, err := r.client.Exists(ctx, r.revokedKey(jti)).Result(); err == nil {
		if n > 0 {
			return true, nil
		}
	} else if !errors.Is(err, redis.Nil) {
		r.warn("is token revoked: cache read: %v", err)
	}

	revoked, err := r.Repository.IsTokenRevoked(ctx, jti)
	if err != nil {
		return revoked, err
	}

	if revoked {
		// We don't know the original TTL; backfill with DefaultTTL so a
		// stale cache eventually re-checks the inner repo.
		if e := r.client.Set(ctx, r.revokedKey(jti), "1", r.opts.DefaultTTL).Err(); e != nil {
			r.warn("is token revoked: cache backfill: %v", e)
		}
	} else if !r.opts.DisableNegativeCache {
		if e := r.client.Set(ctx, r.revokedNegKey(jti), "1", r.opts.NegativeCacheTTL).Err(); e != nil {
			r.warn("is token revoked: negative cache write: %v", e)
		}
	}
	return revoked, nil
}
