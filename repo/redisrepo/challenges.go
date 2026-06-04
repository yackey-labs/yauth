package redisrepo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// SetChallenge writes through to the inner repo, then mirrors the row into
// Redis with a TTL matching the supplied window.
func (r *Repo) SetChallenge(ctx context.Context, key, value string, ttl time.Duration) error {
	ctx = ctxOrBackground(ctx)
	if err := r.Repository.SetChallenge(ctx, key, value, ttl); err != nil {
		return err
	}

	c := domain.Challenge{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	payload, err := json.Marshal(c)
	if err != nil {
		r.warn("set challenge: marshal: %v", err)
		return nil
	}

	pipe := r.client.TxPipeline()
	pipe.Set(ctx, r.challengeKey(key), payload, ttl)
	pipe.Del(ctx, r.challengeNegKey(key))
	if _, e := pipe.Exec(ctx); e != nil {
		r.warn("set challenge: cache write: %v", e)
	}
	return nil
}

// GetChallenge is a read-through. Cache hits bypass the inner repo.
func (r *Repo) GetChallenge(ctx context.Context, key string) (*domain.Challenge, error) {
	ctx = ctxOrBackground(ctx)

	if !r.opts.DisableNegativeCache {
		if exists, err := r.client.Exists(ctx, r.challengeNegKey(key)).Result(); err == nil && exists > 0 {
			return nil, yautherr.ErrNotFound
		}
	}

	if raw, err := r.client.Get(ctx, r.challengeKey(key)).Bytes(); err == nil {
		var c domain.Challenge
		if json.Unmarshal(raw, &c) == nil {
			if c.ExpiresAt.UTC().After(time.Now().UTC()) {
				return &c, nil
			}
			_ = r.client.Del(ctx, r.challengeKey(key)).Err()
		}
	} else if !errors.Is(err, redis.Nil) {
		r.warn("get challenge: cache read: %v", err)
	}

	got, err := r.Repository.GetChallenge(ctx, key)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) && !r.opts.DisableNegativeCache {
			if e := r.client.Set(ctx, r.challengeNegKey(key), "1", r.opts.NegativeCacheTTL).Err(); e != nil {
				r.warn("get challenge: negative cache write: %v", e)
			}
		}
		return nil, err
	}

	if payload, mErr := json.Marshal(got); mErr == nil {
		ttl := remainingTTL(got.ExpiresAt)
		if e := r.client.Set(ctx, r.challengeKey(key), payload, ttl).Err(); e != nil {
			r.warn("get challenge: cache backfill: %v", e)
		}
	}
	return got, nil
}

// ConsumeChallenge invalidates the cache entry as well as the inner row.
func (r *Repo) ConsumeChallenge(ctx context.Context, key string) (*domain.Challenge, error) {
	ctx = ctxOrBackground(ctx)
	c, err := r.Repository.ConsumeChallenge(ctx, key)
	// Whether or not consume succeeded, drop the cache entry.
	if e := r.client.Del(ctx, r.challengeKey(key)).Err(); e != nil {
		r.warn("consume challenge: cache cleanup: %v", e)
	}
	return c, err
}

// DeleteChallenge deletes the inner row and invalidates the cache entry.
func (r *Repo) DeleteChallenge(ctx context.Context, key string) error {
	ctx = ctxOrBackground(ctx)
	err := r.Repository.DeleteChallenge(ctx, key)
	if e := r.client.Del(ctx, r.challengeKey(key)).Err(); e != nil {
		r.warn("delete challenge: cache cleanup: %v", e)
	}
	return err
}
