package redisrepo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// CreateSession writes through: insert into the inner repo (source of
// truth), then mirror the row into Redis with a TTL matching the session's
// remaining lifetime. Adds the token hash to the per-user set so a
// DeleteUserSessions can fan out and invalidate every cached entry.
func (r *Repo) CreateSession(ctx context.Context, input domain.NewSession) error {
	ctx = ctxOrBackground(ctx)
	if err := r.Repository.CreateSession(ctx, input); err != nil {
		return err
	}

	session := domain.Session{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		IPAddress: input.IPAddress,
		UserAgent: input.UserAgent,
		ExpiresAt: input.ExpiresAt.UTC(),
		CreatedAt: input.CreatedAt.UTC(),
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now().UTC()
	}

	payload, err := json.Marshal(session)
	if err != nil {
		r.warn("create session: marshal: %v", err)
		return nil
	}

	ttl := remainingTTL(session.ExpiresAt)
	pipe := r.client.TxPipeline()
	pipe.Set(ctx, r.sessionKey(input.TokenHash), payload, ttl)
	pipe.SAdd(ctx, r.userSessionsKey(input.UserID), input.TokenHash)
	// The user-sessions set has no natural TTL; bump it so abandoned sets
	// don't pile up. Set it slightly longer than the session itself so the
	// SREM in DeleteSession still has the membership available.
	pipe.Expire(ctx, r.userSessionsKey(input.UserID), ttl+time.Hour)
	// Clear any negative cache that might have stuck on this hash.
	pipe.Del(ctx, r.sessionNegKey(input.TokenHash))
	if _, err := pipe.Exec(ctx); err != nil {
		r.warn("create session: cache write: %v", err)
	}
	return nil
}

// GetSessionByTokenHash is the read-through hot path. Cache hits skip the
// inner repo entirely. On miss, the inner repo is consulted and a fresh
// row is backfilled into Redis with a TTL matching the session's
// remaining lifetime. Negative results (not found / expired) get a
// short TTL to mitigate enumeration thrash, unless DisableNegativeCache.
func (r *Repo) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	ctx = ctxOrBackground(ctx)

	// Negative-cache hit: ErrNotFound short-circuit.
	if !r.opts.DisableNegativeCache {
		if exists, err := r.client.Exists(ctx, r.sessionNegKey(tokenHash)).Result(); err == nil && exists > 0 {
			return nil, yautherr.ErrNotFound
		}
	}

	if raw, err := r.client.Get(ctx, r.sessionKey(tokenHash)).Bytes(); err == nil {
		var s domain.Session
		if json.Unmarshal(raw, &s) == nil {
			if s.ExpiresAt.UTC().After(time.Now().UTC()) {
				return &s, nil
			}
			// Expired in cache — clean up and fall through.
			_ = r.client.Del(ctx, r.sessionKey(tokenHash)).Err()
		}
	} else if !errors.Is(err, redis.Nil) {
		r.warn("get session: cache read: %v", err)
	}

	got, err := r.Repository.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) && !r.opts.DisableNegativeCache {
			if e := r.client.Set(ctx, r.sessionNegKey(tokenHash), "1", r.opts.NegativeCacheTTL).Err(); e != nil {
				r.warn("get session: negative cache write: %v", e)
			}
		}
		return nil, err
	}

	if payload, mErr := json.Marshal(got); mErr == nil {
		ttl := remainingTTL(got.ExpiresAt)
		pipe := r.client.TxPipeline()
		pipe.Set(ctx, r.sessionKey(tokenHash), payload, ttl)
		pipe.SAdd(ctx, r.userSessionsKey(got.UserID), tokenHash)
		pipe.Expire(ctx, r.userSessionsKey(got.UserID), ttl+time.Hour)
		if _, e := pipe.Exec(ctx); e != nil {
			r.warn("get session: cache backfill: %v", e)
		}
	}
	return got, nil
}

// DeleteSession invalidates the cached entry and the per-user set
// membership before/after the inner delete.
func (r *Repo) DeleteSession(ctx context.Context, tokenHash string) (bool, error) {
	ctx = ctxOrBackground(ctx)

	// Pull the cached value to find the user_id for set cleanup. Best-effort.
	var userID string
	if raw, err := r.client.Get(ctx, r.sessionKey(tokenHash)).Bytes(); err == nil {
		var s domain.Session
		if json.Unmarshal(raw, &s) == nil {
			userID = s.UserID
		}
	}

	deleted, err := r.Repository.DeleteSession(ctx, tokenHash)
	if err != nil {
		return deleted, err
	}

	pipe := r.client.TxPipeline()
	pipe.Del(ctx, r.sessionKey(tokenHash))
	if userID != "" {
		pipe.SRem(ctx, r.userSessionsKey(userID), tokenHash)
	}
	if _, e := pipe.Exec(ctx); e != nil {
		r.warn("delete session: cache cleanup: %v", e)
	}
	return deleted, nil
}

// DeleteSessionByID forwards to inner; if a cached entry exists keyed by
// token hash we'd need to look up the row to invalidate, but the inner
// path returns nothing. We pull the user's cached set and rebuild it from
// the cache opportunistically.
func (r *Repo) DeleteSessionByID(ctx context.Context, id string) error {
	ctx = ctxOrBackground(ctx)

	// Pull the inner record before delete so we know which token hash to
	// invalidate. Best-effort; if not found the inner call will return the
	// canonical ErrNotFound.
	var tokenHash, userID string
	if s, err := r.Repository.GetSessionByID(ctx, id); err == nil && s != nil {
		tokenHash = s.TokenHash
		userID = s.UserID
	}

	if err := r.Repository.DeleteSessionByID(ctx, id); err != nil {
		return err
	}

	if tokenHash != "" {
		pipe := r.client.TxPipeline()
		pipe.Del(ctx, r.sessionKey(tokenHash))
		if userID != "" {
			pipe.SRem(ctx, r.userSessionsKey(userID), tokenHash)
		}
		if _, e := pipe.Exec(ctx); e != nil {
			r.warn("delete session by id: cache cleanup: %v", e)
		}
	}
	return nil
}

// DeleteUserSessions invalidates every cached session belonging to userID.
func (r *Repo) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	ctx = ctxOrBackground(ctx)

	hashes, hErr := r.client.SMembers(ctx, r.userSessionsKey(userID)).Result()
	if hErr != nil && !errors.Is(hErr, redis.Nil) {
		r.warn("delete user sessions: cache smembers: %v", hErr)
	}

	count, err := r.Repository.DeleteUserSessions(ctx, userID)
	if err != nil {
		return count, err
	}

	pipe := r.client.TxPipeline()
	for _, h := range hashes {
		pipe.Del(ctx, r.sessionKey(h))
	}
	pipe.Del(ctx, r.userSessionsKey(userID))
	if _, e := pipe.Exec(ctx); e != nil {
		r.warn("delete user sessions: cache cleanup: %v", e)
	}
	return count, nil
}

// DeleteOtherUserSessions invalidates everything in the user's cached set
// except keepTokenHash.
func (r *Repo) DeleteOtherUserSessions(ctx context.Context, userID, keepTokenHash string) (int64, error) {
	ctx = ctxOrBackground(ctx)

	hashes, hErr := r.client.SMembers(ctx, r.userSessionsKey(userID)).Result()
	if hErr != nil && !errors.Is(hErr, redis.Nil) {
		r.warn("delete other user sessions: cache smembers: %v", hErr)
	}

	count, err := r.Repository.DeleteOtherUserSessions(ctx, userID, keepTokenHash)
	if err != nil {
		return count, err
	}

	pipe := r.client.TxPipeline()
	for _, h := range hashes {
		if h == keepTokenHash {
			continue
		}
		pipe.Del(ctx, r.sessionKey(h))
		pipe.SRem(ctx, r.userSessionsKey(userID), h)
	}
	if _, e := pipe.Exec(ctx); e != nil {
		r.warn("delete other user sessions: cache cleanup: %v", e)
	}
	return count, nil
}
