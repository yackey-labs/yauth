package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- AuditLog ---

func (r *Repo) LogAuditEvent(ctx context.Context, input domain.NewAuditLog) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	a := &domain.AuditLog{
		ID:        input.ID,
		UserID:    input.UserID,
		EventType: input.EventType,
		IPAddress: input.IPAddress,
		CreatedAt: created.UTC(),
	}
	if len(input.Metadata) > 0 {
		a.Metadata = append([]byte(nil), input.Metadata...)
	}
	r.auditLog = append(r.auditLog, a)
	return nil
}

func (r *Repo) ListAuditLog(ctx context.Context, filters domain.ListAuditFilters) ([]*domain.AuditLog, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()

	matches := make([]*domain.AuditLog, 0, len(r.auditLog))
	for _, a := range r.auditLog {
		if filters.UserID != nil {
			if a.UserID == nil || *a.UserID != *filters.UserID {
				continue
			}
		}
		if filters.EventType != nil && a.EventType != *filters.EventType {
			continue
		}
		matches = append(matches, a)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	if filters.Offset > 0 {
		if filters.Offset >= len(matches) {
			return []*domain.AuditLog{}, nil
		}
		matches = matches[filters.Offset:]
	}
	if filters.Limit > 0 && filters.Limit < len(matches) {
		matches = matches[:filters.Limit]
	}
	out := make([]*domain.AuditLog, len(matches))
	for i := range matches {
		out[i] = cloneAuditLog(matches[i])
	}
	return out, nil
}

// --- Challenge ---

func (r *Repo) SetChallenge(ctx context.Context, key, value string, ttl time.Duration) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[key] = &domain.Challenge{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	return nil
}

func (r *Repo) GetChallenge(ctx context.Context, key string) (*domain.Challenge, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[key]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	if !c.ExpiresAt.UTC().After(time.Now().UTC()) {
		delete(r.challenges, key)
		return nil, yautherr.ErrNotFound
	}
	return cloneChallenge(c), nil
}

func (r *Repo) ConsumeChallenge(ctx context.Context, key string) (*domain.Challenge, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[key]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	delete(r.challenges, key)
	if !c.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	return cloneChallenge(c), nil
}

func (r *Repo) DeleteChallenge(ctx context.Context, key string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.challenges, key)
	return nil
}

// --- RateLimit ---

func (r *Repo) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (domain.RateLimitResult, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	windowStart := now.Add(-window)

	st, ok := r.rateLimits[key]
	if !ok {
		r.rateLimits[key] = &rateLimitState{count: 1, windowStart: now}
		rem := limit - 1
		if rem < 0 {
			rem = 0
		}
		return domain.RateLimitResult{Allowed: true, Remaining: rem, RetryAfter: 0}, nil
	}

	if st.windowStart.UTC().Before(windowStart) {
		st.count = 1
		st.windowStart = now
		rem := limit - 1
		if rem < 0 {
			rem = 0
		}
		return domain.RateLimitResult{Allowed: true, Remaining: rem, RetryAfter: 0}, nil
	}

	if st.count >= limit {
		retry := window - now.Sub(st.windowStart.UTC())
		if retry < 0 {
			retry = 0
		}
		return domain.RateLimitResult{Allowed: false, Remaining: 0, RetryAfter: retry}, nil
	}

	st.count++
	rem := limit - st.count
	if rem < 0 {
		rem = 0
	}
	return domain.RateLimitResult{Allowed: true, Remaining: rem, RetryAfter: 0}, nil
}

// --- Revocation ---

func (r *Repo) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revocations[jti] = time.Now().UTC().Add(ttl)
	return nil
}

func (r *Repo) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.revocations[jti]
	if !ok {
		return false, nil
	}
	if !exp.UTC().After(time.Now().UTC()) {
		delete(r.revocations, jti)
		return false, nil
	}
	return true, nil
}
