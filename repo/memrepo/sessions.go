package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- Session ---

func (r *Repo) CreateSession(ctx context.Context, input domain.NewSession) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	created := input.CreatedAt
	if created.IsZero() {
		created = now
	}

	s := &domain.Session{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		IPAddress: input.IPAddress,
		UserAgent: input.UserAgent,
		ExpiresAt: input.ExpiresAt.UTC(),
		CreatedAt: created.UTC(),
	}
	r.sessions[s.ID] = s
	r.sessionTokenIdx[s.TokenHash] = s.ID
	return nil
}

func (r *Repo) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneSession(s), nil
}

func (r *Repo) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.sessionTokenIdx[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneSession(r.sessions[id]), nil
}

func (r *Repo) DeleteSession(ctx context.Context, tokenHash string) (bool, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.sessionTokenIdx[tokenHash]
	if !ok {
		return false, nil
	}
	delete(r.sessionTokenIdx, tokenHash)
	delete(r.sessions, id)
	return true, nil
}

func (r *Repo) DeleteSessionByID(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	delete(r.sessionTokenIdx, s.TokenHash)
	delete(r.sessions, id)
	return nil
}

func (r *Repo) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, s := range r.sessions {
		if s.UserID == userID {
			delete(r.sessionTokenIdx, s.TokenHash)
			delete(r.sessions, id)
			n++
		}
	}
	return n, nil
}

func (r *Repo) DeleteOtherUserSessions(ctx context.Context, userID, keepTokenHash string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, s := range r.sessions {
		if s.UserID == userID && s.TokenHash != keepTokenHash {
			delete(r.sessionTokenIdx, s.TokenHash)
			delete(r.sessions, id)
			n++
		}
	}
	return n, nil
}

func (r *Repo) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.UTC()
	var n int64
	for id, s := range r.sessions {
		if !s.ExpiresAt.UTC().After(cutoff) {
			delete(r.sessionTokenIdx, s.TokenHash)
			delete(r.sessions, id)
			n++
		}
	}
	return n, nil
}

func (r *Repo) ListSessions(ctx context.Context, filters domain.ListSessionsFilters) ([]*domain.Session, int64, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := make([]*domain.Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		if filters.UserID != nil && *filters.UserID != "" && s.UserID != *filters.UserID {
			continue
		}
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})

	total := int64(len(all))
	if filters.Offset > 0 {
		if filters.Offset >= len(all) {
			return []*domain.Session{}, total, nil
		}
		all = all[filters.Offset:]
	}
	if filters.Limit > 0 && filters.Limit < len(all) {
		all = all[:filters.Limit]
	}
	out := make([]*domain.Session, len(all))
	for i := range all {
		out[i] = cloneSession(all[i])
	}
	return out, total, nil
}
