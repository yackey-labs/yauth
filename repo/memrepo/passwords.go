package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- Password ---

func (r *Repo) UpsertPassword(ctx context.Context, input domain.NewPassword) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passwords[input.UserID] = &domain.Password{
		UserID:       input.UserID,
		PasswordHash: input.PasswordHash,
	}
	return nil
}

func (r *Repo) GetPasswordByUserID(ctx context.Context, userID string) (*domain.Password, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.passwords[userID]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return clonePassword(p), nil
}

// --- PasswordHistory ---

func (r *Repo) AppendPasswordHistory(ctx context.Context, input domain.NewPasswordHistory) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	row := &domain.PasswordHistory{
		ID:           input.ID,
		UserID:       input.UserID,
		PasswordHash: input.PasswordHash,
		CreatedAt:    created.UTC(),
	}
	r.passwordHistory[input.UserID] = append(r.passwordHistory[input.UserID], row)
	return nil
}

func (r *Repo) GetPasswordHistory(ctx context.Context, userID string, n int) ([]*domain.PasswordHistory, error) {
	_ = ensureCtx(ctx)
	if n <= 0 {
		return nil, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	rows := r.passwordHistory[userID]
	if len(rows) == 0 {
		return nil, nil
	}
	sorted := make([]*domain.PasswordHistory, len(rows))
	copy(sorted, rows)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	out := make([]*domain.PasswordHistory, 0, len(sorted))
	for _, row := range sorted {
		clone := *row
		out = append(out, &clone)
	}
	return out, nil
}

func (r *Repo) TrimPasswordHistory(ctx context.Context, userID string, keep int) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	rows := r.passwordHistory[userID]
	if len(rows) == 0 {
		return 0, nil
	}
	if keep <= 0 {
		delete(r.passwordHistory, userID)
		return int64(len(rows)), nil
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})
	if len(rows) <= keep {
		r.passwordHistory[userID] = rows
		return 0, nil
	}
	deleted := int64(len(rows) - keep)
	r.passwordHistory[userID] = rows[:keep]
	return deleted, nil
}
