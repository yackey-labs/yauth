package memrepo

import (
	"context"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- EmailVerification ---

func (r *Repo) CreateEmailVerification(ctx context.Context, input domain.NewEmailVerification) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	v := &domain.EmailVerification{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		ExpiresAt: input.ExpiresAt.UTC(),
		CreatedAt: created.UTC(),
	}
	r.emailVerifs[v.ID] = v
	r.emailVerifTokenIdx[v.TokenHash] = v.ID
	return nil
}

func (r *Repo) ConsumeEmailVerification(ctx context.Context, tokenHash string) (*domain.EmailVerification, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.emailVerifTokenIdx[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	v := r.emailVerifs[id]
	delete(r.emailVerifTokenIdx, tokenHash)
	delete(r.emailVerifs, id)
	if !v.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	return cloneEmailVerification(v), nil
}

func (r *Repo) DeleteEmailVerification(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.emailVerifs[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	delete(r.emailVerifTokenIdx, v.TokenHash)
	delete(r.emailVerifs, id)
	return nil
}

func (r *Repo) DeleteEmailVerificationsForUser(ctx context.Context, userID string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, v := range r.emailVerifs {
		if v.UserID == userID {
			delete(r.emailVerifTokenIdx, v.TokenHash)
			delete(r.emailVerifs, id)
			n++
		}
	}
	return n, nil
}

// --- PasswordReset ---

func (r *Repo) CreatePasswordReset(ctx context.Context, input domain.NewPasswordReset) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	p := &domain.PasswordReset{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		ExpiresAt: input.ExpiresAt.UTC(),
		CreatedAt: created.UTC(),
	}
	r.passwordResets[p.ID] = p
	r.passwordResetTokenIdx[p.TokenHash] = p.ID
	return nil
}

func (r *Repo) ConsumePasswordReset(ctx context.Context, tokenHash string) (*domain.PasswordReset, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.passwordResetTokenIdx[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	p := r.passwordResets[id]
	now := time.Now().UTC()
	if p.UsedAt != nil {
		return nil, yautherr.ErrNotFound
	}
	if !p.ExpiresAt.UTC().After(now) {
		return nil, yautherr.ErrNotFound
	}
	p.UsedAt = &now
	return clonePasswordReset(p), nil
}

func (r *Repo) DeleteUnusedPasswordResetsForUser(ctx context.Context, userID string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, p := range r.passwordResets {
		if p.UserID == userID && p.UsedAt == nil {
			delete(r.passwordResetTokenIdx, p.TokenHash)
			delete(r.passwordResets, id)
			n++
		}
	}
	return n, nil
}

// --- MagicLink ---

func (r *Repo) CreateMagicLink(ctx context.Context, input domain.NewMagicLink) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	m := &domain.MagicLink{
		ID:        input.ID,
		Email:     input.Email,
		TokenHash: input.TokenHash,
		ExpiresAt: input.ExpiresAt.UTC(),
		CreatedAt: created.UTC(),
	}
	r.magicLinks[m.ID] = m
	r.magicLinkTokenIdx[m.TokenHash] = m.ID
	return nil
}

func (r *Repo) GetUnusedMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*domain.MagicLink, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.magicLinkTokenIdx[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	m := r.magicLinks[id]
	if m.Used {
		return nil, yautherr.ErrNotFound
	}
	if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	return cloneMagicLink(m), nil
}

func (r *Repo) ConsumeMagicLink(ctx context.Context, tokenHash string) (*domain.MagicLink, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.magicLinkTokenIdx[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	m := r.magicLinks[id]
	if m.Used {
		return nil, yautherr.ErrNotFound
	}
	if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	m.Used = true
	return cloneMagicLink(m), nil
}

func (r *Repo) MarkMagicLinkUsed(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.magicLinks[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	m.Used = true
	return nil
}

func (r *Repo) DeleteMagicLink(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.magicLinks[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	delete(r.magicLinkTokenIdx, m.TokenHash)
	delete(r.magicLinks, id)
	return nil
}

func (r *Repo) DeleteUnusedMagicLinksForEmail(ctx context.Context, email string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, m := range r.magicLinks {
		if m.Email == email && !m.Used {
			delete(r.magicLinkTokenIdx, m.TokenHash)
			delete(r.magicLinks, id)
			n++
		}
	}
	return n, nil
}

// --- UnlockToken ---

func (r *Repo) CreateUnlockToken(ctx context.Context, input domain.NewUnlockToken) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	t := &domain.UnlockToken{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		ExpiresAt: input.ExpiresAt.UTC(),
		CreatedAt: created.UTC(),
	}
	r.unlockTokens[t.ID] = t
	r.unlockTokenHashIdx[t.TokenHash] = t.ID
	return nil
}

func (r *Repo) GetUnlockTokenByHash(ctx context.Context, tokenHash string) (*domain.UnlockToken, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.unlockTokenHashIdx[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	t := r.unlockTokens[id]
	if !t.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	return cloneUnlockToken(t), nil
}

func (r *Repo) ConsumeUnlockToken(ctx context.Context, tokenHash string) (*domain.UnlockToken, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.unlockTokenHashIdx[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	t := r.unlockTokens[id]
	delete(r.unlockTokenHashIdx, tokenHash)
	delete(r.unlockTokens, id)
	if !t.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	return cloneUnlockToken(t), nil
}

func (r *Repo) DeleteUnlockToken(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.unlockTokens[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	delete(r.unlockTokenHashIdx, t.TokenHash)
	delete(r.unlockTokens, id)
	return nil
}

func (r *Repo) DeleteAllUnlockTokensForUser(ctx context.Context, userID string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, t := range r.unlockTokens {
		if t.UserID == userID {
			delete(r.unlockTokenHashIdx, t.TokenHash)
			delete(r.unlockTokens, id)
			n++
		}
	}
	return n, nil
}
