package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- Passkey ---

func (r *Repo) GetPasskeysByUserID(ctx context.Context, userID string) ([]*domain.WebauthnCredential, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	matches := make([]*domain.WebauthnCredential, 0)
	for _, p := range r.passkeys {
		if p.UserID == userID {
			matches = append(matches, p)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.Before(matches[j].CreatedAt)
	})
	out := make([]*domain.WebauthnCredential, len(matches))
	for i := range matches {
		out[i] = clonePasskey(matches[i])
	}
	return out, nil
}

func (r *Repo) GetPasskeyByIDAndUser(ctx context.Context, id, userID string) (*domain.WebauthnCredential, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.passkeys[id]
	if !ok || p.UserID != userID {
		return nil, yautherr.ErrNotFound
	}
	return clonePasskey(p), nil
}

func (r *Repo) CreatePasskey(ctx context.Context, input domain.NewWebauthnCredential) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	p := &domain.WebauthnCredential{
		ID:         input.ID,
		UserID:     input.UserID,
		Name:       input.Name,
		AAGUID:     input.AAGUID,
		DeviceName: input.DeviceName,
		CreatedAt:  created.UTC(),
	}
	if len(input.Credential) > 0 {
		p.Credential = append([]byte(nil), input.Credential...)
	}
	r.passkeys[p.ID] = p
	return nil
}

func (r *Repo) UpdatePasskeyLastUsed(ctx context.Context, id string, at time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.passkeys[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	t := at.UTC()
	p.LastUsedAt = &t
	return nil
}

func (r *Repo) DeletePasskey(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.passkeys[id]; !ok {
		return yautherr.ErrNotFound
	}
	delete(r.passkeys, id)
	return nil
}

// --- TOTP ---

func (r *Repo) GetTOTPByUserID(ctx context.Context, userID string, verifiedOnly *bool) (*domain.TOTPSecret, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, t := range r.totp {
		if t.UserID != userID {
			continue
		}
		if verifiedOnly != nil && t.Verified != *verifiedOnly {
			continue
		}
		return cloneTOTP(t), nil
	}
	return nil, yautherr.ErrNotFound
}

func (r *Repo) CreateTOTP(ctx context.Context, input domain.NewTOTPSecret) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	r.totp[input.ID] = &domain.TOTPSecret{
		ID:              input.ID,
		UserID:          input.UserID,
		EncryptedSecret: input.EncryptedSecret,
		Verified:        input.Verified,
		CreatedAt:       created.UTC(),
	}
	return nil
}

func (r *Repo) MarkTOTPVerified(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.totp[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	t.Verified = true
	return nil
}

func (r *Repo) DeleteTOTPForUser(ctx context.Context, userID string, verifiedOnly *bool) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, t := range r.totp {
		if t.UserID != userID {
			continue
		}
		if verifiedOnly != nil && t.Verified != *verifiedOnly {
			continue
		}
		delete(r.totp, id)
		n++
	}
	return n, nil
}

// --- BackupCode ---

func (r *Repo) GetUnusedBackupCodesByUserID(ctx context.Context, userID string) ([]*domain.BackupCode, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	matches := make([]*domain.BackupCode, 0)
	for _, b := range r.backupCodes {
		if b.UserID == userID && !b.Used {
			matches = append(matches, b)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.Before(matches[j].CreatedAt)
	})
	out := make([]*domain.BackupCode, len(matches))
	for i := range matches {
		out[i] = cloneBackupCode(matches[i])
	}
	return out, nil
}

func (r *Repo) CreateBackupCode(ctx context.Context, input domain.NewBackupCode) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	r.backupCodes[input.ID] = &domain.BackupCode{
		ID:        input.ID,
		UserID:    input.UserID,
		CodeHash:  input.CodeHash,
		Used:      input.Used,
		CreatedAt: created.UTC(),
	}
	return nil
}

func (r *Repo) MarkBackupCodeUsed(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.backupCodes[id]
	if !ok || b.Used {
		return yautherr.ErrNotFound
	}
	b.Used = true
	return nil
}

func (r *Repo) DeleteAllBackupCodesForUser(ctx context.Context, userID string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, b := range r.backupCodes {
		if b.UserID == userID {
			delete(r.backupCodes, id)
			n++
		}
	}
	return n, nil
}

// --- AccountLock ---

func (r *Repo) GetAccountLockByUserID(ctx context.Context, userID string) (*domain.AccountLock, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.accountLockUserIdx[userID]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneAccountLock(r.accountLocks[id]), nil
}

func (r *Repo) CreateAccountLock(ctx context.Context, input domain.NewAccountLock) (domain.AccountLock, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	created := input.CreatedAt
	if created.IsZero() {
		created = now
	}
	updated := input.UpdatedAt
	if updated.IsZero() {
		updated = now
	}
	a := &domain.AccountLock{
		ID:           input.ID,
		UserID:       input.UserID,
		FailedCount:  input.FailedCount,
		LockedUntil:  input.LockedUntil,
		LockCount:    input.LockCount,
		LockedReason: input.LockedReason,
		CreatedAt:    created.UTC(),
		UpdatedAt:    updated.UTC(),
	}
	if a.LockedUntil != nil {
		t := a.LockedUntil.UTC()
		a.LockedUntil = &t
	}
	r.accountLocks[a.ID] = a
	r.accountLockUserIdx[a.UserID] = a.ID
	return *cloneAccountLock(a), nil
}

func (r *Repo) IncrementAccountLockFailedCount(ctx context.Context, id string, updatedAt time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.accountLocks[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	a.FailedCount++
	a.UpdatedAt = updatedAt.UTC()
	return nil
}

func (r *Repo) SetAccountLockState(ctx context.Context, id string, state domain.LockState, updatedAt time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.accountLocks[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	a.LockedReason = state.LockedReason
	a.LockCount = state.LockCount
	if state.LockedUntil != nil {
		t := state.LockedUntil.UTC()
		a.LockedUntil = &t
	} else {
		a.LockedUntil = nil
	}
	a.UpdatedAt = updatedAt.UTC()
	return nil
}

func (r *Repo) ResetAccountLockFailedCount(ctx context.Context, id string, updatedAt time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.accountLocks[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	a.FailedCount = 0
	a.UpdatedAt = updatedAt.UTC()
	return nil
}

func (r *Repo) AutoUnlockAccount(ctx context.Context, id string, updatedAt time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.accountLocks[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	a.LockedUntil = nil
	a.LockedReason = nil
	a.UpdatedAt = updatedAt.UTC()
	return nil
}
