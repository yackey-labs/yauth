package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- OAuthAccount ---

func (r *Repo) GetOAuthAccountByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.oauthAccounts {
		if a.Provider == provider && a.ProviderUserID == providerUserID {
			return cloneOAuthAccount(a), nil
		}
	}
	return nil, yautherr.ErrNotFound
}

func (r *Repo) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*domain.OAuthAccount, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	matches := make([]*domain.OAuthAccount, 0)
	for _, a := range r.oauthAccounts {
		if a.UserID == userID {
			matches = append(matches, a)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.Before(matches[j].CreatedAt)
	})
	out := make([]*domain.OAuthAccount, len(matches))
	for i := range matches {
		out[i] = cloneOAuthAccount(matches[i])
	}
	return out, nil
}

func (r *Repo) GetOAuthAccountByUserAndProvider(ctx context.Context, userID, provider string) (*domain.OAuthAccount, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.oauthAccounts {
		if a.UserID == userID && a.Provider == provider {
			return cloneOAuthAccount(a), nil
		}
	}
	return nil, yautherr.ErrNotFound
}

func (r *Repo) CreateOAuthAccount(ctx context.Context, input domain.NewOAuthAccount) error {
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
	a := &domain.OAuthAccount{
		ID:              input.ID,
		UserID:          input.UserID,
		Provider:        input.Provider,
		ProviderUserID:  input.ProviderUserID,
		AccessTokenEnc:  input.AccessTokenEnc,
		RefreshTokenEnc: input.RefreshTokenEnc,
		CreatedAt:       created.UTC(),
		ExpiresAt:       input.ExpiresAt,
		UpdatedAt:       updated.UTC(),
	}
	if a.ExpiresAt != nil {
		t := a.ExpiresAt.UTC()
		a.ExpiresAt = &t
	}
	r.oauthAccounts[a.ID] = a
	return nil
}

func (r *Repo) UpdateOAuthAccountTokens(ctx context.Context, id string, accessTokenEnc, refreshTokenEnc *string, expiresAt *time.Time, updatedAt time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.oauthAccounts[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	a.AccessTokenEnc = accessTokenEnc
	a.RefreshTokenEnc = refreshTokenEnc
	if expiresAt != nil {
		t := expiresAt.UTC()
		a.ExpiresAt = &t
	} else {
		a.ExpiresAt = nil
	}
	a.UpdatedAt = updatedAt.UTC()
	return nil
}

func (r *Repo) DeleteOAuthAccount(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.oauthAccounts[id]; !ok {
		return yautherr.ErrNotFound
	}
	delete(r.oauthAccounts, id)
	return nil
}

// --- OAuthState ---

func (r *Repo) CreateOAuthState(ctx context.Context, input domain.NewOAuthState) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	r.oauthStates[input.State] = &domain.OAuthState{
		State:       input.State,
		Provider:    input.Provider,
		RedirectURL: input.RedirectURL,
		ExpiresAt:   input.ExpiresAt.UTC(),
		CreatedAt:   created.UTC(),
	}
	return nil
}

func (r *Repo) ConsumeOAuthState(ctx context.Context, state string) (*domain.OAuthState, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.oauthStates[state]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	delete(r.oauthStates, state)
	if !s.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	return cloneOAuthState(s), nil
}

// --- RefreshToken ---

func (r *Repo) CreateRefreshToken(ctx context.Context, input domain.NewRefreshToken) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	t := &domain.RefreshToken{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		FamilyID:  input.FamilyID,
		ExpiresAt: input.ExpiresAt.UTC(),
		Revoked:   input.Revoked,
		CreatedAt: created.UTC(),
	}
	r.refreshTokens[t.ID] = t
	r.refreshTokenIdx[t.TokenHash] = t.ID
	return nil
}

func (r *Repo) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.refreshTokenIdx[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneRefreshToken(r.refreshTokens[id]), nil
}

func (r *Repo) RevokeRefreshToken(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.refreshTokens[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	t.Revoked = true
	return nil
}

func (r *Repo) RevokeRefreshTokenFamily(ctx context.Context, familyID string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, t := range r.refreshTokens {
		if t.FamilyID == familyID && !t.Revoked {
			t.Revoked = true
			n++
		}
	}
	return n, nil
}

func (r *Repo) RevokeAllUserRefreshTokens(ctx context.Context, userID string) (int64, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, t := range r.refreshTokens {
		if t.UserID == userID && !t.Revoked {
			t.Revoked = true
			n++
		}
	}
	return n, nil
}

// --- APIKey ---

// strPtrCopy duplicates a *string so callers cannot mutate the stored row.
func strPtrCopy(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// validateAPIKeyOwner enforces the "exactly one of UserID /
// OrganizationID is set" invariant (yauth #91). Returns
// yautherr.ErrInvalidRequest when both are set or both are nil.
func validateAPIKeyOwner(in domain.NewAPIKey) error {
	hasUser := in.UserID != nil && *in.UserID != ""
	hasOrg := in.OrganizationID != nil && *in.OrganizationID != ""
	if hasUser == hasOrg {
		return yautherr.ErrInvalidRequest
	}
	return nil
}

func (r *Repo) CreateAPIKey(ctx context.Context, input domain.NewAPIKey) error {
	_ = ensureCtx(ctx)
	if err := validateAPIKeyOwner(input); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	k := &domain.APIKey{
		ID:              input.ID,
		UserID:          strPtrCopy(input.UserID),
		OrganizationID:  strPtrCopy(input.OrganizationID),
		KeyPrefix:       input.KeyPrefix,
		KeyHash:         input.KeyHash,
		Name:            input.Name,
		Role:            strPtrCopy(input.Role),
		ExpiresAt:       input.ExpiresAt,
		CreatedAt:       created.UTC(),
		CreatedByUserID: input.CreatedByUserID,
	}
	if len(input.Scopes) > 0 {
		k.Scopes = append([]byte(nil), input.Scopes...)
	}
	if k.ExpiresAt != nil {
		t := k.ExpiresAt.UTC()
		k.ExpiresAt = &t
	}
	r.apiKeys[k.ID] = k
	r.apiKeyPrefixIdx[k.KeyPrefix] = k.ID
	return nil
}

func (r *Repo) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*domain.APIKey, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.apiKeyPrefixIdx[prefix]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	k := r.apiKeys[id]
	if k.ExpiresAt != nil && !k.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	return cloneAPIKey(k), nil
}

func (r *Repo) GetAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*domain.APIKey, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.apiKeys[id]
	if !ok || k.UserID == nil || *k.UserID != userID {
		return nil, yautherr.ErrNotFound
	}
	return cloneAPIKey(k), nil
}

func (r *Repo) GetAPIKeyByIDAndOrg(ctx context.Context, id, organizationID string) (*domain.APIKey, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.apiKeys[id]
	if !ok || k.OrganizationID == nil || *k.OrganizationID != organizationID {
		return nil, yautherr.ErrNotFound
	}
	return cloneAPIKey(k), nil
}

func (r *Repo) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*domain.APIKey, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	matches := make([]*domain.APIKey, 0)
	for _, k := range r.apiKeys {
		if k.UserID != nil && *k.UserID == userID {
			matches = append(matches, k)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	out := make([]*domain.APIKey, len(matches))
	for i := range matches {
		out[i] = cloneAPIKey(matches[i])
	}
	return out, nil
}

func (r *Repo) ListAPIKeysByOrgID(ctx context.Context, organizationID string) ([]*domain.APIKey, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	matches := make([]*domain.APIKey, 0)
	for _, k := range r.apiKeys {
		if k.OrganizationID != nil && *k.OrganizationID == organizationID {
			matches = append(matches, k)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	out := make([]*domain.APIKey, len(matches))
	for i := range matches {
		out[i] = cloneAPIKey(matches[i])
	}
	return out, nil
}

func (r *Repo) UpdateAPIKeyLastUsed(ctx context.Context, id string, at time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.apiKeys[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	t := at.UTC()
	k.LastUsedAt = &t
	return nil
}

func (r *Repo) SetAPIKeyExpiry(ctx context.Context, id string, expiresAt *time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.apiKeys[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	if expiresAt == nil {
		k.ExpiresAt = nil
		return nil
	}
	t := expiresAt.UTC()
	k.ExpiresAt = &t
	return nil
}

func (r *Repo) DeleteAPIKey(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.apiKeys[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	delete(r.apiKeyPrefixIdx, k.KeyPrefix)
	delete(r.apiKeys, id)
	return nil
}
