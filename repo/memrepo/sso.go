// sso.go — in-memory backing for SsoConnectionRepository,
// ExternalIdentityRepository, and SsoLoginStateRepository (yauth #93 /
// yauth-go #23).
package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- SsoConnection -----------------------------------------------------

func (r *Repo) CreateSsoConnection(ctx context.Context, input domain.NewSsoConnection) (domain.SsoConnection, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.ssoConnections[input.ID]; dup {
		return domain.SsoConnection{}, yautherr.ErrConflict
	}
	now := time.Now().UTC()
	created := input.CreatedAt
	if created.IsZero() {
		created = now
	}
	updated := input.UpdatedAt
	if updated.IsZero() {
		updated = now
	}
	status := input.Status
	if !status.IsValid() {
		status = domain.ConnectionStatusDraft
	}
	kind := input.Kind
	if !kind.IsValid() {
		kind = domain.ConnectionKindOIDCClient
	}
	c := &domain.SsoConnection{
		ID:                     input.ID,
		OrganizationID:         input.OrganizationID,
		Kind:                   kind,
		Name:                   input.Name,
		Status:                 status,
		Config:                 cloneBytes(input.Config),
		JitProvisioningEnabled: input.JitProvisioningEnabled,
		DefaultRoleOnJit:       input.DefaultRoleOnJit,
		CreatedAt:              created.UTC(),
		UpdatedAt:              updated.UTC(),
	}
	r.ssoConnections[c.ID] = c
	return *cloneSsoConnection(c), nil
}

func (r *Repo) GetSsoConnectionByID(ctx context.Context, id string) (*domain.SsoConnection, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.ssoConnections[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneSsoConnection(c), nil
}

func (r *Repo) ListSsoConnectionsByOrg(ctx context.Context, organizationID string) ([]*domain.SsoConnection, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.SsoConnection, 0)
	for _, c := range r.ssoConnections {
		if c.OrganizationID == organizationID {
			out = append(out, cloneSsoConnection(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (r *Repo) ListAllSsoConnections(ctx context.Context) ([]*domain.SsoConnection, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.SsoConnection, 0, len(r.ssoConnections))
	for _, c := range r.ssoConnections {
		out = append(out, cloneSsoConnection(c))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (r *Repo) UpdateSsoConnection(ctx context.Context, id string, changes domain.UpdateSsoConnection) (domain.SsoConnection, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.ssoConnections[id]
	if !ok {
		return domain.SsoConnection{}, yautherr.ErrNotFound
	}
	if changes.Name != nil {
		c.Name = *changes.Name
	}
	if changes.Status != nil && changes.Status.IsValid() {
		c.Status = *changes.Status
	}
	if changes.Config != nil {
		c.Config = cloneBytes(*changes.Config)
	}
	if changes.JitProvisioningEnabled != nil {
		c.JitProvisioningEnabled = *changes.JitProvisioningEnabled
	}
	if changes.DefaultRoleOnJit != nil {
		c.DefaultRoleOnJit = *changes.DefaultRoleOnJit
	}
	if changes.UpdatedAt != nil {
		c.UpdatedAt = changes.UpdatedAt.UTC()
	} else {
		c.UpdatedAt = time.Now().UTC()
	}
	return *cloneSsoConnection(c), nil
}

func (r *Repo) DeleteSsoConnection(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ssoConnections, id)
	return nil
}

// --- ExternalIdentity --------------------------------------------------

func extIdentityKey(provider, externalID string) string {
	return provider + "|" + externalID
}

func (r *Repo) CreateExternalIdentity(ctx context.Context, input domain.NewExternalIdentity) (domain.ExternalIdentity, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.extIdentities[input.ID]; dup {
		return domain.ExternalIdentity{}, yautherr.ErrConflict
	}
	key := extIdentityKey(input.Provider, input.ExternalID)
	if _, dup := r.extIdentityProviderIdx[key]; dup {
		return domain.ExternalIdentity{}, yautherr.ErrConflict
	}
	now := time.Now().UTC()
	linked := input.LinkedAt
	if linked.IsZero() {
		linked = now
	}
	last := input.LastLoginAt
	if last.IsZero() {
		last = linked
	}
	e := &domain.ExternalIdentity{
		ID:          input.ID,
		UserID:      input.UserID,
		Provider:    input.Provider,
		ExternalID:  input.ExternalID,
		LinkedAt:    linked.UTC(),
		LastLoginAt: last.UTC(),
	}
	r.extIdentities[e.ID] = e
	r.extIdentityProviderIdx[key] = e.ID
	return *cloneExternalIdentity(e), nil
}

func (r *Repo) GetExternalIdentityByProviderAndExternalID(ctx context.Context, provider, externalID string) (*domain.ExternalIdentity, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.extIdentityProviderIdx[extIdentityKey(provider, externalID)]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	e, ok := r.extIdentities[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneExternalIdentity(e), nil
}

func (r *Repo) ListExternalIdentitiesByUser(ctx context.Context, userID string) ([]*domain.ExternalIdentity, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.ExternalIdentity, 0)
	for _, e := range r.extIdentities {
		if e.UserID == userID {
			out = append(out, cloneExternalIdentity(e))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LinkedAt.Equal(out[j].LinkedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].LinkedAt.Before(out[j].LinkedAt)
	})
	return out, nil
}

func (r *Repo) UpdateExternalIdentityLastLogin(ctx context.Context, id string, at time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.extIdentities[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	e.LastLoginAt = at.UTC()
	return nil
}

func (r *Repo) DeleteExternalIdentity(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.extIdentities[id]
	if !ok {
		return nil
	}
	delete(r.extIdentityProviderIdx, extIdentityKey(e.Provider, e.ExternalID))
	delete(r.extIdentities, id)
	return nil
}

// --- SsoLoginState -----------------------------------------------------

func (r *Repo) CreateSsoLoginState(ctx context.Context, input domain.NewSsoLoginState) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.ssoLoginStates[input.State]; dup {
		return yautherr.ErrConflict
	}
	now := time.Now().UTC()
	created := input.CreatedAt
	if created.IsZero() {
		created = now
	}
	r.ssoLoginStates[input.State] = &domain.SsoLoginState{
		State:        input.State,
		ConnectionID: input.ConnectionID,
		Nonce:        input.Nonce,
		PKCEVerifier: input.PKCEVerifier,
		RedirectURL:  input.RedirectURL,
		CreatedAt:    created.UTC(),
		ExpiresAt:    input.ExpiresAt.UTC(),
	}
	return nil
}

func (r *Repo) ConsumeSsoLoginState(ctx context.Context, state string) (*domain.SsoLoginState, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.ssoLoginStates[state]
	if !ok {
		return nil, nil
	}
	delete(r.ssoLoginStates, state)
	if !s.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, nil
	}
	clone := *s
	return &clone, nil
}

// --- helpers -----------------------------------------------------------

func cloneSsoConnection(c *domain.SsoConnection) *domain.SsoConnection {
	if c == nil {
		return nil
	}
	out := *c
	out.Config = cloneBytes(c.Config)
	return &out
}

func cloneExternalIdentity(e *domain.ExternalIdentity) *domain.ExternalIdentity {
	if e == nil {
		return nil
	}
	out := *e
	return &out
}
