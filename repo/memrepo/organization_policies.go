// organization_policies.go — in-memory backing for the
// OrganizationPolicyRepository interface (yauth #92 / yauth-go #21).
//
// The per-org policy is a single row keyed by organization_id; there
// is no separate primary id. The map is gated by Repo.mu like every
// other collection in this package. Cascade-on-delete-org happens in
// organizations.go's DeleteOrganization.
package memrepo

import (
	"context"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

func (r *Repo) GetOrganizationPolicy(ctx context.Context, organizationID string) (*domain.OrganizationPolicy, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.orgPolicies[organizationID]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneOrgPolicy(p), nil
}

func (r *Repo) CreateOrganizationPolicy(ctx context.Context, input domain.NewOrganizationPolicy) (domain.OrganizationPolicy, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.orgPolicies[input.OrganizationID]; dup {
		return domain.OrganizationPolicy{}, yautherr.ErrConflict
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
	binding := input.SessionBinding
	if !binding.IsValid() {
		binding = domain.SessionBindingUnset
	}
	p := &domain.OrganizationPolicy{
		OrganizationID:         input.OrganizationID,
		MaxSessionDurationSecs: cloneI64Ptr(input.MaxSessionDurationSecs),
		IdleTimeoutSecs:        cloneI64Ptr(input.IdleTimeoutSecs),
		MfaRequired:            input.MfaRequired,
		MfaGracePeriodDays:     input.MfaGracePeriodDays,
		IPAllowlist:            cloneStringSlice(input.IPAllowlist),
		MaxConcurrentSessions:  cloneI32Ptr(input.MaxConcurrentSessions),
		AllowedAuthMethods:     cloneStringSlice(input.AllowedAuthMethods),
		SessionBinding:         binding,
		CreatedAt:              created.UTC(),
		UpdatedAt:              updated.UTC(),
	}
	r.orgPolicies[p.OrganizationID] = p
	return *cloneOrgPolicy(p), nil
}

func (r *Repo) UpdateOrganizationPolicy(ctx context.Context, organizationID string, changes domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.orgPolicies[organizationID]
	if !ok {
		return domain.OrganizationPolicy{}, yautherr.ErrNotFound
	}
	applyOrgPolicyChanges(p, changes)
	return *cloneOrgPolicy(p), nil
}

func (r *Repo) UpsertOrganizationPolicy(ctx context.Context, organizationID string, changes domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.orgPolicies[organizationID]
	if !ok {
		now := time.Now().UTC()
		p = &domain.OrganizationPolicy{
			OrganizationID: organizationID,
			SessionBinding: domain.SessionBindingUnset,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		r.orgPolicies[organizationID] = p
	}
	applyOrgPolicyChanges(p, changes)
	return *cloneOrgPolicy(p), nil
}

func (r *Repo) DeleteOrganizationPolicy(ctx context.Context, organizationID string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.orgPolicies, organizationID)
	return nil
}

// applyOrgPolicyChanges mutates p in place according to the partial-
// update payload. Callers hold r.mu.Lock.
func applyOrgPolicyChanges(p *domain.OrganizationPolicy, changes domain.UpdateOrganizationPolicy) {
	if changes.MaxSessionDurationSecs != nil {
		p.MaxSessionDurationSecs = cloneI64Ptr(*changes.MaxSessionDurationSecs)
	}
	if changes.IdleTimeoutSecs != nil {
		p.IdleTimeoutSecs = cloneI64Ptr(*changes.IdleTimeoutSecs)
	}
	if changes.MfaRequired != nil {
		p.MfaRequired = *changes.MfaRequired
	}
	if changes.MfaGracePeriodDays != nil {
		p.MfaGracePeriodDays = *changes.MfaGracePeriodDays
	}
	if changes.IPAllowlist != nil {
		p.IPAllowlist = cloneStringSlice(*changes.IPAllowlist)
	}
	if changes.MaxConcurrentSessions != nil {
		p.MaxConcurrentSessions = cloneI32Ptr(*changes.MaxConcurrentSessions)
	}
	if changes.AllowedAuthMethods != nil {
		p.AllowedAuthMethods = cloneStringSlice(*changes.AllowedAuthMethods)
	}
	if changes.SessionBinding != nil && changes.SessionBinding.IsValid() {
		p.SessionBinding = *changes.SessionBinding
	}
	if changes.UpdatedAt != nil {
		p.UpdatedAt = changes.UpdatedAt.UTC()
	} else {
		p.UpdatedAt = time.Now().UTC()
	}
}

func cloneOrgPolicy(p *domain.OrganizationPolicy) *domain.OrganizationPolicy {
	if p == nil {
		return nil
	}
	c := *p
	c.MaxSessionDurationSecs = cloneI64Ptr(p.MaxSessionDurationSecs)
	c.IdleTimeoutSecs = cloneI64Ptr(p.IdleTimeoutSecs)
	c.MaxConcurrentSessions = cloneI32Ptr(p.MaxConcurrentSessions)
	c.IPAllowlist = cloneStringSlice(p.IPAllowlist)
	c.AllowedAuthMethods = cloneStringSlice(p.AllowedAuthMethods)
	return &c
}

func cloneI64Ptr(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneI32Ptr(p *int32) *int32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	c := make([]string, len(s))
	copy(c, s)
	return c
}
