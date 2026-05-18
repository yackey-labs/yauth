package memrepo

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// canonicalDomain normalizes a domain string for storage + lookup. The
// trim + lowercase steps match the spec's "Domain (lowercase canonical)"
// language. Callers should pass the value through this before any
// CRUD; the repo also re-canonicalizes defensively.
func canonicalDomain(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func (r *Repo) CreateOrganizationDomain(ctx context.Context, input domain.NewOrganizationDomain) (domain.OrganizationDomain, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, dup := r.orgDomains[input.ID]; dup {
		return domain.OrganizationDomain{}, yautherr.ErrConflict
	}
	canon := canonicalDomain(input.Domain)
	if _, dup := r.orgDomainNameIdx[canon]; dup {
		return domain.OrganizationDomain{}, yautherr.ErrConflict
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

	d := &domain.OrganizationDomain{
		ID:                    input.ID,
		OrganizationID:        input.OrganizationID,
		Domain:                canon,
		Status:                input.Status,
		VerificationToken:     input.VerificationToken,
		AutoJoinOnSignup:      input.AutoJoinOnSignup,
		DefaultRoleOnAutoJoin: input.DefaultRoleOnAutoJoin,
		RequireEmailVerified:  input.RequireEmailVerified,
		CreatedAt:             created.UTC(),
		UpdatedAt:             updated.UTC(),
	}
	r.orgDomains[d.ID] = d
	r.orgDomainNameIdx[canon] = d.ID
	return *cloneOrgDomain(d), nil
}

func (r *Repo) GetOrganizationDomainByID(ctx context.Context, id string) (*domain.OrganizationDomain, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.orgDomains[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneOrgDomain(d), nil
}

func (r *Repo) GetOrganizationDomainByDomain(ctx context.Context, domainStr string) (*domain.OrganizationDomain, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.orgDomainNameIdx[canonicalDomain(domainStr)]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneOrgDomain(r.orgDomains[id]), nil
}

func (r *Repo) ListOrganizationDomainsByOrg(ctx context.Context, organizationID string) ([]*domain.OrganizationDomain, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.OrganizationDomain, 0)
	for _, d := range r.orgDomains {
		if d.OrganizationID == organizationID {
			out = append(out, cloneOrgDomain(d))
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

// ListVerifiedAutoJoinOrganizationDomains is the routing query used by
// the auto-join hook. It returns rows for which domain matches AND
// status == verified AND auto_join_on_signup == true. With the app-wide
// UNIQUE(domain) constraint this is 0..1 rows, but we return a slice so
// the contract survives a future "multiple orgs can co-claim a domain"
// relaxation without churning callers.
func (r *Repo) ListVerifiedAutoJoinOrganizationDomains(ctx context.Context, domainStr string) ([]*domain.OrganizationDomain, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	canon := canonicalDomain(domainStr)
	out := make([]*domain.OrganizationDomain, 0)
	for _, d := range r.orgDomains {
		if d.Domain != canon {
			continue
		}
		if d.Status != domain.DomainVerified {
			continue
		}
		if !d.AutoJoinOnSignup {
			continue
		}
		out = append(out, cloneOrgDomain(d))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (r *Repo) UpdateOrganizationDomain(ctx context.Context, id string, changes domain.UpdateOrganizationDomain) (domain.OrganizationDomain, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.orgDomains[id]
	if !ok {
		return domain.OrganizationDomain{}, yautherr.ErrNotFound
	}
	if changes.AutoJoinOnSignup != nil {
		d.AutoJoinOnSignup = *changes.AutoJoinOnSignup
	}
	if changes.DefaultRoleOnAutoJoin != nil {
		d.DefaultRoleOnAutoJoin = *changes.DefaultRoleOnAutoJoin
	}
	if changes.RequireEmailVerified != nil {
		d.RequireEmailVerified = *changes.RequireEmailVerified
	}
	if changes.UpdatedAt != nil {
		d.UpdatedAt = changes.UpdatedAt.UTC()
	} else {
		d.UpdatedAt = time.Now().UTC()
	}
	return *cloneOrgDomain(d), nil
}

func (r *Repo) SetOrganizationDomainVerification(ctx context.Context, id string, status domain.DomainStatus, verifiedAt *time.Time, lastCheckedAt time.Time) (domain.OrganizationDomain, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.orgDomains[id]
	if !ok {
		return domain.OrganizationDomain{}, yautherr.ErrNotFound
	}
	d.Status = status
	d.VerifiedAt = ptrUTC(verifiedAt)
	t := lastCheckedAt.UTC()
	d.LastCheckedAt = &t
	d.UpdatedAt = lastCheckedAt.UTC()
	return *cloneOrgDomain(d), nil
}

func (r *Repo) DeleteOrganizationDomain(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.orgDomains[id]
	if !ok {
		return nil
	}
	delete(r.orgDomainNameIdx, canonicalDomain(d.Domain))
	delete(r.orgDomains, id)
	return nil
}

func cloneOrgDomain(d *domain.OrganizationDomain) *domain.OrganizationDomain {
	if d == nil {
		return nil
	}
	c := *d
	c.VerifiedAt = ptrUTC(d.VerifiedAt)
	c.LastCheckedAt = ptrUTC(d.LastCheckedAt)
	return &c
}
