package memrepo

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- Organization ---

func (r *Repo) CreateOrganization(ctx context.Context, input domain.NewOrganization) (domain.Organization, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	slugKey := strings.ToLower(input.Slug)
	if _, dup := r.orgSlugIdx[slugKey]; dup {
		return domain.Organization{}, yautherr.ErrConflict
	}
	if _, dup := r.organizations[input.ID]; dup {
		return domain.Organization{}, yautherr.ErrConflict
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

	o := &domain.Organization{
		ID:          input.ID,
		Name:        input.Name,
		Slug:        input.Slug,
		DisplayName: input.DisplayName,
		AvatarURL:   input.AvatarURL,
		Metadata:    cloneBytes(input.Metadata),
		CreatedAt:   created.UTC(),
		UpdatedAt:   updated.UTC(),
	}
	r.organizations[o.ID] = o
	r.orgSlugIdx[slugKey] = o.ID
	return *cloneOrganization(o), nil
}

func (r *Repo) GetOrganizationByID(ctx context.Context, id string) (*domain.Organization, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	o, ok := r.organizations[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneOrganization(o), nil
}

func (r *Repo) GetOrganizationBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.orgSlugIdx[strings.ToLower(slug)]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneOrganization(r.organizations[id]), nil
}

func (r *Repo) UpdateOrganization(ctx context.Context, id string, changes domain.UpdateOrganization) (domain.Organization, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	o, ok := r.organizations[id]
	if !ok {
		return domain.Organization{}, yautherr.ErrNotFound
	}
	if changes.Name != nil {
		o.Name = *changes.Name
	}
	if changes.Slug != nil && *changes.Slug != o.Slug {
		oldKey := strings.ToLower(o.Slug)
		newKey := strings.ToLower(*changes.Slug)
		if other, dup := r.orgSlugIdx[newKey]; dup && other != id {
			return domain.Organization{}, yautherr.ErrConflict
		}
		delete(r.orgSlugIdx, oldKey)
		o.Slug = *changes.Slug
		r.orgSlugIdx[newKey] = id
	}
	if changes.DisplayName != nil {
		o.DisplayName = *changes.DisplayName
	}
	if changes.AvatarURL != nil {
		o.AvatarURL = *changes.AvatarURL
	}
	if changes.Metadata != nil {
		if *changes.Metadata == nil {
			o.Metadata = nil
		} else {
			o.Metadata = cloneBytes(*changes.Metadata)
		}
	}
	if changes.UpdatedAt != nil {
		o.UpdatedAt = changes.UpdatedAt.UTC()
	} else {
		o.UpdatedAt = time.Now().UTC()
	}
	return *cloneOrganization(o), nil
}

func (r *Repo) DeleteOrganization(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	o, ok := r.organizations[id]
	if !ok {
		return nil // idempotent
	}
	delete(r.orgSlugIdx, strings.ToLower(o.Slug))
	delete(r.organizations, id)

	// Cascade memberships.
	for mID, m := range r.memberships {
		if m.OrganizationID == id {
			delete(r.membershipOrgUserIdx, membershipKey(m.OrganizationID, m.UserID))
			delete(r.memberships, mID)
		}
	}
	// Cascade invitations.
	for iID, inv := range r.invitations {
		if inv.OrganizationID == id {
			delete(r.invitationTokenIdx, inv.TokenHash)
			delete(r.invitations, iID)
		}
	}
	return nil
}

func (r *Repo) ListOrganizationsForUser(ctx context.Context, userID string) ([]*domain.Organization, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Organization, 0)
	for _, m := range r.memberships {
		if m.UserID == userID {
			if o, ok := r.organizations[m.OrganizationID]; ok {
				out = append(out, cloneOrganization(o))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (r *Repo) ListOrganizations(ctx context.Context, search string, limit, offset int) ([]*domain.Organization, int64, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := make([]*domain.Organization, 0, len(r.organizations))
	for _, o := range r.organizations {
		if search != "" {
			if !containsFold(o.Name, search) && !containsFold(o.Slug, search) {
				continue
			}
		}
		all = append(all, cloneOrganization(o))
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})
	total := int64(len(all))
	if offset < 0 {
		offset = 0
	}
	if offset > len(all) {
		offset = len(all)
	}
	end := len(all)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return all[offset:end], total, nil
}

// --- Membership ---

func membershipKey(orgID, userID string) string {
	return orgID + ":" + userID
}

func (r *Repo) CreateMembership(ctx context.Context, input domain.NewMembership) (domain.Membership, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, dup := r.memberships[input.ID]; dup {
		return domain.Membership{}, yautherr.ErrConflict
	}
	key := membershipKey(input.OrganizationID, input.UserID)
	if _, dup := r.membershipOrgUserIdx[key]; dup {
		return domain.Membership{}, yautherr.ErrConflict
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
	m := &domain.Membership{
		ID:             input.ID,
		OrganizationID: input.OrganizationID,
		UserID:         input.UserID,
		Role:           input.Role,
		Status:         input.Status,
		InvitedAt:      ptrUTC(input.InvitedAt),
		JoinedAt:       ptrUTC(input.JoinedAt),
		CreatedAt:      created.UTC(),
		UpdatedAt:      updated.UTC(),
	}
	r.memberships[m.ID] = m
	r.membershipOrgUserIdx[key] = m.ID
	return *cloneMembership(m), nil
}

func (r *Repo) GetMembershipByID(ctx context.Context, id string) (*domain.Membership, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.memberships[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneMembership(m), nil
}

// GetMembershipByOrgUser returns nil with no error when the user is not a
// member of the org — "not a member" is a normal state, not an error.
func (r *Repo) GetMembershipByOrgUser(ctx context.Context, orgID, userID string) (*domain.Membership, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.membershipOrgUserIdx[membershipKey(orgID, userID)]
	if !ok {
		return nil, nil
	}
	return cloneMembership(r.memberships[id]), nil
}

// memrepoOwnerRole is the string the RBAC plugin (auth/rbac.go) uses
// for the owner role. Duplicated here to keep memrepo standalone — the
// auth package depends on memrepo for tests, not the other way around.
const memrepoOwnerRole = "owner"

// countOwnersInOrg returns how many active memberships in orgID hold
// the owner role. Caller MUST hold r.mu (read or write lock).
func (r *Repo) countOwnersInOrg(orgID string) int {
	n := 0
	for _, m := range r.memberships {
		if m.OrganizationID == orgID && m.Role == memrepoOwnerRole {
			n++
		}
	}
	return n
}

func (r *Repo) UpdateMembership(ctx context.Context, id string, changes domain.UpdateMembership) (domain.Membership, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.memberships[id]
	if !ok {
		return domain.Membership{}, yautherr.ErrNotFound
	}
	// Owner-protection: refuse to demote the last owner. The
	// transfer-ownership handler atomically promotes the new owner
	// before this path runs, so a legitimate transfer never sees
	// "count == 1".
	if changes.Role != nil && m.Role == memrepoOwnerRole && *changes.Role != memrepoOwnerRole {
		if r.countOwnersInOrg(m.OrganizationID) <= 1 {
			return domain.Membership{}, yautherr.ErrOwnerProtected
		}
	}
	if changes.Role != nil {
		m.Role = *changes.Role
	}
	if changes.Status != nil {
		m.Status = *changes.Status
	}
	if changes.JoinedAt != nil {
		m.JoinedAt = ptrUTC(*changes.JoinedAt)
	}
	if changes.UpdatedAt != nil {
		m.UpdatedAt = changes.UpdatedAt.UTC()
	} else {
		m.UpdatedAt = time.Now().UTC()
	}
	return *cloneMembership(m), nil
}

func (r *Repo) DeleteMembership(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.memberships[id]
	if !ok {
		return nil
	}
	// Owner-protection: refuse to remove the last owner. The
	// transfer-ownership handler covers the legitimate path.
	if m.Role == memrepoOwnerRole && r.countOwnersInOrg(m.OrganizationID) <= 1 {
		return yautherr.ErrOwnerProtected
	}
	delete(r.membershipOrgUserIdx, membershipKey(m.OrganizationID, m.UserID))
	delete(r.memberships, id)
	return nil
}

func (r *Repo) ListMembershipsByOrg(ctx context.Context, orgID string) ([]*domain.Membership, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Membership, 0)
	for _, m := range r.memberships {
		if m.OrganizationID == orgID {
			out = append(out, cloneMembership(m))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (r *Repo) ListMembershipsByUser(ctx context.Context, userID string) ([]*domain.Membership, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Membership, 0)
	for _, m := range r.memberships {
		if m.UserID == userID {
			out = append(out, cloneMembership(m))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// --- Invitation ---

func (r *Repo) CreateInvitation(ctx context.Context, input domain.NewInvitation) (domain.Invitation, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.invitations[input.ID]; dup {
		return domain.Invitation{}, yautherr.ErrConflict
	}
	if _, dup := r.invitationTokenIdx[input.TokenHash]; dup {
		return domain.Invitation{}, yautherr.ErrConflict
	}
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	i := &domain.Invitation{
		ID:              input.ID,
		OrganizationID:  input.OrganizationID,
		Email:           input.Email,
		Role:            input.Role,
		TokenHash:       input.TokenHash,
		InvitedByUserID: input.InvitedByUserID,
		ExpiresAt:       input.ExpiresAt.UTC(),
		AcceptedAt:      ptrUTC(input.AcceptedAt),
		CreatedAt:       created.UTC(),
	}
	r.invitations[i.ID] = i
	r.invitationTokenIdx[i.TokenHash] = i.ID
	return *cloneInvitation(i), nil
}

func (r *Repo) GetInvitationByID(ctx context.Context, id string) (*domain.Invitation, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	inv, ok := r.invitations[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneInvitation(inv), nil
}

// GetInvitationByTokenHash filters out expired and already-accepted rows,
// returning (nil, nil) in those cases so callers don't have to repeat the
// check.
func (r *Repo) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*domain.Invitation, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.invitationTokenIdx[tokenHash]
	if !ok {
		return nil, nil
	}
	inv := r.invitations[id]
	if inv.AcceptedAt != nil {
		return nil, nil
	}
	if !inv.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, nil
	}
	return cloneInvitation(inv), nil
}

func (r *Repo) MarkInvitationAccepted(ctx context.Context, id string, acceptedAt time.Time) (domain.Invitation, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	inv, ok := r.invitations[id]
	if !ok {
		return domain.Invitation{}, yautherr.ErrNotFound
	}
	if inv.AcceptedAt != nil {
		// Single-shot: a second accept returns NotFound by contract.
		return domain.Invitation{}, yautherr.ErrNotFound
	}
	t := acceptedAt.UTC()
	inv.AcceptedAt = &t
	return *cloneInvitation(inv), nil
}

func (r *Repo) DeleteInvitation(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	inv, ok := r.invitations[id]
	if !ok {
		return nil
	}
	delete(r.invitationTokenIdx, inv.TokenHash)
	delete(r.invitations, id)
	return nil
}

func (r *Repo) ListPendingInvitationsForOrg(ctx context.Context, orgID string) ([]*domain.Invitation, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Invitation, 0)
	for _, inv := range r.invitations {
		if inv.OrganizationID == orgID && inv.AcceptedAt == nil {
			out = append(out, cloneInvitation(inv))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// --- clones ---

func cloneOrganization(o *domain.Organization) *domain.Organization {
	if o == nil {
		return nil
	}
	c := *o
	if o.DisplayName != nil {
		v := *o.DisplayName
		c.DisplayName = &v
	}
	if o.AvatarURL != nil {
		v := *o.AvatarURL
		c.AvatarURL = &v
	}
	c.Metadata = cloneBytes(o.Metadata)
	return &c
}

func cloneMembership(m *domain.Membership) *domain.Membership {
	if m == nil {
		return nil
	}
	c := *m
	c.InvitedAt = ptrUTC(m.InvitedAt)
	c.JoinedAt = ptrUTC(m.JoinedAt)
	return &c
}

func cloneInvitation(i *domain.Invitation) *domain.Invitation {
	if i == nil {
		return nil
	}
	c := *i
	c.AcceptedAt = ptrUTC(i.AcceptedAt)
	return &c
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// ptrUTC returns a fresh pointer to the UTC-normalized copy of t, or nil
// when t is nil. Centralizes the "store every time pointer as UTC and
// don't alias the caller's pointer" pattern used across the memrepo.
func ptrUTC(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
