package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

func cloneGroup(g *domain.Group) *domain.Group {
	if g == nil {
		return nil
	}
	cp := *g
	return &cp
}

func (r *Repo) CreateGroup(ctx context.Context, input domain.NewGroup) (domain.Group, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, dup := r.groups[input.ID]; dup {
		return domain.Group{}, yautherr.ErrConflict
	}
	for _, g := range r.groups {
		if g.OrganizationID != input.OrganizationID {
			continue
		}
		if g.Name == input.Name {
			return domain.Group{}, yautherr.ErrConflict
		}
		if input.ExternalID != nil && g.ExternalID != nil && *g.ExternalID == *input.ExternalID {
			return domain.Group{}, yautherr.ErrConflict
		}
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
	g := &domain.Group{
		ID:             input.ID,
		OrganizationID: input.OrganizationID,
		Name:           input.Name,
		Description:    input.Description,
		ExternalID:     input.ExternalID,
		CreatedAt:      created.UTC(),
		UpdatedAt:      updated.UTC(),
	}
	r.groups[g.ID] = g
	return *cloneGroup(g), nil
}

func (r *Repo) GetGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.groups[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneGroup(g), nil
}

func (r *Repo) GetGroupByOrgAndName(ctx context.Context, orgID, name string) (*domain.Group, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, g := range r.groups {
		if g.OrganizationID == orgID && g.Name == name {
			return cloneGroup(g), nil
		}
	}
	return nil, yautherr.ErrNotFound
}

func (r *Repo) GetGroupByOrgAndExternalID(ctx context.Context, orgID, externalID string) (*domain.Group, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, g := range r.groups {
		if g.OrganizationID == orgID && g.ExternalID != nil && *g.ExternalID == externalID {
			return cloneGroup(g), nil
		}
	}
	return nil, yautherr.ErrNotFound
}

func (r *Repo) ListGroupsByOrg(ctx context.Context, orgID string) ([]*domain.Group, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Group, 0)
	for _, g := range r.groups {
		if g.OrganizationID == orgID {
			out = append(out, cloneGroup(g))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *Repo) UpdateGroup(ctx context.Context, id string, changes domain.UpdateGroup) (domain.Group, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.groups[id]
	if !ok {
		return domain.Group{}, yautherr.ErrNotFound
	}
	if changes.Name != nil {
		g.Name = *changes.Name
	}
	if changes.Description != nil {
		g.Description = changes.Description
	}
	if changes.ExternalID != nil {
		g.ExternalID = changes.ExternalID
	}
	g.UpdatedAt = time.Now().UTC()
	return *cloneGroup(g), nil
}

func (r *Repo) DeleteGroup(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.groups, id)
	delete(r.groupMembers, id)
	for cid, gs := range r.clientGroups {
		delete(gs, id)
		if len(gs) == 0 {
			delete(r.clientGroups, cid)
		}
	}
	return nil
}

func (r *Repo) AddGroupMember(ctx context.Context, groupID, userID string, now time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groupMembers[groupID] == nil {
		r.groupMembers[groupID] = make(map[string]time.Time)
	}
	if _, exists := r.groupMembers[groupID][userID]; !exists {
		r.groupMembers[groupID][userID] = now.UTC()
	}
	return nil
}

func (r *Repo) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.groupMembers[groupID], userID)
	return nil
}

func (r *Repo) ListGroupMembers(ctx context.Context, groupID string) ([]*domain.User, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.User, 0)
	for uid := range r.groupMembers[groupID] {
		if u, ok := r.users[uid]; ok {
			cp := *u
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (r *Repo) ListGroupsForUser(ctx context.Context, orgID, userID string) ([]*domain.Group, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Group, 0)
	for gid, members := range r.groupMembers {
		if _, ok := members[userID]; !ok {
			continue
		}
		g, ok := r.groups[gid]
		if ok && g.OrganizationID == orgID {
			out = append(out, cloneGroup(g))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *Repo) ListGroupNamesForUser(ctx context.Context, userID string) ([]string, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]struct{})
	var out []string
	for gid, mem := range r.groupMembers {
		if _, ok := mem[userID]; !ok {
			continue
		}
		if g, ok := r.groups[gid]; ok {
			if _, dup := seen[g.Name]; !dup {
				seen[g.Name] = struct{}{}
				out = append(out, g.Name)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (r *Repo) IsGroupMember(ctx context.Context, groupID, userID string) (bool, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.groupMembers[groupID][userID]
	return ok, nil
}

func (r *Repo) AssignClientGroup(ctx context.Context, clientID, groupID string, now time.Time) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.clientGroups[clientID] == nil {
		r.clientGroups[clientID] = make(map[string]time.Time)
	}
	if _, exists := r.clientGroups[clientID][groupID]; !exists {
		r.clientGroups[clientID][groupID] = now.UTC()
	}
	return nil
}

func (r *Repo) UnassignClientGroup(ctx context.Context, clientID, groupID string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clientGroups[clientID], groupID)
	return nil
}

func (r *Repo) ListClientGroups(ctx context.Context, clientID string) ([]*domain.Group, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Group, 0)
	for gid := range r.clientGroups[clientID] {
		if g, ok := r.groups[gid]; ok {
			out = append(out, cloneGroup(g))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *Repo) UserInAssignedGroup(ctx context.Context, clientID, userID string) (bool, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for gid := range r.clientGroups[clientID] {
		if _, ok := r.groupMembers[gid][userID]; ok {
			return true, nil
		}
	}
	return false, nil
}

func (r *Repo) AssignClientRole(ctx context.Context, input domain.NewClientRoleAssignment) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	r.clientRoles[input.ID] = &domain.ClientRoleAssignment{
		ID:        input.ID,
		ClientID:  input.ClientID,
		Role:      input.Role,
		GroupID:   input.GroupID,
		UserID:    input.UserID,
		CreatedAt: created.UTC(),
	}
	return nil
}

func (r *Repo) UnassignClientRole(ctx context.Context, assignmentID string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clientRoles, assignmentID)
	return nil
}

func (r *Repo) ListClientRoleAssignments(ctx context.Context, clientID string) ([]*domain.ClientRoleAssignment, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.ClientRoleAssignment, 0)
	for _, a := range r.clientRoles {
		if a.ClientID == clientID {
			cp := *a
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out, nil
}

func (r *Repo) ResolveUserRolesForClient(ctx context.Context, clientID, userID string) ([]string, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]struct{})
	var out []string
	for _, a := range r.clientRoles {
		if a.ClientID != clientID {
			continue
		}
		match := false
		if a.UserID != nil && *a.UserID == userID {
			match = true
		}
		if !match && a.GroupID != nil {
			if _, ok := r.groupMembers[*a.GroupID][userID]; ok {
				match = true
			}
		}
		if match {
			if _, dup := seen[a.Role]; !dup {
				seen[a.Role] = struct{}{}
				out = append(out, a.Role)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (r *Repo) SetClientEnforceGroupAssignment(ctx context.Context, clientID string, enforce bool) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.oauth2ClientIDIdx[clientID]
	if !ok {
		return yautherr.ErrNotFound
	}
	r.oauth2Clients[id].EnforceGroupAssignment = enforce
	return nil
}
