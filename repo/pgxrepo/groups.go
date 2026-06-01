package pgxrepo

import (
	"context"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	pgxgen "github.com/yackey-labs/yauth-go/repo/pgxrepo/gen"
)

func groupToDomain(m pgxgen.YauthGroup) domain.Group {
	return domain.Group{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		Name:           m.Name,
		Description:    m.Description,
		ExternalID:     m.ExternalID,
		CreatedAt:      fromTS(m.CreatedAt),
		UpdatedAt:      fromTS(m.UpdatedAt),
	}
}

func (r *Repo) CreateGroup(ctx context.Context, input domain.NewGroup) (domain.Group, error) {
	row, err := r.q.CreateGroup(ctx, pgxgen.CreateGroupParams{
		ID:             input.ID,
		OrganizationID: input.OrganizationID,
		Name:           input.Name,
		Description:    input.Description,
		ExternalID:     input.ExternalID,
		CreatedAt:      ts(input.CreatedAt),
		UpdatedAt:      ts(input.UpdatedAt),
	})
	if err != nil {
		return domain.Group{}, err
	}
	return groupToDomain(row), nil
}

func (r *Repo) GetGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	row, err := r.q.GetGroupByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	g := groupToDomain(row)
	return &g, nil
}

func (r *Repo) GetGroupByOrgAndName(ctx context.Context, orgID, name string) (*domain.Group, error) {
	row, err := r.q.GetGroupByOrgAndName(ctx, pgxgen.GetGroupByOrgAndNameParams{
		OrganizationID: orgID,
		Name:           name,
	})
	if err != nil {
		return nil, notFound(err)
	}
	g := groupToDomain(row)
	return &g, nil
}

func (r *Repo) GetGroupByOrgAndExternalID(ctx context.Context, orgID, externalID string) (*domain.Group, error) {
	row, err := r.q.GetGroupByOrgAndExternalID(ctx, pgxgen.GetGroupByOrgAndExternalIDParams{
		OrganizationID: orgID,
		ExternalID:     &externalID,
	})
	if err != nil {
		return nil, notFound(err)
	}
	g := groupToDomain(row)
	return &g, nil
}

func (r *Repo) ListGroupsByOrg(ctx context.Context, orgID string) ([]*domain.Group, error) {
	rows, err := r.q.ListGroupsByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Group, 0, len(rows))
	for _, row := range rows {
		g := groupToDomain(row)
		out = append(out, &g)
	}
	return out, nil
}

func (r *Repo) UpdateGroup(ctx context.Context, id string, changes domain.UpdateGroup) (domain.Group, error) {
	// Read-modify-write: overlay the non-nil changes onto the current row so a
	// single full UPDATE persists the merge.
	cur, err := r.q.GetGroupByID(ctx, id)
	if err != nil {
		return domain.Group{}, notFound(err)
	}
	name := cur.Name
	if changes.Name != nil {
		name = *changes.Name
	}
	desc := cur.Description
	if changes.Description != nil {
		desc = changes.Description
	}
	ext := cur.ExternalID
	if changes.ExternalID != nil {
		ext = changes.ExternalID
	}
	row, err := r.q.UpdateGroup(ctx, pgxgen.UpdateGroupParams{
		ID:          id,
		Name:        name,
		Description: desc,
		ExternalID:  ext,
		UpdatedAt:   ts(time.Now().UTC()),
	})
	if err != nil {
		return domain.Group{}, err
	}
	return groupToDomain(row), nil
}

func (r *Repo) DeleteGroup(ctx context.Context, id string) error {
	return r.q.DeleteGroup(ctx, id)
}

func (r *Repo) AddGroupMember(ctx context.Context, groupID, userID string, now time.Time) error {
	return r.q.AddGroupMember(ctx, pgxgen.AddGroupMemberParams{
		GroupID:   groupID,
		UserID:    userID,
		CreatedAt: ts(now),
	})
}

func (r *Repo) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	return r.q.RemoveGroupMember(ctx, pgxgen.RemoveGroupMemberParams{
		GroupID: groupID,
		UserID:  userID,
	})
}

func (r *Repo) ListGroupMembers(ctx context.Context, groupID string) ([]*domain.User, error) {
	rows, err := r.q.ListGroupMembers(ctx, groupID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.User, 0, len(rows))
	for _, row := range rows {
		u := userToDomain(row)
		out = append(out, &u)
	}
	return out, nil
}

func (r *Repo) ListGroupsForUser(ctx context.Context, orgID, userID string) ([]*domain.Group, error) {
	rows, err := r.q.ListGroupsForUser(ctx, pgxgen.ListGroupsForUserParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Group, 0, len(rows))
	for _, row := range rows {
		g := groupToDomain(row)
		out = append(out, &g)
	}
	return out, nil
}

func (r *Repo) IsGroupMember(ctx context.Context, groupID, userID string) (bool, error) {
	return r.q.IsGroupMember(ctx, pgxgen.IsGroupMemberParams{
		GroupID: groupID,
		UserID:  userID,
	})
}

func (r *Repo) AssignClientGroup(ctx context.Context, clientID, groupID string, now time.Time) error {
	return r.q.AssignClientGroup(ctx, pgxgen.AssignClientGroupParams{
		ClientID:  clientID,
		GroupID:   groupID,
		CreatedAt: ts(now),
	})
}

func (r *Repo) UnassignClientGroup(ctx context.Context, clientID, groupID string) error {
	return r.q.UnassignClientGroup(ctx, pgxgen.UnassignClientGroupParams{
		ClientID: clientID,
		GroupID:  groupID,
	})
}

func (r *Repo) ListClientGroups(ctx context.Context, clientID string) ([]*domain.Group, error) {
	rows, err := r.q.ListClientGroups(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Group, 0, len(rows))
	for _, row := range rows {
		g := groupToDomain(row)
		out = append(out, &g)
	}
	return out, nil
}

func (r *Repo) UserInAssignedGroup(ctx context.Context, clientID, userID string) (bool, error) {
	return r.q.UserInAssignedGroup(ctx, pgxgen.UserInAssignedGroupParams{
		ClientID: clientID,
		UserID:   userID,
	})
}

func (r *Repo) SetClientEnforceGroupAssignment(ctx context.Context, clientID string, enforce bool) error {
	_, err := r.q.SetOAuth2ClientEnforceGroupAssignment(ctx, pgxgen.SetOAuth2ClientEnforceGroupAssignmentParams{
		ClientID:               clientID,
		EnforceGroupAssignment: enforce,
	})
	return err
}
