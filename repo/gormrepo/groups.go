package gormrepo

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- models ---

// Group mirrors yauth_groups.
type Group struct {
	ID             string    `gorm:"column:id;primaryKey"`
	OrganizationID string    `gorm:"column:organization_id;not null;index;uniqueIndex:ux_group_org_name,priority:1;uniqueIndex:ux_group_org_ext,priority:1"`
	Name           string    `gorm:"column:name;not null;uniqueIndex:ux_group_org_name,priority:2"`
	Description    *string   `gorm:"column:description"`
	ExternalID     *string   `gorm:"column:external_id;uniqueIndex:ux_group_org_ext,priority:2"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null"`
}

func (Group) TableName() string { return "yauth_groups" }

func (m *Group) toDomain() domain.Group {
	return domain.Group{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		Name:           m.Name,
		Description:    m.Description,
		ExternalID:     m.ExternalID,
		CreatedAt:      m.CreatedAt.UTC(),
		UpdatedAt:      m.UpdatedAt.UTC(),
	}
}

// GroupMember mirrors yauth_group_members.
type GroupMember struct {
	GroupID   string    `gorm:"column:group_id;primaryKey"`
	UserID    string    `gorm:"column:user_id;primaryKey;index"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (GroupMember) TableName() string { return "yauth_group_members" }

// ClientGroupAssignment mirrors yauth_client_group_assignments.
type ClientGroupAssignment struct {
	ClientID  string    `gorm:"column:client_id;primaryKey"`
	GroupID   string    `gorm:"column:group_id;primaryKey;index"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (ClientGroupAssignment) TableName() string { return "yauth_client_group_assignments" }

// --- methods ---

func (r *Repo) CreateGroup(ctx context.Context, input domain.NewGroup) (domain.Group, error) {
	now := time.Now().UTC()
	if input.CreatedAt.IsZero() {
		input.CreatedAt = now
	}
	if input.UpdatedAt.IsZero() {
		input.UpdatedAt = now
	}
	m := Group{
		ID:             input.ID,
		OrganizationID: input.OrganizationID,
		Name:           input.Name,
		Description:    input.Description,
		ExternalID:     input.ExternalID,
		CreatedAt:      input.CreatedAt.UTC(),
		UpdatedAt:      input.UpdatedAt.UTC(),
	}
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.Group{}, yautherr.ErrConflict
		}
		return domain.Group{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) GetGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	var m Group
	err := r.ctx(ctx).Where("id = ?", id).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetGroupByOrgAndName(ctx context.Context, orgID, name string) (*domain.Group, error) {
	var m Group
	err := r.ctx(ctx).Where("organization_id = ? AND name = ?", orgID, name).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetGroupByOrgAndExternalID(ctx context.Context, orgID, externalID string) (*domain.Group, error) {
	var m Group
	err := r.ctx(ctx).Where("organization_id = ? AND external_id = ?", orgID, externalID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ListGroupsByOrg(ctx context.Context, orgID string) ([]*domain.Group, error) {
	var rows []Group
	if err := r.ctx(ctx).Where("organization_id = ?", orgID).Order("name").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Group, 0, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out = append(out, &d)
	}
	return out, nil
}

func (r *Repo) UpdateGroup(ctx context.Context, id string, changes domain.UpdateGroup) (domain.Group, error) {
	var m Group
	err := r.ctx(ctx).Where("id = ?", id).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.Group{}, yautherr.ErrNotFound
	}
	if err != nil {
		return domain.Group{}, err
	}
	if changes.Name != nil {
		m.Name = *changes.Name
	}
	if changes.Description != nil {
		m.Description = changes.Description
	}
	if changes.ExternalID != nil {
		m.ExternalID = changes.ExternalID
	}
	m.UpdatedAt = time.Now().UTC()
	if err := r.ctx(ctx).Save(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.Group{}, yautherr.ErrConflict
		}
		return domain.Group{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteGroup(ctx context.Context, id string) error {
	if err := r.ctx(ctx).Where("group_id = ?", id).Delete(&GroupMember{}).Error; err != nil {
		return err
	}
	if err := r.ctx(ctx).Where("group_id = ?", id).Delete(&ClientGroupAssignment{}).Error; err != nil {
		return err
	}
	return r.ctx(ctx).Where("id = ?", id).Delete(&Group{}).Error
}

func (r *Repo) AddGroupMember(ctx context.Context, groupID, userID string, now time.Time) error {
	m := GroupMember{GroupID: groupID, UserID: userID, CreatedAt: now.UTC()}
	// Idempotent: ignore the conflict when the membership already exists.
	err := r.ctx(ctx).Create(&m).Error
	if err != nil && isUniqueViolation(err) {
		return nil
	}
	return err
}

func (r *Repo) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	return r.ctx(ctx).Where("group_id = ? AND user_id = ?", groupID, userID).Delete(&GroupMember{}).Error
}

func (r *Repo) ListGroupMembers(ctx context.Context, groupID string) ([]*domain.User, error) {
	var users []User
	err := r.ctx(ctx).
		Select("yauth_users.*").
		Joins("JOIN yauth_group_members gm ON gm.user_id = yauth_users.id").
		Where("gm.group_id = ?", groupID).
		Order("yauth_users.email").
		Find(&users).Error
	if err != nil {
		return nil, err
	}
	out := make([]*domain.User, 0, len(users))
	for i := range users {
		d := users[i].toDomain()
		out = append(out, &d)
	}
	return out, nil
}

func (r *Repo) ListGroupsForUser(ctx context.Context, orgID, userID string) ([]*domain.Group, error) {
	var rows []Group
	err := r.ctx(ctx).
		Select("yauth_groups.*").
		Joins("JOIN yauth_group_members gm ON gm.group_id = yauth_groups.id").
		Where("yauth_groups.organization_id = ? AND gm.user_id = ?", orgID, userID).
		Order("yauth_groups.name").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Group, 0, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out = append(out, &d)
	}
	return out, nil
}

func (r *Repo) ListGroupNamesForUser(ctx context.Context, userID string) ([]string, error) {
	var names []string
	err := r.ctx(ctx).
		Model(&Group{}).
		Distinct("yauth_groups.name").
		Joins("JOIN yauth_group_members gm ON gm.group_id = yauth_groups.id").
		Where("gm.user_id = ?", userID).
		Order("yauth_groups.name").
		Pluck("yauth_groups.name", &names).Error
	return names, err
}

func (r *Repo) IsGroupMember(ctx context.Context, groupID, userID string) (bool, error) {
	var count int64
	err := r.ctx(ctx).Model(&GroupMember{}).
		Where("group_id = ? AND user_id = ?", groupID, userID).
		Count(&count).Error
	return count > 0, err
}

func (r *Repo) AssignClientGroup(ctx context.Context, clientID, groupID string, now time.Time) error {
	m := ClientGroupAssignment{ClientID: clientID, GroupID: groupID, CreatedAt: now.UTC()}
	err := r.ctx(ctx).Create(&m).Error
	if err != nil && isUniqueViolation(err) {
		return nil
	}
	return err
}

func (r *Repo) UnassignClientGroup(ctx context.Context, clientID, groupID string) error {
	return r.ctx(ctx).Where("client_id = ? AND group_id = ?", clientID, groupID).Delete(&ClientGroupAssignment{}).Error
}

func (r *Repo) ListClientGroups(ctx context.Context, clientID string) ([]*domain.Group, error) {
	var rows []Group
	err := r.ctx(ctx).
		Select("yauth_groups.*").
		Joins("JOIN yauth_client_group_assignments a ON a.group_id = yauth_groups.id").
		Where("a.client_id = ?", clientID).
		Order("yauth_groups.name").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Group, 0, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out = append(out, &d)
	}
	return out, nil
}

func (r *Repo) UserInAssignedGroup(ctx context.Context, clientID, userID string) (bool, error) {
	var count int64
	err := r.ctx(ctx).
		Table("yauth_client_group_assignments AS a").
		Joins("JOIN yauth_group_members gm ON gm.group_id = a.group_id").
		Where("a.client_id = ? AND gm.user_id = ?", clientID, userID).
		Count(&count).Error
	return count > 0, err
}

func (r *Repo) SetClientEnforceGroupAssignment(ctx context.Context, clientID string, enforce bool) error {
	return r.ctx(ctx).Model(&OAuth2Client{}).
		Where("client_id = ?", clientID).
		Update("enforce_group_assignment", enforce).Error
}
