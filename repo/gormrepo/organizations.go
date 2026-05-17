package gormrepo

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- Organization model ---

// Organization mirrors yauth_organizations. SlugLower is a normalized
// lowercased copy of Slug carried in the same row so we can enforce a
// case-insensitive uniqueness constraint with a single ordinary index —
// without writing dialect-specific expression indexes or CITEXT.
type Organization struct {
	ID          string    `gorm:"column:id;primaryKey"`
	Name        string    `gorm:"column:name;not null"`
	Slug        string    `gorm:"column:slug;not null"`
	SlugLower   string    `gorm:"column:slug_lower;not null;uniqueIndex"`
	DisplayName *string   `gorm:"column:display_name"`
	AvatarURL   *string   `gorm:"column:avatar_url"`
	Metadata    *string   `gorm:"column:metadata;type:text"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
}

func (Organization) TableName() string { return "yauth_organizations" }

func (m *Organization) toDomain() domain.Organization {
	return domain.Organization{
		ID:          m.ID,
		Name:        m.Name,
		Slug:        m.Slug,
		DisplayName: m.DisplayName,
		AvatarURL:   m.AvatarURL,
		Metadata:    rawJSONToBytes(m.Metadata),
		CreatedAt:   m.CreatedAt.UTC(),
		UpdatedAt:   m.UpdatedAt.UTC(),
	}
}

func organizationFromDomain(in domain.NewOrganization) Organization {
	return Organization{
		ID:          in.ID,
		Name:        in.Name,
		Slug:        in.Slug,
		SlugLower:   strings.ToLower(in.Slug),
		DisplayName: in.DisplayName,
		AvatarURL:   in.AvatarURL,
		Metadata:    strFromBytes(in.Metadata),
		CreatedAt:   in.CreatedAt.UTC(),
		UpdatedAt:   in.UpdatedAt.UTC(),
	}
}

// --- Membership model ---

// Membership mirrors yauth_memberships. The composite uniqueIndex on
// (organization_id, user_id) enforces the "one membership per (org,
// user)" invariant; cascade deletes are wired by FK at the DB.
type Membership struct {
	ID             string     `gorm:"column:id;primaryKey"`
	OrganizationID string     `gorm:"column:organization_id;not null;index;uniqueIndex:ux_membership_org_user"`
	UserID         string     `gorm:"column:user_id;not null;index;uniqueIndex:ux_membership_org_user"`
	Role           string     `gorm:"column:role;not null"`
	Status         string     `gorm:"column:status;not null"`
	InvitedAt      *time.Time `gorm:"column:invited_at"`
	JoinedAt       *time.Time `gorm:"column:joined_at"`
	CreatedAt      time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time  `gorm:"column:updated_at;not null"`
}

func (Membership) TableName() string { return "yauth_memberships" }

func (m *Membership) toDomain() domain.Membership {
	// Status is round-tripped as the raw column value. An unknown
	// row state surfaces as-is so callers can validate explicitly via
	// domain.MembershipStatus.IsValid() if they need to.
	status := domain.MembershipStatus(m.Status)
	return domain.Membership{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		UserID:         m.UserID,
		Role:           m.Role,
		Status:         status,
		InvitedAt:      ptrUTC(m.InvitedAt),
		JoinedAt:       ptrUTC(m.JoinedAt),
		CreatedAt:      m.CreatedAt.UTC(),
		UpdatedAt:      m.UpdatedAt.UTC(),
	}
}

func membershipFromDomain(in domain.NewMembership) Membership {
	return Membership{
		ID:             in.ID,
		OrganizationID: in.OrganizationID,
		UserID:         in.UserID,
		Role:           in.Role,
		Status:         string(in.Status),
		InvitedAt:      ptrUTC(in.InvitedAt),
		JoinedAt:       ptrUTC(in.JoinedAt),
		CreatedAt:      in.CreatedAt.UTC(),
		UpdatedAt:      in.UpdatedAt.UTC(),
	}
}

// --- Invitation model ---

// Invitation mirrors yauth_invitations. token_hash carries a uniqueness
// invariant so duplicate-hash inserts surface as ErrConflict.
type Invitation struct {
	ID              string     `gorm:"column:id;primaryKey"`
	OrganizationID  string     `gorm:"column:organization_id;not null;index"`
	Email           string     `gorm:"column:email;not null"`
	Role            string     `gorm:"column:role;not null"`
	TokenHash       string     `gorm:"column:token_hash;not null;uniqueIndex"`
	InvitedByUserID string     `gorm:"column:invited_by_user_id;not null"`
	ExpiresAt       time.Time  `gorm:"column:expires_at;not null"`
	AcceptedAt      *time.Time `gorm:"column:accepted_at"`
	CreatedAt       time.Time  `gorm:"column:created_at;not null"`
}

func (Invitation) TableName() string { return "yauth_invitations" }

func (m *Invitation) toDomain() domain.Invitation {
	return domain.Invitation{
		ID:              m.ID,
		OrganizationID:  m.OrganizationID,
		Email:           m.Email,
		Role:            m.Role,
		TokenHash:       m.TokenHash,
		InvitedByUserID: m.InvitedByUserID,
		ExpiresAt:       m.ExpiresAt.UTC(),
		AcceptedAt:      ptrUTC(m.AcceptedAt),
		CreatedAt:       m.CreatedAt.UTC(),
	}
}

func invitationFromDomain(in domain.NewInvitation) Invitation {
	return Invitation{
		ID:              in.ID,
		OrganizationID:  in.OrganizationID,
		Email:           in.Email,
		Role:            in.Role,
		TokenHash:       in.TokenHash,
		InvitedByUserID: in.InvitedByUserID,
		ExpiresAt:       in.ExpiresAt.UTC(),
		AcceptedAt:      ptrUTC(in.AcceptedAt),
		CreatedAt:       in.CreatedAt.UTC(),
	}
}

// --- Organization repo methods ---

func (r *Repo) CreateOrganization(ctx context.Context, input domain.NewOrganization) (domain.Organization, error) {
	m := organizationFromDomain(input)
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.Organization{}, yautherr.ErrConflict
		}
		return domain.Organization{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) GetOrganizationByID(ctx context.Context, id string) (*domain.Organization, error) {
	var m Organization
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetOrganizationBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	var m Organization
	if err := r.ctx(ctx).Where("slug_lower = ?", strings.ToLower(slug)).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) UpdateOrganization(ctx context.Context, id string, changes domain.UpdateOrganization) (domain.Organization, error) {
	var m Organization
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		updates := map[string]any{}
		if changes.Name != nil {
			updates["name"] = *changes.Name
		}
		if changes.Slug != nil {
			updates["slug"] = *changes.Slug
			updates["slug_lower"] = strings.ToLower(*changes.Slug)
		}
		if changes.DisplayName != nil {
			updates["display_name"] = *changes.DisplayName
		}
		if changes.AvatarURL != nil {
			updates["avatar_url"] = *changes.AvatarURL
		}
		if changes.Metadata != nil {
			if *changes.Metadata == nil {
				updates["metadata"] = (*string)(nil)
			} else {
				s := string(*changes.Metadata)
				updates["metadata"] = &s
			}
		}
		if changes.UpdatedAt != nil {
			updates["updated_at"] = changes.UpdatedAt.UTC()
		} else {
			updates["updated_at"] = time.Now().UTC()
		}
		if len(updates) == 0 {
			return nil
		}
		if err := tx.Model(&m).Updates(updates).Error; err != nil {
			if isUniqueViolation(err) {
				return yautherr.ErrConflict
			}
			return err
		}
		return tx.Where("id = ?", id).First(&m).Error
	})
	if err != nil {
		return domain.Organization{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteOrganization(ctx context.Context, id string) error {
	// Cascade is enforced application-side here too — many SQLite
	// configurations ship with FKs disabled, and we want the
	// semantics to hold regardless. We wrap in a single transaction
	// so a half-delete can never leak orphaned rows.
	return r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("organization_id = ?", id).Delete(&Invitation{}).Error; err != nil {
			return err
		}
		if err := tx.Where("organization_id = ?", id).Delete(&Membership{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&Organization{}).Error
	})
}

func (r *Repo) ListOrganizationsForUser(ctx context.Context, userID string) ([]*domain.Organization, error) {
	var rows []Organization
	if err := r.ctx(ctx).
		Where("id IN (?)",
			r.ctx(ctx).Model(&Membership{}).Select("organization_id").Where("user_id = ?", userID),
		).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Organization, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) ListOrganizations(ctx context.Context, search string, limit, offset int) ([]*domain.Organization, int64, error) {
	q := r.ctx(ctx).Model(&Organization{})
	if search != "" {
		pat := "%" + strings.ToLower(search) + "%"
		q = q.Where("LOWER(name) LIKE ? OR slug_lower LIKE ?", pat, pat)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	if offset > 0 {
		q = q.Offset(offset)
	}
	var rows []Organization
	if err := q.Order("created_at ASC, id ASC").Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]*domain.Organization, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, total, nil
}

// --- Membership repo methods ---

func (r *Repo) CreateMembership(ctx context.Context, input domain.NewMembership) (domain.Membership, error) {
	m := membershipFromDomain(input)
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.Membership{}, yautherr.ErrConflict
		}
		return domain.Membership{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) GetMembershipByID(ctx context.Context, id string) (*domain.Membership, error) {
	var m Membership
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

// GetMembershipByOrgUser returns (nil, nil) when the user is not a
// member — "not a member" is a normal state, not an error.
func (r *Repo) GetMembershipByOrgUser(ctx context.Context, orgID, userID string) (*domain.Membership, error) {
	var m Membership
	err := r.ctx(ctx).Where("organization_id = ? AND user_id = ?", orgID, userID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

// gormrepoOwnerRole is the string the RBAC plugin uses for the owner
// role. Duplicated here to keep gormrepo standalone from the auth
// package.
const gormrepoOwnerRole = "owner"

func (r *Repo) UpdateMembership(ctx context.Context, id string, changes domain.UpdateMembership) (domain.Membership, error) {
	var m Membership
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		// Owner-protection: refuse to demote the last owner. The
		// transfer-ownership handler atomically promotes the new
		// owner before running this update, so a legitimate
		// transfer never sees count == 1.
		if changes.Role != nil && m.Role == gormrepoOwnerRole && *changes.Role != gormrepoOwnerRole {
			var count int64
			if err := tx.Model(&Membership{}).
				Where("organization_id = ? AND role = ?", m.OrganizationID, gormrepoOwnerRole).
				Count(&count).Error; err != nil {
				return err
			}
			if count <= 1 {
				return yautherr.ErrOwnerProtected
			}
		}
		updates := map[string]any{}
		if changes.Role != nil {
			updates["role"] = *changes.Role
		}
		if changes.Status != nil {
			updates["status"] = string(*changes.Status)
		}
		if changes.JoinedAt != nil {
			updates["joined_at"] = ptrUTC(*changes.JoinedAt)
		}
		if changes.UpdatedAt != nil {
			updates["updated_at"] = changes.UpdatedAt.UTC()
		} else {
			updates["updated_at"] = time.Now().UTC()
		}
		if len(updates) == 0 {
			return nil
		}
		if err := tx.Model(&m).Updates(updates).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).First(&m).Error
	})
	if err != nil {
		return domain.Membership{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteMembership(ctx context.Context, id string) error {
	return r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m Membership
		if err := tx.Where("id = ?", id).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		if m.Role == gormrepoOwnerRole {
			var count int64
			if err := tx.Model(&Membership{}).
				Where("organization_id = ? AND role = ?", m.OrganizationID, gormrepoOwnerRole).
				Count(&count).Error; err != nil {
				return err
			}
			if count <= 1 {
				return yautherr.ErrOwnerProtected
			}
		}
		return tx.Where("id = ?", id).Delete(&Membership{}).Error
	})
}

func (r *Repo) ListMembershipsByOrg(ctx context.Context, orgID string) ([]*domain.Membership, error) {
	var rows []Membership
	if err := r.ctx(ctx).
		Where("organization_id = ?", orgID).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Membership, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) ListMembershipsByUser(ctx context.Context, userID string) ([]*domain.Membership, error) {
	var rows []Membership
	if err := r.ctx(ctx).
		Where("user_id = ?", userID).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Membership, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

// --- Invitation repo methods ---

func (r *Repo) CreateInvitation(ctx context.Context, input domain.NewInvitation) (domain.Invitation, error) {
	m := invitationFromDomain(input)
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.Invitation{}, yautherr.ErrConflict
		}
		return domain.Invitation{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) GetInvitationByID(ctx context.Context, id string) (*domain.Invitation, error) {
	var m Invitation
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

// GetInvitationByTokenHash filters out expired and already-accepted rows
// at the SQL layer so callers don't have to repeat the check.
func (r *Repo) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*domain.Invitation, error) {
	var m Invitation
	now := time.Now().UTC()
	err := r.ctx(ctx).
		Where("token_hash = ? AND accepted_at IS NULL AND expires_at > ?", tokenHash, now).
		First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

// MarkInvitationAccepted is single-shot — UPDATE … WHERE accepted_at IS
// NULL means a second call finds nothing to update and returns NotFound.
func (r *Repo) MarkInvitationAccepted(ctx context.Context, id string, acceptedAt time.Time) (domain.Invitation, error) {
	var m Invitation
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&Invitation{}).
			Where("id = ? AND accepted_at IS NULL", id).
			Update("accepted_at", acceptedAt.UTC())
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return yautherr.ErrNotFound
		}
		return tx.Where("id = ?", id).First(&m).Error
	})
	if err != nil {
		return domain.Invitation{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteInvitation(ctx context.Context, id string) error {
	return r.ctx(ctx).Where("id = ?", id).Delete(&Invitation{}).Error
}

func (r *Repo) ListPendingInvitationsForOrg(ctx context.Context, orgID string) ([]*domain.Invitation, error) {
	var rows []Invitation
	if err := r.ctx(ctx).
		Where("organization_id = ? AND accepted_at IS NULL", orgID).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Invitation, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}
