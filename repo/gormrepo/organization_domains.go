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

// OrganizationDomain mirrors yauth_organization_domains. Port of yauth
// Rust #90.
//
// DomainCanonical carries a trimmed-lowercased copy of Domain in the
// same row so the app-wide UNIQUE(domain) gate is a single ordinary
// uniqueIndex (no dialect-specific expression indexes or CITEXT). This
// follows the same pattern Organization uses for SlugLower.
type OrganizationDomain struct {
	ID                    string     `gorm:"column:id;primaryKey"`
	OrganizationID        string     `gorm:"column:organization_id;not null;index"`
	Domain                string     `gorm:"column:domain;not null"`
	DomainCanonical       string     `gorm:"column:domain_canonical;not null;uniqueIndex"`
	Status                string     `gorm:"column:status;not null"`
	VerificationToken     string     `gorm:"column:verification_token;not null"`
	VerifiedAt            *time.Time `gorm:"column:verified_at"`
	LastCheckedAt         *time.Time `gorm:"column:last_checked_at"`
	AutoJoinOnSignup      bool       `gorm:"column:auto_join_on_signup;not null"`
	DefaultRoleOnAutoJoin string     `gorm:"column:default_role_on_auto_join;not null"`
	RequireEmailVerified  bool       `gorm:"column:require_email_verified;not null"`
	CreatedAt             time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt             time.Time  `gorm:"column:updated_at;not null"`
}

func (OrganizationDomain) TableName() string { return "yauth_organization_domains" }

func (m *OrganizationDomain) toDomain() domain.OrganizationDomain {
	return domain.OrganizationDomain{
		ID:                    m.ID,
		OrganizationID:        m.OrganizationID,
		Domain:                m.Domain,
		Status:                domain.DomainStatus(m.Status),
		VerificationToken:     m.VerificationToken,
		VerifiedAt:            ptrUTC(m.VerifiedAt),
		LastCheckedAt:         ptrUTC(m.LastCheckedAt),
		AutoJoinOnSignup:      m.AutoJoinOnSignup,
		DefaultRoleOnAutoJoin: m.DefaultRoleOnAutoJoin,
		RequireEmailVerified:  m.RequireEmailVerified,
		CreatedAt:             m.CreatedAt.UTC(),
		UpdatedAt:             m.UpdatedAt.UTC(),
	}
}

func organizationDomainFromDomain(in domain.NewOrganizationDomain) OrganizationDomain {
	canon := strings.ToLower(strings.TrimSpace(in.Domain))
	return OrganizationDomain{
		ID:                    in.ID,
		OrganizationID:        in.OrganizationID,
		Domain:                canon,
		DomainCanonical:       canon,
		Status:                string(in.Status),
		VerificationToken:     in.VerificationToken,
		AutoJoinOnSignup:      in.AutoJoinOnSignup,
		DefaultRoleOnAutoJoin: in.DefaultRoleOnAutoJoin,
		RequireEmailVerified:  in.RequireEmailVerified,
		CreatedAt:             in.CreatedAt.UTC(),
		UpdatedAt:             in.UpdatedAt.UTC(),
	}
}

// --- repo methods ---

func (r *Repo) CreateOrganizationDomain(ctx context.Context, input domain.NewOrganizationDomain) (domain.OrganizationDomain, error) {
	m := organizationDomainFromDomain(input)
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.OrganizationDomain{}, yautherr.ErrConflict
		}
		return domain.OrganizationDomain{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) GetOrganizationDomainByID(ctx context.Context, id string) (*domain.OrganizationDomain, error) {
	var m OrganizationDomain
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetOrganizationDomainByDomain(ctx context.Context, domainStr string) (*domain.OrganizationDomain, error) {
	var m OrganizationDomain
	canon := strings.ToLower(strings.TrimSpace(domainStr))
	if err := r.ctx(ctx).Where("domain_canonical = ?", canon).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ListOrganizationDomainsByOrg(ctx context.Context, organizationID string) ([]*domain.OrganizationDomain, error) {
	var rows []OrganizationDomain
	if err := r.ctx(ctx).
		Where("organization_id = ?", organizationID).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.OrganizationDomain, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) ListVerifiedAutoJoinOrganizationDomains(ctx context.Context, domainStr string) ([]*domain.OrganizationDomain, error) {
	canon := strings.ToLower(strings.TrimSpace(domainStr))
	var rows []OrganizationDomain
	if err := r.ctx(ctx).
		Where("domain_canonical = ? AND status = ? AND auto_join_on_signup = ?",
			canon, string(domain.DomainVerified), true).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.OrganizationDomain, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) UpdateOrganizationDomain(ctx context.Context, id string, changes domain.UpdateOrganizationDomain) (domain.OrganizationDomain, error) {
	var m OrganizationDomain
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		updates := map[string]any{}
		if changes.AutoJoinOnSignup != nil {
			updates["auto_join_on_signup"] = *changes.AutoJoinOnSignup
		}
		if changes.DefaultRoleOnAutoJoin != nil {
			updates["default_role_on_auto_join"] = *changes.DefaultRoleOnAutoJoin
		}
		if changes.RequireEmailVerified != nil {
			updates["require_email_verified"] = *changes.RequireEmailVerified
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
		return domain.OrganizationDomain{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) SetOrganizationDomainVerification(ctx context.Context, id string, status domain.DomainStatus, verifiedAt *time.Time, lastCheckedAt time.Time) (domain.OrganizationDomain, error) {
	var m OrganizationDomain
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		updates := map[string]any{
			"status":          string(status),
			"verified_at":     ptrUTC(verifiedAt),
			"last_checked_at": lastCheckedAt.UTC(),
			"updated_at":      lastCheckedAt.UTC(),
		}
		if err := tx.Model(&m).Updates(updates).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).First(&m).Error
	})
	if err != nil {
		return domain.OrganizationDomain{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteOrganizationDomain(ctx context.Context, id string) error {
	return r.ctx(ctx).Where("id = ?", id).Delete(&OrganizationDomain{}).Error
}
