// organization_policies.go — gorm-backed OrganizationPolicyRepository
// implementation (yauth #92 / yauth-go #21).
//
// One row per organization keyed by organization_id (no separate id).
// IPAllowlist and AllowedAuthMethods are persisted as JSON-encoded TEXT
// columns so every dialect (sqlite/postgres/mysql) ships the migration
// with no array-type drift; the in-memory shape is []string and the
// conversion is a tiny helper at the model boundary.
package gormrepo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// OrganizationPolicy mirrors yauth_organization_policies.
//
// JSON-encoded slice columns:
//
//   - ip_allowlist_json    JSON-encoded []string of CIDR strings
//   - auth_methods_json    JSON-encoded []string of method names
//
// nil pointers are nil columns; pointer-to-zero is a real value.
type OrganizationPolicy struct {
	OrganizationID         string    `gorm:"column:organization_id;primaryKey"`
	MaxSessionDurationSecs *int64    `gorm:"column:max_session_duration_secs"`
	IdleTimeoutSecs        *int64    `gorm:"column:idle_timeout_secs"`
	MfaRequired            bool      `gorm:"column:mfa_required;not null"`
	MfaGracePeriodDays     int32     `gorm:"column:mfa_grace_period_days;not null"`
	IPAllowlistJSON        *string   `gorm:"column:ip_allowlist_json;type:text"`
	MaxConcurrentSessions  *int32    `gorm:"column:max_concurrent_sessions"`
	AuthMethodsJSON        *string   `gorm:"column:auth_methods_json;type:text"`
	SessionBinding         string    `gorm:"column:session_binding;not null"`
	CreatedAt              time.Time `gorm:"column:created_at;not null"`
	UpdatedAt              time.Time `gorm:"column:updated_at;not null"`
}

func (OrganizationPolicy) TableName() string { return "yauth_organization_policies" }

func (m *OrganizationPolicy) toDomain() domain.OrganizationPolicy {
	binding, _ := domain.ParseSessionBindingMode(m.SessionBinding)
	return domain.OrganizationPolicy{
		OrganizationID:         m.OrganizationID,
		MaxSessionDurationSecs: copyI64Ptr(m.MaxSessionDurationSecs),
		IdleTimeoutSecs:        copyI64Ptr(m.IdleTimeoutSecs),
		MfaRequired:            m.MfaRequired,
		MfaGracePeriodDays:     m.MfaGracePeriodDays,
		IPAllowlist:            decodeStringSlice(m.IPAllowlistJSON),
		MaxConcurrentSessions:  copyI32Ptr(m.MaxConcurrentSessions),
		AllowedAuthMethods:     decodeStringSlice(m.AuthMethodsJSON),
		SessionBinding:         binding,
		CreatedAt:              m.CreatedAt.UTC(),
		UpdatedAt:              m.UpdatedAt.UTC(),
	}
}

func organizationPolicyFromDomain(in domain.NewOrganizationPolicy) OrganizationPolicy {
	binding := in.SessionBinding
	if !binding.IsValid() {
		binding = domain.SessionBindingUnset
	}
	return OrganizationPolicy{
		OrganizationID:         in.OrganizationID,
		MaxSessionDurationSecs: copyI64Ptr(in.MaxSessionDurationSecs),
		IdleTimeoutSecs:        copyI64Ptr(in.IdleTimeoutSecs),
		MfaRequired:            in.MfaRequired,
		MfaGracePeriodDays:     in.MfaGracePeriodDays,
		IPAllowlistJSON:        encodeStringSlice(in.IPAllowlist),
		MaxConcurrentSessions:  copyI32Ptr(in.MaxConcurrentSessions),
		AuthMethodsJSON:        encodeStringSlice(in.AllowedAuthMethods),
		SessionBinding:         string(binding),
		CreatedAt:              in.CreatedAt.UTC(),
		UpdatedAt:              in.UpdatedAt.UTC(),
	}
}

// --- repo methods ---

func (r *Repo) GetOrganizationPolicy(ctx context.Context, organizationID string) (*domain.OrganizationPolicy, error) {
	var m OrganizationPolicy
	if err := r.ctx(ctx).Where("organization_id = ?", organizationID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) CreateOrganizationPolicy(ctx context.Context, input domain.NewOrganizationPolicy) (domain.OrganizationPolicy, error) {
	m := organizationPolicyFromDomain(input)
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = m.CreatedAt
	}
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.OrganizationPolicy{}, yautherr.ErrConflict
		}
		return domain.OrganizationPolicy{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) UpdateOrganizationPolicy(ctx context.Context, organizationID string, changes domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error) {
	var m OrganizationPolicy
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("organization_id = ?", organizationID).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		applyPolicyUpdates(&m, changes)
		return tx.Save(&m).Error
	})
	if err != nil {
		return domain.OrganizationPolicy{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) UpsertOrganizationPolicy(ctx context.Context, organizationID string, changes domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error) {
	var m OrganizationPolicy
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		findErr := tx.Where("organization_id = ?", organizationID).First(&m).Error
		if errors.Is(findErr, gorm.ErrRecordNotFound) {
			now := time.Now().UTC()
			m = OrganizationPolicy{
				OrganizationID: organizationID,
				SessionBinding: string(domain.SessionBindingUnset),
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			applyPolicyUpdates(&m, changes)
			return tx.Create(&m).Error
		}
		if findErr != nil {
			return findErr
		}
		applyPolicyUpdates(&m, changes)
		return tx.Save(&m).Error
	})
	if err != nil {
		return domain.OrganizationPolicy{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteOrganizationPolicy(ctx context.Context, organizationID string) error {
	res := r.ctx(ctx).Where("organization_id = ?", organizationID).Delete(&OrganizationPolicy{})
	return res.Error
}

// --- helpers ---

func applyPolicyUpdates(m *OrganizationPolicy, changes domain.UpdateOrganizationPolicy) {
	if changes.MaxSessionDurationSecs != nil {
		m.MaxSessionDurationSecs = copyI64Ptr(*changes.MaxSessionDurationSecs)
	}
	if changes.IdleTimeoutSecs != nil {
		m.IdleTimeoutSecs = copyI64Ptr(*changes.IdleTimeoutSecs)
	}
	if changes.MfaRequired != nil {
		m.MfaRequired = *changes.MfaRequired
	}
	if changes.MfaGracePeriodDays != nil {
		m.MfaGracePeriodDays = *changes.MfaGracePeriodDays
	}
	if changes.IPAllowlist != nil {
		m.IPAllowlistJSON = encodeStringSlice(*changes.IPAllowlist)
	}
	if changes.MaxConcurrentSessions != nil {
		m.MaxConcurrentSessions = copyI32Ptr(*changes.MaxConcurrentSessions)
	}
	if changes.AllowedAuthMethods != nil {
		m.AuthMethodsJSON = encodeStringSlice(*changes.AllowedAuthMethods)
	}
	if changes.SessionBinding != nil && changes.SessionBinding.IsValid() {
		m.SessionBinding = string(*changes.SessionBinding)
	}
	if changes.UpdatedAt != nil {
		m.UpdatedAt = changes.UpdatedAt.UTC()
	} else {
		m.UpdatedAt = time.Now().UTC()
	}
}

// encodeStringSlice marshals s as JSON. nil/empty becomes nil-pointer so
// the column stores NULL — which round-trips back through decodeStringSlice
// as a nil slice, preserving the inherit-global semantics.
func encodeStringSlice(s []string) *string {
	if len(s) == 0 {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal on []string is infallible in practice; fall
		// back to a NULL column rather than panicking.
		return nil
	}
	v := string(b)
	return &v
}

func decodeStringSlice(p *string) []string {
	if p == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*p)
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return nil
	}
	return out
}

func copyI64Ptr(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyI32Ptr(p *int32) *int32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
