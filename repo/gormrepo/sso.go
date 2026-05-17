// sso.go — gorm-backed SsoConnectionRepository,
// ExternalIdentityRepository, and SsoLoginStateRepository (yauth #93 /
// yauth-go #23).
//
// Config is stored as TEXT/JSON: the in-memory shape is []byte and the
// repo treats it as opaque — encryption of the ClientSecret happens at
// the plugin boundary, not here.
package gormrepo

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// SsoConnection mirrors yauth_sso_connections.
type SsoConnection struct {
	ID                     string    `gorm:"column:id;primaryKey"`
	OrganizationID         string    `gorm:"column:organization_id;not null;index"`
	Kind                   string    `gorm:"column:kind;not null"`
	Name                   string    `gorm:"column:name;not null"`
	Status                 string    `gorm:"column:status;not null"`
	Config                 string    `gorm:"column:config;type:text;not null"`
	JitProvisioningEnabled bool      `gorm:"column:jit_provisioning_enabled;not null"`
	DefaultRoleOnJit       string    `gorm:"column:default_role_on_jit;not null"`
	CreatedAt              time.Time `gorm:"column:created_at;not null"`
	UpdatedAt              time.Time `gorm:"column:updated_at;not null"`
}

func (SsoConnection) TableName() string { return "yauth_sso_connections" }

func (m *SsoConnection) toDomain() domain.SsoConnection {
	kind, _ := domain.ParseConnectionKind(m.Kind)
	status, _ := domain.ParseConnectionStatus(m.Status)
	return domain.SsoConnection{
		ID:                     m.ID,
		OrganizationID:         m.OrganizationID,
		Kind:                   kind,
		Name:                   m.Name,
		Status:                 status,
		Config:                 []byte(m.Config),
		JitProvisioningEnabled: m.JitProvisioningEnabled,
		DefaultRoleOnJit:       m.DefaultRoleOnJit,
		CreatedAt:              m.CreatedAt.UTC(),
		UpdatedAt:              m.UpdatedAt.UTC(),
	}
}

func ssoConnectionFromDomain(in domain.NewSsoConnection) SsoConnection {
	kind := in.Kind
	if !kind.IsValid() {
		kind = domain.ConnectionKindOIDCClient
	}
	status := in.Status
	if !status.IsValid() {
		status = domain.ConnectionStatusDraft
	}
	return SsoConnection{
		ID:                     in.ID,
		OrganizationID:         in.OrganizationID,
		Kind:                   string(kind),
		Name:                   in.Name,
		Status:                 string(status),
		Config:                 string(in.Config),
		JitProvisioningEnabled: in.JitProvisioningEnabled,
		DefaultRoleOnJit:       in.DefaultRoleOnJit,
		CreatedAt:              in.CreatedAt.UTC(),
		UpdatedAt:              in.UpdatedAt.UTC(),
	}
}

func (r *Repo) CreateSsoConnection(ctx context.Context, input domain.NewSsoConnection) (domain.SsoConnection, error) {
	m := ssoConnectionFromDomain(input)
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = m.CreatedAt
	}
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.SsoConnection{}, yautherr.ErrConflict
		}
		return domain.SsoConnection{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) GetSsoConnectionByID(ctx context.Context, id string) (*domain.SsoConnection, error) {
	var m SsoConnection
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ListSsoConnectionsByOrg(ctx context.Context, organizationID string) ([]*domain.SsoConnection, error) {
	var rows []SsoConnection
	if err := r.ctx(ctx).
		Where("organization_id = ?", organizationID).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.SsoConnection, 0, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out = append(out, &d)
	}
	return out, nil
}

func (r *Repo) UpdateSsoConnection(ctx context.Context, id string, changes domain.UpdateSsoConnection) (domain.SsoConnection, error) {
	var m SsoConnection
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		if changes.Name != nil {
			m.Name = *changes.Name
		}
		if changes.Status != nil && changes.Status.IsValid() {
			m.Status = string(*changes.Status)
		}
		if changes.Config != nil {
			m.Config = string(*changes.Config)
		}
		if changes.JitProvisioningEnabled != nil {
			m.JitProvisioningEnabled = *changes.JitProvisioningEnabled
		}
		if changes.DefaultRoleOnJit != nil {
			m.DefaultRoleOnJit = *changes.DefaultRoleOnJit
		}
		if changes.UpdatedAt != nil {
			m.UpdatedAt = changes.UpdatedAt.UTC()
		} else {
			m.UpdatedAt = time.Now().UTC()
		}
		return tx.Save(&m).Error
	})
	if err != nil {
		return domain.SsoConnection{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteSsoConnection(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&SsoConnection{})
	return res.Error
}

// --- ExternalIdentity --------------------------------------------------

// ExternalIdentity mirrors yauth_external_identities. The (provider,
// external_id) pair is enforced via a composite uniqueIndex named
// "ux_ext_identity_provider_externalid".
type ExternalIdentity struct {
	ID          string    `gorm:"column:id;primaryKey"`
	UserID      string    `gorm:"column:user_id;not null;index"`
	Provider    string    `gorm:"column:provider;not null;uniqueIndex:ux_ext_identity_provider_externalid,priority:1"`
	ExternalID  string    `gorm:"column:external_id;not null;uniqueIndex:ux_ext_identity_provider_externalid,priority:2"`
	LinkedAt    time.Time `gorm:"column:linked_at;not null"`
	LastLoginAt time.Time `gorm:"column:last_login_at;not null"`
}

func (ExternalIdentity) TableName() string { return "yauth_external_identities" }

func (m *ExternalIdentity) toDomain() domain.ExternalIdentity {
	return domain.ExternalIdentity{
		ID:          m.ID,
		UserID:      m.UserID,
		Provider:    m.Provider,
		ExternalID:  m.ExternalID,
		LinkedAt:    m.LinkedAt.UTC(),
		LastLoginAt: m.LastLoginAt.UTC(),
	}
}

func (r *Repo) CreateExternalIdentity(ctx context.Context, input domain.NewExternalIdentity) (domain.ExternalIdentity, error) {
	now := time.Now().UTC()
	linked := input.LinkedAt
	if linked.IsZero() {
		linked = now
	}
	last := input.LastLoginAt
	if last.IsZero() {
		last = linked
	}
	m := ExternalIdentity{
		ID:          input.ID,
		UserID:      input.UserID,
		Provider:    input.Provider,
		ExternalID:  input.ExternalID,
		LinkedAt:    linked.UTC(),
		LastLoginAt: last.UTC(),
	}
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.ExternalIdentity{}, yautherr.ErrConflict
		}
		return domain.ExternalIdentity{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) GetExternalIdentityByProviderAndExternalID(ctx context.Context, provider, externalID string) (*domain.ExternalIdentity, error) {
	var m ExternalIdentity
	if err := r.ctx(ctx).
		Where("provider = ? AND external_id = ?", provider, externalID).
		First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ListExternalIdentitiesByUser(ctx context.Context, userID string) ([]*domain.ExternalIdentity, error) {
	var rows []ExternalIdentity
	if err := r.ctx(ctx).
		Where("user_id = ?", userID).
		Order("linked_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.ExternalIdentity, 0, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out = append(out, &d)
	}
	return out, nil
}

func (r *Repo) UpdateExternalIdentityLastLogin(ctx context.Context, id string, at time.Time) error {
	res := r.ctx(ctx).Model(&ExternalIdentity{}).
		Where("id = ?", id).
		Update("last_login_at", at.UTC())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteExternalIdentity(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&ExternalIdentity{})
	return res.Error
}

// --- SsoLoginState -----------------------------------------------------

// SsoLoginState mirrors yauth_sso_login_states.
type SsoLoginState struct {
	State        string    `gorm:"column:state;primaryKey"`
	ConnectionID string    `gorm:"column:connection_id;not null;index"`
	Nonce        string    `gorm:"column:nonce;not null"`
	PKCEVerifier string    `gorm:"column:pkce_verifier;not null"`
	RedirectURL  string    `gorm:"column:redirect_url"`
	CreatedAt    time.Time `gorm:"column:created_at;not null"`
	ExpiresAt    time.Time `gorm:"column:expires_at;not null;index"`
}

func (SsoLoginState) TableName() string { return "yauth_sso_login_states" }

func (r *Repo) CreateSsoLoginState(ctx context.Context, input domain.NewSsoLoginState) error {
	now := time.Now().UTC()
	created := input.CreatedAt
	if created.IsZero() {
		created = now
	}
	m := SsoLoginState{
		State:        input.State,
		ConnectionID: input.ConnectionID,
		Nonce:        input.Nonce,
		PKCEVerifier: input.PKCEVerifier,
		RedirectURL:  input.RedirectURL,
		CreatedAt:    created.UTC(),
		ExpiresAt:    input.ExpiresAt.UTC(),
	}
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return yautherr.ErrConflict
		}
		return err
	}
	return nil
}

func (r *Repo) ConsumeSsoLoginState(ctx context.Context, state string) (*domain.SsoLoginState, error) {
	var found *domain.SsoLoginState
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m SsoLoginState
		if err := tx.Where("state = ?", state).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil // soft-miss; we return nil result, no error
			}
			return err
		}
		if delErr := tx.Where("state = ?", state).Delete(&SsoLoginState{}).Error; delErr != nil {
			return delErr
		}
		if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
			return nil // expired -> already deleted, signal soft-miss
		}
		found = &domain.SsoLoginState{
			State:        m.State,
			ConnectionID: m.ConnectionID,
			Nonce:        m.Nonce,
			PKCEVerifier: m.PKCEVerifier,
			RedirectURL:  m.RedirectURL,
			CreatedAt:    m.CreatedAt.UTC(),
			ExpiresAt:    m.ExpiresAt.UTC(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}
