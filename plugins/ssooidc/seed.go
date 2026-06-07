package ssooidc

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
)

// connectionCreator is the slice of the repository SeedConnection needs. Both
// pgxrepo and memrepo satisfy it.
type connectionCreator interface {
	CreateSsoConnection(ctx context.Context, in domain.NewSsoConnection) (domain.SsoConnection, error)
}

// SeedConnectionInput describes an OIDC SSO connection to provision
// programmatically (connection-as-code).
type SeedConnectionInput struct {
	OrganizationID         string
	Name                   string
	Status                 domain.ConnectionStatus // default: active
	JitProvisioningEnabled bool
	DefaultRoleOnJit       string
	OIDC                   OidcConnectionConfig
}

// SeedConnection provisions an OIDC SSO connection directly through the repo,
// encrypting the upstream client_secret with key exactly as the admin API does
// (AES-256-GCM via the connection codec). It exists so apps and tests can
// declare connections as config/code instead of driving the admin HTTP API —
// the connection's client_secret never has to be copy-pasted through a UI.
//
// It is NOT idempotent; callers that re-run on boot should check existence
// (e.g. list the org's connections) first. claim_mappings default to
// DefaultClaimMappings() when omitted.
func SeedConnection(ctx context.Context, repo connectionCreator, key [32]byte, in SeedConnectionInput) (domain.SsoConnection, error) {
	if in.OIDC.ClaimMappings.Email == "" && in.OIDC.ClaimMappings.ExternalID == "" {
		in.OIDC.ClaimMappings = DefaultClaimMappings()
	}
	raw, err := marshalOidcConfig(key, in.OIDC) // validates + encrypts the secret
	if err != nil {
		return domain.SsoConnection{}, err
	}
	status := in.Status
	if status == "" {
		status = domain.ConnectionStatusActive
	}
	now := time.Now().UTC()
	return repo.CreateSsoConnection(ctx, domain.NewSsoConnection{
		ID:                     uuid.NewString(),
		OrganizationID:         in.OrganizationID,
		Kind:                   domain.ConnectionKindOIDCClient,
		Name:                   in.Name,
		Status:                 status,
		Config:                 raw,
		JitProvisioningEnabled: in.JitProvisioningEnabled,
		DefaultRoleOnJit:       in.DefaultRoleOnJit,
		CreatedAt:              now,
		UpdatedAt:              now,
	})
}
