// config.go — OidcConnectionConfig codec.
//
// The SsoConnection row carries the IdP-specific connection config as
// opaque []byte. This file defines the OIDC-client-flavored payload and
// the marshal/unmarshal helpers that bridge the wire shape (JSON with
// an *encrypted* client_secret) to the in-memory shape callers use.
package ssooidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yackey-labs/yauth/auth"
)

// ClaimMappings selects which claim names yauth pulls from the IdP's
// id_token to populate the JIT user record and apply the group→role
// mapping. Defaults follow the OIDC spec — most IdPs ship "email",
// "name", "sub", "groups" verbatim.
type ClaimMappings struct {
	// Email is the id_token claim used as the JIT user's email
	// address. Defaults to "email".
	Email string `json:"email,omitempty"`
	// DisplayName is the id_token claim copied into the JIT user's
	// display_name. nil/empty disables display-name JIT population.
	// Defaults to "name".
	DisplayName string `json:"display_name,omitempty"`
	// ExternalID is the id_token claim used as the ExternalIdentity
	// row's `external_id`. Defaults to "sub" — the canonical OIDC
	// stable-identifier claim.
	ExternalID string `json:"external_id,omitempty"`
	// Groups is the id_token claim that lists the user's group
	// memberships at the IdP. Empty disables group→role mapping.
	// Defaults to "groups".
	Groups string `json:"groups,omitempty"`
	// GroupToRole maps a raw group name from the IdP to a yauth-side
	// org role. Looked up case-sensitively. The first matching entry
	// wins. Empty leaves the role at the connection's
	// DefaultRoleOnJit.
	GroupToRole map[string]string `json:"group_to_role,omitempty"`
}

// DefaultClaimMappings returns the OIDC-spec-aligned defaults.
func DefaultClaimMappings() ClaimMappings {
	return ClaimMappings{
		Email:       "email",
		DisplayName: "name",
		ExternalID:  "sub",
		Groups:      "groups",
	}
}

// merged returns a copy of m with empty string fields filled from
// DefaultClaimMappings. The GroupToRole map is shallow-cloned.
func (m ClaimMappings) merged() ClaimMappings {
	def := DefaultClaimMappings()
	out := m
	if out.Email == "" {
		out.Email = def.Email
	}
	if out.DisplayName == "" {
		out.DisplayName = def.DisplayName
	}
	if out.ExternalID == "" {
		out.ExternalID = def.ExternalID
	}
	if out.Groups == "" {
		out.Groups = def.Groups
	}
	if out.GroupToRole != nil {
		clone := make(map[string]string, len(out.GroupToRole))
		for k, v := range out.GroupToRole {
			clone[k] = v
		}
		out.GroupToRole = clone
	}
	return out
}

// OidcConnectionConfig is the OIDC-client-flavored payload that goes
// into SsoConnection.Config. The struct is the public/in-memory shape
// — what gets persisted is a transparently transformed copy with
// ClientSecret swapped for ClientSecretEnc (base64 AES-256-GCM
// ciphertext).
type OidcConnectionConfig struct {
	// DiscoveryURL is the OIDC discovery endpoint (RFC 8414 / OpenID
	// Connect Discovery 1.0). Typically ends in
	// "/.well-known/openid-configuration". omitempty so it is optional in
	// the huma request schema: create validates it via validate()
	// (business 400) and PATCH merges only when present, so a required
	// schema would wrongly 422 partial updates and create's own checks.
	DiscoveryURL string `json:"discovery_url,omitempty"`
	// ClientID is the IdP-assigned RP identifier. Sent on every
	// authorization redirect and token exchange. omitempty for the same
	// partial-update / business-400 reason as DiscoveryURL.
	ClientID string `json:"client_id,omitempty"`
	// ClientSecret is the IdP-assigned RP secret. Stored encrypted
	// at rest; the plaintext value is only held in memory during the
	// codec round-trip. omitempty for the same partial-update /
	// business-400 reason as DiscoveryURL.
	ClientSecret string `json:"client_secret,omitempty"`
	// Scopes is the space-separated scope list sent on
	// /authorize?scope=. Defaults to "openid email profile" when
	// empty.
	Scopes []string `json:"scopes,omitempty"`
	// ClaimMappings configures how claims from the IdP id_token are
	// projected onto the JIT user record. Zero-value fields fall
	// back to DefaultClaimMappings. omitempty marks it optional in the
	// huma-derived request schema so callers may omit the whole block
	// and let the handler apply DefaultClaimMappings (the create/update
	// handlers default an absent mapping) rather than huma 422ing on a
	// missing required property.
	ClaimMappings ClaimMappings `json:"claim_mappings,omitempty"`
}

// DefaultOidcScopes is the scope list applied when OidcConnectionConfig.Scopes
// is empty. Mirrors the OIDC Core 1.0 baseline a relying party needs to
// recover identity + email + profile.
var DefaultOidcScopes = []string{"openid", "email", "profile"}

// EffectiveScopes returns the configured scope list, defaulting to
// DefaultOidcScopes when the slice is empty.
func (c *OidcConnectionConfig) EffectiveScopes() []string {
	if len(c.Scopes) == 0 {
		out := make([]string, len(DefaultOidcScopes))
		copy(out, DefaultOidcScopes)
		return out
	}
	out := make([]string, len(c.Scopes))
	copy(out, c.Scopes)
	return out
}

// IssuerKeyFromDiscoveryURL extracts a canonical "issuer key" from a
// discovery URL — the base URL (everything before
// /.well-known/openid-configuration). Used to form
// ExternalIdentity.Provider ("oidc:<issuer-url>") so two connections
// pointing at the same IdP share an identity namespace.
func IssuerKeyFromDiscoveryURL(discoveryURL string) string {
	s := strings.TrimSpace(discoveryURL)
	const wk = "/.well-known/openid-configuration"
	if idx := strings.Index(s, wk); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimRight(s, "/")
}

// validate runs structural checks on the config. It does NOT round-
// trip against the IdP — that's the /test endpoint's job. Validation
// surfaces obvious bad input before the row hits the repo.
func (c *OidcConnectionConfig) validate() error {
	if strings.TrimSpace(c.DiscoveryURL) == "" {
		return errors.New("ssooidc: discovery_url is required")
	}
	if !strings.HasPrefix(c.DiscoveryURL, "https://") && !strings.HasPrefix(c.DiscoveryURL, "http://") {
		return errors.New("ssooidc: discovery_url must be an absolute URL")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("ssooidc: client_id is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("ssooidc: client_secret is required")
	}
	// group_to_role is applied verbatim to the membership on every JIT login —
	// including for users who are ALREADY members, so it promotes as well as
	// provisions. Mapping an IdP group to "owner" would hand the org admin who
	// writes this config the owner slot, via anyone in a group they control at
	// the IdP. validate() is the single chokepoint every config write passes
	// through: create, PATCH, guided-federation seeding, global connections.
	if err := auth.ValidateAssignableRoles(c.ClaimMappings.GroupToRole); err != nil {
		return errors.New("ssooidc: group_to_role cannot map to owner; use transfer-ownership")
	}
	return nil
}

// --- codec -------------------------------------------------------------

// persistedConfig is the JSON shape actually written to
// SsoConnection.Config. ClientSecretEnc carries the base64-encoded
// AES-256-GCM ciphertext of the secret. The plaintext field is never
// persisted — the marshal step zeroes it out and the unmarshal step
// decrypts on demand.
type persistedConfig struct {
	DiscoveryURL    string        `json:"discovery_url"`
	ClientID        string        `json:"client_id"`
	ClientSecretEnc string        `json:"client_secret_enc"`
	Scopes          []string      `json:"scopes,omitempty"`
	ClaimMappings   ClaimMappings `json:"claim_mappings"`
}

// marshalOidcConfig produces the SsoConnection.Config payload from an
// in-memory OidcConnectionConfig, encrypting ClientSecret with key.
//
// The returned bytes are pure JSON — every backend (memrepo, pgxrepo)
// stores them verbatim.
func marshalOidcConfig(key [32]byte, c OidcConnectionConfig) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	enc, err := encryptString(key, c.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("ssooidc: encrypt client_secret: %w", err)
	}
	p := persistedConfig{
		DiscoveryURL:    c.DiscoveryURL,
		ClientID:        c.ClientID,
		ClientSecretEnc: enc,
		Scopes:          append([]string(nil), c.Scopes...),
		ClaimMappings:   c.ClaimMappings.merged(),
	}
	return json.Marshal(&p)
}

// unmarshalOidcConfig is the read-side of marshalOidcConfig. The
// returned OidcConnectionConfig carries the *plaintext* ClientSecret
// and is safe to use against the IdP. Callers MUST NOT echo the
// returned struct back over the wire (the /get handler scrubs it
// explicitly).
func unmarshalOidcConfig(key [32]byte, raw []byte) (OidcConnectionConfig, error) {
	var p persistedConfig
	if err := json.Unmarshal(raw, &p); err != nil {
		return OidcConnectionConfig{}, fmt.Errorf("ssooidc: decode config: %w", err)
	}
	secret := ""
	if p.ClientSecretEnc != "" {
		s, err := decryptString(key, p.ClientSecretEnc)
		if err != nil {
			return OidcConnectionConfig{}, fmt.Errorf("ssooidc: decrypt client_secret: %w", err)
		}
		secret = s
	}
	return OidcConnectionConfig{
		DiscoveryURL:  p.DiscoveryURL,
		ClientID:      p.ClientID,
		ClientSecret:  secret,
		Scopes:        append([]string(nil), p.Scopes...),
		ClaimMappings: p.ClaimMappings.merged(),
	}, nil
}

// peekOidcConfigPublic decodes only the non-secret fields of a stored
// config — used by the list/get handlers so an admin can see the
// connection's IdP URL + claim mappings without round-tripping the
// secret through memory.
//
// The returned struct's ClientSecret is the empty string. Callers MUST
// NOT pass the result to any IdP-bound code path; use unmarshalOidcConfig
// for that.
func peekOidcConfigPublic(raw []byte) (OidcConnectionConfig, error) {
	var p persistedConfig
	if err := json.Unmarshal(raw, &p); err != nil {
		return OidcConnectionConfig{}, fmt.Errorf("ssooidc: decode config: %w", err)
	}
	return OidcConnectionConfig{
		DiscoveryURL:  p.DiscoveryURL,
		ClientID:      p.ClientID,
		ClientSecret:  "", // intentionally scrubbed
		Scopes:        append([]string(nil), p.Scopes...),
		ClaimMappings: p.ClaimMappings.merged(),
	}, nil
}
