// config.go — SamlConnectionConfig codec.
//
// The SsoConnection row carries the IdP-specific connection config as
// opaque []byte. This file defines the SAML-SP-flavored payload and
// the marshal/unmarshal helpers that bridge the wire shape (JSON with
// an *encrypted* SP private key) to the in-memory shape callers use.
package ssosaml

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yackey-labs/yauth/auth"
)

// SAML attribute names matching the common Microsoft / WS-* claim type
// URIs. We default to these because Azure AD / ADFS / Okta-default-
// claim-mapping use them. Admins can override per-connection.
const (
	// DefaultEmailAttr is the WS-* claim URI for email address.
	DefaultEmailAttr = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	// DefaultDisplayNameAttr is the WS-* claim URI for display name.
	DefaultDisplayNameAttr = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
	// DefaultExternalIDFromNameID is the sentinel value for "use the
	// SAML NameID as the external_id" — the most stable choice when
	// the IdP issues a persistent NameID.
	DefaultExternalIDFromNameID = "$NameID"
	// DefaultGroupsAttr is the WS-* claim URI for group membership.
	DefaultGroupsAttr = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups"
)

// AttributeMappings selects which assertion attributes yauth pulls from
// the IdP's SAML response to populate the JIT user record and apply
// the group→role mapping.
type AttributeMappings struct {
	// Email is the assertion attribute Name used as the JIT user's
	// email address. Empty → DefaultEmailAttr.
	Email string `json:"email,omitempty"`
	// DisplayName is the assertion attribute Name copied into the
	// JIT user's display_name. Empty → DefaultDisplayNameAttr; the
	// JSON field can be omitted to disable display-name population.
	DisplayName *string `json:"display_name,omitempty"`
	// ExternalID is the assertion attribute Name used as the
	// ExternalIdentity row's external_id. The sentinel "$NameID"
	// (DefaultExternalIDFromNameID) means "use the assertion's
	// Subject/NameID value" — the safest choice for IdPs that issue
	// stable NameIDs (AD's objectGUID, Okta's email NameID, etc).
	// Empty → DefaultExternalIDFromNameID.
	ExternalID string `json:"external_id,omitempty"`
	// Groups is the assertion attribute Name that lists the user's
	// group memberships at the IdP. nil/empty disables group→role
	// mapping.
	Groups *string `json:"groups,omitempty"`
	// GroupToRole maps a raw group name from the IdP to a yauth-side
	// org role. Looked up case-sensitively. The first matching entry
	// wins. Empty leaves the role at the connection's
	// DefaultRoleOnJit.
	GroupToRole map[string]string `json:"group_to_role,omitempty"`

	// _ carries the additionalProperties:false marker so huma rejects
	// unknown keys in the nested `attribute_mappings` block with a 422.
	// json:"-" keeps it out of every (un)marshal path.
	_ struct{} `json:"-" additionalProperties:"false"`
}

// DefaultAttributeMappings returns the WS-* defaults.
func DefaultAttributeMappings() AttributeMappings {
	dn := DefaultDisplayNameAttr
	gp := DefaultGroupsAttr
	return AttributeMappings{
		Email:       DefaultEmailAttr,
		DisplayName: &dn,
		ExternalID:  DefaultExternalIDFromNameID,
		Groups:      &gp,
	}
}

// merged returns a copy of m with empty fields filled from defaults.
// The GroupToRole map is shallow-cloned.
func (m AttributeMappings) merged() AttributeMappings {
	def := DefaultAttributeMappings()
	out := m
	if out.Email == "" {
		out.Email = def.Email
	}
	if out.ExternalID == "" {
		out.ExternalID = def.ExternalID
	}
	if out.DisplayName == nil {
		out.DisplayName = def.DisplayName
	}
	if out.Groups == nil {
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

// SamlConnectionConfig is the SAML-SP-flavored payload that goes into
// SsoConnection.Config. The struct is the public/in-memory shape — what
// gets persisted is a transparently transformed copy with SpPrivateKey
// swapped for SpPrivateKeyEnc (base64 AES-256-GCM ciphertext).
//
// It is reused as the nested request-body type for the huma-native
// connection CRUD (create/patch), so every field carries `,omitempty`:
// huma treats a field WITHOUT omitempty as required, which would force
// callers to send every field on a partial PATCH and break the secure-
// defaults convention on create. omitempty only affects huma's required
// derivation and JSON *marshaling* — it has no effect on unmarshaling, and
// this struct is never marshaled to a response (responses go through
// samlPublicConfig; persistence goes through persistedConfig). Business
// validation (validate(), the merge logic) stays in the handlers, so the
// real 400s are unchanged. additionalProperties:false rejects unknown keys
// in the nested block (→ huma 422).
type SamlConnectionConfig struct {
	// IdpEntityID is the IdP's SAML entity ID
	// (e.g. "urn:idp:acme:saml" or
	// "https://sts.windows.net/<tenant-id>/").
	IdpEntityID string `json:"idp_entity_id,omitempty"`
	// IdpSsoURL is the IdP's SingleSignOnService HTTP-Redirect or
	// HTTP-POST endpoint. yauth issues the AuthnRequest here.
	IdpSsoURL string `json:"idp_sso_url,omitempty"`
	// IdpSloURL is the IdP's SingleLogoutService endpoint, optional.
	// When empty, SP-initiated SLO is disabled for this connection.
	IdpSloURL string `json:"idp_slo_url,omitempty"`
	// IdpX509Cert is the IdP's signing certificate in PEM form. Used
	// to verify XML signatures on assertions / responses. May contain
	// multiple PEM blocks for key rollover (every cert is tried).
	IdpX509Cert string `json:"idp_x509_cert,omitempty"`

	// SpEntityID is yauth's own SAML entity ID for this connection.
	// The default is the BaseURL + "/saml/metadata/<connection_id>"
	// when empty — overridable per connection (some IdPs require a
	// specific form). Sent in metadata.xml and AuthnRequest Issuer.
	SpEntityID string `json:"sp_entity_id,omitempty"`
	// SpAcsURL is the Assertion Consumer Service URL the IdP POSTs
	// the SAMLResponse to. Defaults to BaseURL + "/api/auth/sso/saml/acs"
	// when empty. MUST match the SubjectConfirmationData/@Recipient
	// on inbound assertions.
	SpAcsURL string `json:"sp_acs_url,omitempty"`

	// IdpInitiatedSsoAllowed permits unsolicited SAMLResponses
	// (POSTed to ACS without an outstanding AuthnRequest from yauth).
	// OFF by default — the unsolicited path skips the request-id
	// binding and is the historical SAML attack surface. Admins must
	// opt in per connection.
	IdpInitiatedSsoAllowed bool `json:"idp_initiated_sso_allowed,omitempty"`

	// AssertionSignedRequired demands that the inbound assertion
	// itself carry a valid signature (vs. relying on the wrapping
	// Response signature only). Default true. Disabling violates
	// SAML profile best practice and is logged loudly.
	//
	// omitempty here is for huma's optional-field derivation only; the
	// create handler still applies the secure default (true) when the
	// client omits BOTH signed-required flags, and the merge logic on
	// PATCH preserves the current value when the block is partial.
	AssertionSignedRequired bool `json:"assertion_signed_required,omitempty"`
	// ResponseSignedRequired demands that the outer SAMLResponse
	// carry a valid signature. Default true. Disabling violates
	// SAML profile best practice.
	ResponseSignedRequired bool `json:"response_signed_required,omitempty"`

	// WantEncryptedAssertions tells the IdP (via metadata.xml) that
	// yauth wants the assertion encrypted. Default false; rare. When
	// true, SpPrivateKey is required.
	WantEncryptedAssertions bool `json:"want_encrypted_assertions,omitempty"`

	// SpPrivateKey is the SP's RSA private key in PEM form, used to:
	//
	//   1. Sign outbound AuthnRequest (when SignAuthnRequests is true)
	//   2. Decrypt inbound EncryptedAssertion (when WantEncryptedAssertions)
	//
	// Stored encrypted at rest; the plaintext value is only held in
	// memory during the codec round-trip. Optional unless one of the
	// above features is enabled.
	SpPrivateKey *string `json:"sp_private_key,omitempty"`
	// SpCertificate is the X.509 cert matching SpPrivateKey, in PEM
	// form. Optional unless SignAuthnRequests is true.
	SpCertificate *string `json:"sp_certificate,omitempty"`
	// SignAuthnRequests tells the SP to sign every outbound
	// AuthnRequest. Off by default; most IdPs accept unsigned
	// AuthnRequests over HTTP-Redirect (the binding embeds the
	// SAMLRequest in URL query parameters).
	SignAuthnRequests bool `json:"sign_authn_requests,omitempty"`

	// AttributeMappings configures how SAML attribute statements are
	// projected onto the JIT user record. Zero-value fields fall
	// back to DefaultAttributeMappings.
	AttributeMappings AttributeMappings `json:"attribute_mappings,omitempty"`

	// _ carries the additionalProperties:false marker so huma rejects
	// unknown keys in the nested `saml` block with a 422. json:"-" keeps
	// it out of every (un)marshal path — storage (persistedConfig),
	// responses (samlPublicConfig), and request decoding all ignore it.
	_ struct{} `json:"-" additionalProperties:"false"`
}

// EntityIDForConnection returns the connection's effective entity ID,
// falling back to a stable derivation from baseURL+connectionID if
// SpEntityID is empty.
func (c *SamlConnectionConfig) EntityIDForConnection(baseURL, connectionID string) string {
	if s := strings.TrimSpace(c.SpEntityID); s != "" {
		return s
	}
	base := strings.TrimRight(baseURL, "/")
	return base + "/api/auth/sso/saml/connections/" + connectionID + "/metadata.xml"
}

// ACSURLForConnection returns the connection's effective ACS URL,
// falling back to baseURL + standard path.
func (c *SamlConnectionConfig) ACSURLForConnection(baseURL string) string {
	if s := strings.TrimSpace(c.SpAcsURL); s != "" {
		return s
	}
	base := strings.TrimRight(baseURL, "/")
	return base + "/api/auth/sso/saml/acs"
}

// validate runs structural checks on the config. It does NOT round-
// trip against the IdP — that's the metadata endpoint's job. Validation
// surfaces obvious bad input before the row hits the repo.
func (c *SamlConnectionConfig) validate() error {
	if strings.TrimSpace(c.IdpEntityID) == "" {
		return errors.New("ssosaml: idp_entity_id is required")
	}
	if strings.TrimSpace(c.IdpSsoURL) == "" {
		return errors.New("ssosaml: idp_sso_url is required")
	}
	if !strings.HasPrefix(c.IdpSsoURL, "https://") && !strings.HasPrefix(c.IdpSsoURL, "http://") {
		return errors.New("ssosaml: idp_sso_url must be an absolute URL")
	}
	if strings.TrimSpace(c.IdpX509Cert) == "" {
		return errors.New("ssosaml: idp_x509_cert is required")
	}
	if !strings.Contains(c.IdpX509Cert, "BEGIN CERTIFICATE") {
		return errors.New("ssosaml: idp_x509_cert must be PEM-encoded")
	}
	if c.SignAuthnRequests {
		if c.SpPrivateKey == nil || strings.TrimSpace(*c.SpPrivateKey) == "" {
			return errors.New("ssosaml: sp_private_key required when sign_authn_requests is true")
		}
		if c.SpCertificate == nil || strings.TrimSpace(*c.SpCertificate) == "" {
			return errors.New("ssosaml: sp_certificate required when sign_authn_requests is true")
		}
	}
	if c.WantEncryptedAssertions {
		if c.SpPrivateKey == nil || strings.TrimSpace(*c.SpPrivateKey) == "" {
			return errors.New("ssosaml: sp_private_key required when want_encrypted_assertions is true")
		}
	}
	// group_to_role is applied verbatim to the membership on every JIT login —
	// including for users who are ALREADY members, so it promotes as well as
	// provisions. Mapping an IdP group to "owner" would hand the org admin who
	// writes this config the owner slot, via anyone in a group they control at
	// the IdP. validate() is the single chokepoint every config write passes
	// through. Mirrors the ssooidc check of the same name.
	if err := auth.ValidateAssignableRoles(c.AttributeMappings.GroupToRole); err != nil {
		return errors.New("ssosaml: group_to_role cannot map to owner; use transfer-ownership")
	}
	return nil
}

// IssuerKeyFromEntityID returns the stable key used to scope an
// ExternalIdentity for this IdP. Mirrors ssooidc.IssuerKeyFromDiscoveryURL.
// Two connections pointing at the same IdP entity ID share an identity
// namespace so a deleted-and-recreated connection does not orphan
// users.
func IssuerKeyFromEntityID(entityID string) string {
	return strings.TrimSpace(entityID)
}

// --- codec -------------------------------------------------------------

// persistedConfig is the JSON shape actually written to
// SsoConnection.Config. SpPrivateKeyEnc carries the base64-encoded
// AES-256-GCM ciphertext of the SP private key.
type persistedConfig struct {
	IdpEntityID             string            `json:"idp_entity_id"`
	IdpSsoURL               string            `json:"idp_sso_url"`
	IdpSloURL               string            `json:"idp_slo_url,omitempty"`
	IdpX509Cert             string            `json:"idp_x509_cert"`
	SpEntityID              string            `json:"sp_entity_id,omitempty"`
	SpAcsURL                string            `json:"sp_acs_url,omitempty"`
	IdpInitiatedSsoAllowed  bool              `json:"idp_initiated_sso_allowed,omitempty"`
	AssertionSignedRequired bool              `json:"assertion_signed_required"`
	ResponseSignedRequired  bool              `json:"response_signed_required"`
	WantEncryptedAssertions bool              `json:"want_encrypted_assertions,omitempty"`
	SpPrivateKeyEnc         string            `json:"sp_private_key_enc,omitempty"`
	SpCertificate           string            `json:"sp_certificate,omitempty"`
	SignAuthnRequests       bool              `json:"sign_authn_requests,omitempty"`
	AttributeMappings       AttributeMappings `json:"attribute_mappings"`
}

// marshalSamlConfig produces the SsoConnection.Config payload from an
// in-memory SamlConnectionConfig, encrypting SpPrivateKey with key.
func marshalSamlConfig(key [32]byte, c SamlConnectionConfig) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	p := persistedConfig{
		IdpEntityID:             c.IdpEntityID,
		IdpSsoURL:               c.IdpSsoURL,
		IdpSloURL:               c.IdpSloURL,
		IdpX509Cert:             c.IdpX509Cert,
		SpEntityID:              c.SpEntityID,
		SpAcsURL:                c.SpAcsURL,
		IdpInitiatedSsoAllowed:  c.IdpInitiatedSsoAllowed,
		AssertionSignedRequired: c.AssertionSignedRequired,
		ResponseSignedRequired:  c.ResponseSignedRequired,
		WantEncryptedAssertions: c.WantEncryptedAssertions,
		SignAuthnRequests:       c.SignAuthnRequests,
		AttributeMappings:       c.AttributeMappings.merged(),
	}
	if c.SpCertificate != nil {
		p.SpCertificate = *c.SpCertificate
	}
	if c.SpPrivateKey != nil && strings.TrimSpace(*c.SpPrivateKey) != "" {
		enc, err := encryptString(key, *c.SpPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("ssosaml: encrypt sp_private_key: %w", err)
		}
		p.SpPrivateKeyEnc = enc
	}
	return json.Marshal(&p)
}

// unmarshalSamlConfig is the read-side of marshalSamlConfig. The returned
// SamlConnectionConfig carries the *plaintext* SpPrivateKey and is safe
// to use to sign AuthnRequests. Callers MUST NOT echo the returned
// struct back over the wire (the /get handler scrubs it explicitly).
func unmarshalSamlConfig(key [32]byte, raw []byte) (SamlConnectionConfig, error) {
	var p persistedConfig
	if err := json.Unmarshal(raw, &p); err != nil {
		return SamlConnectionConfig{}, fmt.Errorf("ssosaml: decode config: %w", err)
	}
	out := SamlConnectionConfig{
		IdpEntityID:             p.IdpEntityID,
		IdpSsoURL:               p.IdpSsoURL,
		IdpSloURL:               p.IdpSloURL,
		IdpX509Cert:             p.IdpX509Cert,
		SpEntityID:              p.SpEntityID,
		SpAcsURL:                p.SpAcsURL,
		IdpInitiatedSsoAllowed:  p.IdpInitiatedSsoAllowed,
		AssertionSignedRequired: p.AssertionSignedRequired,
		ResponseSignedRequired:  p.ResponseSignedRequired,
		WantEncryptedAssertions: p.WantEncryptedAssertions,
		SignAuthnRequests:       p.SignAuthnRequests,
		AttributeMappings:       p.AttributeMappings.merged(),
	}
	if p.SpCertificate != "" {
		s := p.SpCertificate
		out.SpCertificate = &s
	}
	if p.SpPrivateKeyEnc != "" {
		pt, err := decryptString(key, p.SpPrivateKeyEnc)
		if err != nil {
			return SamlConnectionConfig{}, fmt.Errorf("ssosaml: decrypt sp_private_key: %w", err)
		}
		out.SpPrivateKey = &pt
	}
	return out, nil
}

// peekSamlConfigPublic decodes only the non-secret fields of a stored
// config — used by the list/get handlers so an admin can see the
// connection's IdP URL + attribute mappings without round-tripping the
// SP private key through memory.
//
// The returned struct's SpPrivateKey is nil. Callers MUST NOT pass the
// result to any IdP-bound code path; use unmarshalSamlConfig for that.
func peekSamlConfigPublic(raw []byte) (SamlConnectionConfig, error) {
	var p persistedConfig
	if err := json.Unmarshal(raw, &p); err != nil {
		return SamlConnectionConfig{}, fmt.Errorf("ssosaml: decode config: %w", err)
	}
	out := SamlConnectionConfig{
		IdpEntityID:             p.IdpEntityID,
		IdpSsoURL:               p.IdpSsoURL,
		IdpSloURL:               p.IdpSloURL,
		IdpX509Cert:             p.IdpX509Cert,
		SpEntityID:              p.SpEntityID,
		SpAcsURL:                p.SpAcsURL,
		IdpInitiatedSsoAllowed:  p.IdpInitiatedSsoAllowed,
		AssertionSignedRequired: p.AssertionSignedRequired,
		ResponseSignedRequired:  p.ResponseSignedRequired,
		WantEncryptedAssertions: p.WantEncryptedAssertions,
		SignAuthnRequests:       p.SignAuthnRequests,
		AttributeMappings:       p.AttributeMappings.merged(),
	}
	if p.SpCertificate != "" {
		s := p.SpCertificate
		out.SpCertificate = &s
	}
	return out, nil
}

// hasEncryptedSpKey reports whether the stored payload includes a
// non-empty sp_private_key_enc. Used to drive UI "sp_private_key_set"
// flag without decrypting.
func hasEncryptedSpKey(raw []byte) bool {
	var p persistedConfig
	if err := json.Unmarshal(raw, &p); err != nil {
		return false
	}
	return strings.TrimSpace(p.SpPrivateKeyEnc) != ""
}
