package domain

import "time"

// ConnectionKind is the protocol carried by an SsoConnection row.
// Persisted as VARCHAR; new variants can land without DDL drift.
//
// Port of yauth Rust #93. SAML SP (sibling Rust issue) will reuse this
// enum without schema churn — only the Config payload differs.
type ConnectionKind string

const (
	// ConnectionKindOIDCClient is yauth-as-Relying-Party against an
	// external OIDC IdP (Okta, Entra ID, Auth0, Keycloak, Google
	// Workspace, …). The Config column carries OidcConnectionConfig.
	ConnectionKindOIDCClient ConnectionKind = "oidc_client"
	// ConnectionKindSamlSP is reserved for the sibling SAML SP issue.
	// yauth-go does not act on it yet — the value is accepted by the
	// repos so a future plugin can land without a domain-type bump.
	ConnectionKindSamlSP ConnectionKind = "saml_sp"
)

// IsValid reports whether k is one of the known variants.
func (k ConnectionKind) IsValid() bool {
	switch k {
	case ConnectionKindOIDCClient, ConnectionKindSamlSP:
		return true
	default:
		return false
	}
}

// ParseConnectionKind accepts the on-disk string form. Returns
// ("", false) on an unknown value.
func ParseConnectionKind(s string) (ConnectionKind, bool) {
	v := ConnectionKind(s)
	if !v.IsValid() {
		return "", false
	}
	return v, true
}

// ConnectionStatus is the lifecycle bit on an SsoConnection. Persisted
// as VARCHAR.
type ConnectionStatus string

const (
	// ConnectionStatusDraft is the initial state right after create —
	// the admin can still PATCH discovery/client values without the
	// /sso/login route honoring the row. The /test endpoint is the
	// pre-flight that flips a connection from draft to active.
	ConnectionStatusDraft ConnectionStatus = "draft"
	// ConnectionStatusActive is the steady state — the connection is
	// resolved by HRD and /sso/login.
	ConnectionStatusActive ConnectionStatus = "active"
	// ConnectionStatusDisabled is an admin-applied terminal state that
	// hides the connection from HRD without deleting the audit trail.
	ConnectionStatusDisabled ConnectionStatus = "disabled"
)

// IsValid reports whether s is one of the recognized values.
func (s ConnectionStatus) IsValid() bool {
	switch s {
	case ConnectionStatusDraft, ConnectionStatusActive, ConnectionStatusDisabled:
		return true
	default:
		return false
	}
}

// ParseConnectionStatus accepts the on-disk string form. Returns
// ("", false) on an unknown value.
func ParseConnectionStatus(s string) (ConnectionStatus, bool) {
	v := ConnectionStatus(s)
	if !v.IsValid() {
		return "", false
	}
	return v, true
}

// SsoConnection is the per-organization SSO IdP binding. A single row
// represents one IdP (a tenant in Okta, an Entra ID app registration,
// …) and is the unit a user picks when they "sign in with SSO".
//
// Port of yauth Rust #93. Config is opaque JSON keyed by Kind:
//
//   - Kind == ConnectionKindOIDCClient → OidcConnectionConfig
//   - Kind == ConnectionKindSamlSP     → reserved
//
// The Config column is stored as raw bytes (TEXT in SQL backends,
// []byte in-memory) so adding a new Kind never costs a migration.
// Callers MUST decode through ParseOidcConnectionConfig — the bytes
// hold a ClientSecret encrypted-at-rest token, not the plaintext.
type SsoConnection struct {
	ID                     string
	OrganizationID         string
	Kind                   ConnectionKind
	Name                   string
	Status                 ConnectionStatus
	Config                 []byte // JSON-encoded OidcConnectionConfig (ClientSecret encrypted)
	JitProvisioningEnabled bool
	DefaultRoleOnJit       string
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// NewSsoConnection is the create payload.
type NewSsoConnection struct {
	ID                     string
	OrganizationID         string
	Kind                   ConnectionKind
	Name                   string
	Status                 ConnectionStatus
	Config                 []byte
	JitProvisioningEnabled bool
	DefaultRoleOnJit       string
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// UpdateSsoConnection is the partial-update payload. nil pointers leave
// the column unchanged; non-nil overwrite it.
type UpdateSsoConnection struct {
	Name                   *string
	Status                 *ConnectionStatus
	Config                 *[]byte
	JitProvisioningEnabled *bool
	DefaultRoleOnJit       *string
	UpdatedAt              *time.Time
}

// ExternalIdentity is the join between a yauth User and an external IdP
// identity. (Provider, ExternalID) is unique across the table — the
// same yauth user can have multiple ExternalIdentity rows (e.g. one per
// IdP after a merger), but a single (issuer, sub) tuple at the IdP
// never authenticates two different yauth accounts.
//
// Port of yauth Rust #93. Provider follows the format
// "oidc:<issuer-url>" so the same key shape works for SAML in the
// future ("saml:<entity-id>") without a discriminator column.
type ExternalIdentity struct {
	ID          string
	UserID      string
	Provider    string // "oidc:https://login.acme.com/"
	ExternalID  string // IdP `sub` claim
	LinkedAt    time.Time
	LastLoginAt time.Time
}

// NewExternalIdentity is the create payload.
type NewExternalIdentity struct {
	ID          string
	UserID      string
	Provider    string
	ExternalID  string
	LinkedAt    time.Time
	LastLoginAt time.Time
}

// SsoLoginState is the short-lived state row that ties an outbound
// /sso/login redirect to the eventual /sso/callback. It carries the
// nonce + PKCE verifier + connection id so the callback can reconstruct
// the request without holding session state at the IdP.
//
// State is single-use: the callback consumes it (lookup-and-delete) and
// must reject second-use. Rows expire after StateTTL (default 10 min)
// per the OIDC spec recommendation.
type SsoLoginState struct {
	State        string // primary key — the random state parameter
	ConnectionID string // SsoConnection.ID this state belongs to
	Nonce        string // value to be present in id_token.nonce
	PKCEVerifier string // PKCE code_verifier (S256-hashed for challenge)
	RedirectURL  string // post-login redirect (validated allow-list)
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// NewSsoLoginState is the create payload.
type NewSsoLoginState struct {
	State        string
	ConnectionID string
	Nonce        string
	PKCEVerifier string
	RedirectURL  string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}
