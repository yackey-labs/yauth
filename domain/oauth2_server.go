package domain

import (
	"encoding/json"
	"time"
)

// OAuth2Client is a registered OAuth2 server client (RFC 6749 / 7591).
type OAuth2Client struct {
	ID                      string
	ClientID                string
	ClientSecretHash        *string
	RedirectURIs            json.RawMessage
	ClientName              *string
	GrantTypes              json.RawMessage
	Scopes                  json.RawMessage
	IsPublic                bool
	CreatedAt               time.Time
	TokenEndpointAuthMethod *string
	PublicKeyPEM            *string
	JWKSURI                 *string
	BannedAt                *time.Time
	BannedReason            *string
	// EnforceGroupAssignment, when true, restricts this client to users who
	// are members of at least one assigned group (see ClientGroupAssignment).
	// Default false: any authenticated user may complete the flow.
	EnforceGroupAssignment bool
	// PostLogoutRedirectURIs is a JSON array of URIs the client may be
	// redirected to after RP-Initiated Logout (OIDC RP-Initiated Logout 1.0).
	// A post_logout_redirect_uri parameter MUST match one of these exactly.
	PostLogoutRedirectURIs json.RawMessage
	// BackchannelLogoutURI is the client's OIDC Back-Channel Logout endpoint.
	// When set, the OP POSTs a signed logout_token there when the user's
	// session ends. nil → the client does not support back-channel logout.
	BackchannelLogoutURI *string
	// BackchannelLogoutSessionRequired indicates the client requires a `sid`
	// claim in the logout_token (OIDC Back-Channel Logout 1.0 §2.4).
	BackchannelLogoutSessionRequired bool
	// DynamicallyRegistered is true for clients created via RFC 7591 dynamic
	// client registration (DCR). The stale-client sweep only ever touches these
	// — never admin-provisioned clients.
	DynamicallyRegistered bool
	// LastUsedAt is the last successful token-endpoint use of this client
	// (auth_code exchange or refresh grant). nil → never used since creation;
	// the sweep falls back to CreatedAt. Keeps an actively-used client alive.
	LastUsedAt *time.Time
	// InitiateLoginURI is the OIDC third-party / IdP-initiated login URL — the
	// launch target an app-launcher tile points at. MUST be https when set
	// (enforced at the API layer). nil → not configured.
	InitiateLoginURI *string
	// ClientURI is the RFC 7591 client home page URL. nil → not configured.
	ClientURI *string
	// LogoURI is the RFC 7591 logo URL (the launcher tile icon). nil → not
	// configured.
	LogoURI *string
}

// NewOAuth2Client is the input for registering an OAuth2 client.
type NewOAuth2Client struct {
	ID                               string
	ClientID                         string
	ClientSecretHash                 *string
	RedirectURIs                     json.RawMessage
	ClientName                       *string
	GrantTypes                       json.RawMessage
	Scopes                           json.RawMessage
	IsPublic                         bool
	CreatedAt                        time.Time
	TokenEndpointAuthMethod          *string
	PublicKeyPEM                     *string
	JWKSURI                          *string
	EnforceGroupAssignment           bool
	PostLogoutRedirectURIs           json.RawMessage
	BackchannelLogoutURI             *string
	BackchannelLogoutSessionRequired bool
	DynamicallyRegistered            bool
	InitiateLoginURI                 *string
	ClientURI                        *string
	LogoURI                          *string
}

// AuthorizationCode is a single-use OAuth2 authorization code (RFC 6749).
type AuthorizationCode struct {
	ID                  string
	CodeHash            string
	ClientID            string
	UserID              string
	Scopes              json.RawMessage
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Used                bool
	Nonce               *string
	CreatedAt           time.Time
}

// NewAuthorizationCode is the input for creating an authorization code.
type NewAuthorizationCode struct {
	ID                  string
	CodeHash            string
	ClientID            string
	UserID              string
	Scopes              json.RawMessage
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Used                bool
	Nonce               *string
	CreatedAt           time.Time
}

// Consent is a user's recorded grant of scopes to an OAuth2 client.
type Consent struct {
	ID        string
	UserID    string
	ClientID  string
	Scopes    json.RawMessage
	CreatedAt time.Time
}

// NewConsent is the input for creating a consent record.
type NewConsent struct {
	ID        string
	UserID    string
	ClientID  string
	Scopes    json.RawMessage
	CreatedAt time.Time
}

// DeviceCode is an in-flight OAuth2 device-authorization-grant code (RFC 8628).
type DeviceCode struct {
	ID             string
	DeviceCodeHash string
	UserCode       string
	ClientID       string
	Scopes         json.RawMessage
	UserID         *string
	Status         string
	Interval       int
	ExpiresAt      time.Time
	LastPolledAt   *time.Time
	CreatedAt      time.Time
}

// NewDeviceCode is the input for creating a device code.
type NewDeviceCode struct {
	ID             string
	DeviceCodeHash string
	UserCode       string
	ClientID       string
	Scopes         json.RawMessage
	UserID         *string
	Status         string
	Interval       int
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

// OIDCNonce is a one-time-use OIDC nonce, recorded for replay protection.
type OIDCNonce struct {
	ID                  string
	NonceHash           string
	AuthorizationCodeID string
	CreatedAt           time.Time
}

// NewOIDCNonce is the input for storing an OIDC nonce.
type NewOIDCNonce struct {
	ID                  string
	NonceHash           string
	AuthorizationCodeID string
	CreatedAt           time.Time
}
