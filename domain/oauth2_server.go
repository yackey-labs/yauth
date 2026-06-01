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
}

// NewOAuth2Client is the input for registering an OAuth2 client.
type NewOAuth2Client struct {
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
	EnforceGroupAssignment  bool
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
