package domain

import (
	"encoding/json"
	"time"
)

// RefreshToken is a JWT refresh token tracked for rotation and reuse detection.
//
// ClientID is the issuer discriminator. Two independent issuers write this
// table — the bearer plugin (first-party email+password logins) and the
// oauth2server plugin (per-client OAuth2/OIDC grants) — and both used to
// redeem by bare token hash alone. A row therefore has to record who it was
// minted for, or a refresh token issued to a third-party OAuth2 client can be
// replayed at the first-party POST /token/refresh (turning a read-only
// "openid" consent into a full first-party access token), and a first-party
// token can be redeemed at /oauth/token by any registered client.
//
//   - nil → first-party: minted by the bearer plugin, redeemable ONLY at the
//     bearer plugin's /token/refresh.
//   - non-nil → minted by oauth2server for exactly that client_id, redeemable
//     ONLY at /oauth/token by that same client.
//
// Rows written before the discriminator existed carry nil (see migration 009)
// and are therefore treated as first-party, so refresh tokens already held by
// mobile/API clients survive the upgrade.
//
// Scopes is the grant the token was minted under, as a JSON array of strings.
// RFC 6749 §6 forbids a refresh request from widening the scope the resource
// owner granted, and the row is the only place that grant survives once the
// authorization code has been consumed — without it, /oauth/token had nothing
// to compare the requested scope against and honoured whatever was asked for.
// It is nil for first-party (bearer plugin) tokens, which carry no scopes at
// all, and for rows written before migration 010; oauth2server reconstructs
// the grant for those from the consent record or the client registration
// rather than trusting the request. See that migration for the reasoning.
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	FamilyID  string
	ClientID  *string
	Scopes    json.RawMessage
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}

// NewRefreshToken is the input for creating a refresh token. Leave ClientID
// and Scopes nil for first-party (bearer plugin) tokens; oauth2server sets
// them to the client the token is issued to and the scopes granted with it.
// See [RefreshToken].
type NewRefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	FamilyID  string
	ClientID  *string
	Scopes    json.RawMessage
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}
