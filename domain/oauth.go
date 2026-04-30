package domain

import "time"

// OAuthAccount links a user to an external OAuth provider identity.
type OAuthAccount struct {
	ID              string
	UserID          string
	Provider        string
	ProviderUserID  string
	AccessTokenEnc  *string
	RefreshTokenEnc *string
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	UpdatedAt       time.Time
}

// NewOAuthAccount is the input for creating an OAuth account link.
type NewOAuthAccount struct {
	ID              string
	UserID          string
	Provider        string
	ProviderUserID  string
	AccessTokenEnc  *string
	RefreshTokenEnc *string
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	UpdatedAt       time.Time
}

// OAuthState is a CSRF-protecting state token for the OAuth authorization code
// flow.
type OAuthState struct {
	State       string
	Provider    string
	RedirectURL *string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// NewOAuthState is the input for creating an OAuth state token.
type NewOAuthState struct {
	State       string
	Provider    string
	RedirectURL *string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}
