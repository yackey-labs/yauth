package yauth

import "github.com/yackey-labs/yauth/yautherr"

// Sentinel errors returned across the yauth-go API. These are aliases for
// the leaf package github.com/yackey-labs/yauth/yautherr so that
// sub-packages (middleware, plugins, repo backends) can compare against
// the same errors without creating an import cycle through the root
// package.
var (
	ErrNotFound           = yautherr.ErrNotFound
	ErrUserExists         = yautherr.ErrUserExists
	ErrInvalidCredentials = yautherr.ErrInvalidCredentials
	ErrSessionExpired     = yautherr.ErrSessionExpired
	ErrTokenExpired       = yautherr.ErrTokenExpired
	ErrTokenUsed          = yautherr.ErrTokenUsed
	ErrInvalidToken       = yautherr.ErrInvalidToken
	ErrUnauthorized       = yautherr.ErrUnauthorized
	ErrForbidden          = yautherr.ErrForbidden
	ErrUserBanned         = yautherr.ErrUserBanned
	ErrEmailNotVerified   = yautherr.ErrEmailNotVerified
	ErrConflict           = yautherr.ErrConflict
	ErrInternal           = yautherr.ErrInternal

	// OAuth2 / bearer.
	ErrInvalidGrant         = yautherr.ErrInvalidGrant
	ErrInvalidClient        = yautherr.ErrInvalidClient
	ErrClientNotFound       = yautherr.ErrClientNotFound
	ErrClientBanned         = yautherr.ErrClientBanned
	ErrInvalidRequest       = yautherr.ErrInvalidRequest
	ErrInvalidScope         = yautherr.ErrInvalidScope
	ErrConsentRequired      = yautherr.ErrConsentRequired
	ErrUnsupportedGrantType = yautherr.ErrUnsupportedGrantType

	// Account lockout / rate limiting.
	ErrAccountLocked = yautherr.ErrAccountLocked
	ErrRateLimited   = yautherr.ErrRateLimited

	// MFA.
	ErrMFARequired = yautherr.ErrMFARequired
	ErrInvalidMFA  = yautherr.ErrInvalidMFA
)
