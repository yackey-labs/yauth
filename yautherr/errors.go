// Package yautherr exposes yauth-go's sentinel errors as a leaf package so
// any sub-package (middleware, plugins, repo backends) can compare against
// them without forming an import cycle through the root yauth package.
//
// The root yauth package re-exports each sentinel under its public name
// (e.g. yauth.ErrNotFound) so user-facing code never sees the yautherr
// import path.
package yautherr

import "errors"

var (
	ErrNotFound           = errors.New("yauth: not found")
	ErrUserExists         = errors.New("yauth: user already exists")
	ErrInvalidCredentials = errors.New("yauth: invalid credentials")
	ErrSessionExpired     = errors.New("yauth: session expired")
	ErrTokenExpired       = errors.New("yauth: token expired")
	ErrTokenUsed          = errors.New("yauth: token already used")
	ErrInvalidToken       = errors.New("yauth: invalid token")
	ErrUnauthorized       = errors.New("yauth: unauthorized")
	ErrForbidden          = errors.New("yauth: forbidden")
	ErrUserBanned         = errors.New("yauth: user banned")
	ErrEmailNotVerified   = errors.New("yauth: email not verified")
	ErrConflict           = errors.New("yauth: conflict")
	ErrInternal           = errors.New("yauth: internal error")

	// OAuth2 / bearer.
	ErrInvalidGrant         = errors.New("yauth: invalid grant")
	ErrInvalidClient        = errors.New("yauth: invalid client")
	ErrClientNotFound       = errors.New("yauth: client not found")
	ErrClientBanned         = errors.New("yauth: client banned")
	ErrInvalidRequest       = errors.New("yauth: invalid request")
	ErrInvalidScope         = errors.New("yauth: invalid scope")
	ErrConsentRequired      = errors.New("yauth: consent required")
	ErrUnsupportedGrantType = errors.New("yauth: unsupported grant type")

	// Account lockout / rate limiting.
	ErrAccountLocked = errors.New("yauth: account locked")
	ErrRateLimited   = errors.New("yauth: rate limited")

	// MFA.
	ErrMFARequired = errors.New("yauth: mfa required")
	ErrInvalidMFA  = errors.New("yauth: invalid mfa code")
)
