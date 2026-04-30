package repo

import (
	"context"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
)

// Lookup methods that return (*T, error) MUST return (nil, yauth.ErrNotFound)
// when no row matches; backends must not return (nil, nil).

// UserRepository covers user CRUD and admin listing.
type UserRepository interface {
	CreateUser(ctx context.Context, input domain.NewUser) (domain.User, error)
	GetUserByID(ctx context.Context, id string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateUser(ctx context.Context, id string, changes domain.UpdateUser) (domain.User, error)
	DeleteUser(ctx context.Context, id string) error

	// AnyUserExists reports whether at least one user row exists.
	AnyUserExists(ctx context.Context) (bool, error)

	// ListUsers returns a page of users plus the total matching the (optional)
	// case-insensitive search filter. An empty search string disables the filter.
	ListUsers(ctx context.Context, search string, limit, offset int) ([]*domain.User, int64, error)
}

// SessionRepository covers session create/lookup/revocation and admin listing.
type SessionRepository interface {
	CreateSession(ctx context.Context, input domain.NewSession) error
	GetSessionByID(ctx context.Context, id string) (*domain.Session, error)
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	DeleteSession(ctx context.Context, tokenHash string) (bool, error)
	DeleteSessionByID(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) (int64, error)
	DeleteOtherUserSessions(ctx context.Context, userID, keepTokenHash string) (int64, error)
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)
	ListSessions(ctx context.Context, filters domain.ListSessionsFilters) ([]*domain.Session, int64, error)
}

// PasswordRepository covers password hash storage.
type PasswordRepository interface {
	UpsertPassword(ctx context.Context, input domain.NewPassword) error
	GetPasswordByUserID(ctx context.Context, userID string) (*domain.Password, error)
}

// PasswordHistoryRepository covers per-user password-reuse history. The
// password-policy check queries the most-recent N rows; rotation is
// driven by the password-rotating handler (register/change/reset)
// recording the previous hash before it overwrites yauth_passwords.
type PasswordHistoryRepository interface {
	AppendPasswordHistory(ctx context.Context, input domain.NewPasswordHistory) error
	// GetPasswordHistory returns at most n most-recent rows (newest
	// first) for userID. n<=0 returns an empty slice without querying.
	GetPasswordHistory(ctx context.Context, userID string, n int) ([]*domain.PasswordHistory, error)
	// TrimPasswordHistory deletes rows beyond keep most-recent for
	// userID. keep<=0 deletes every row. Returns the number deleted.
	TrimPasswordHistory(ctx context.Context, userID string, keep int) (int64, error)
}

// EmailVerificationRepository covers email-verification tokens.
type EmailVerificationRepository interface {
	CreateEmailVerification(ctx context.Context, input domain.NewEmailVerification) error
	// ConsumeEmailVerification atomically looks up the token and deletes it.
	// Returns the matched record or nil if not found / expired.
	ConsumeEmailVerification(ctx context.Context, tokenHash string) (*domain.EmailVerification, error)
	DeleteEmailVerification(ctx context.Context, id string) error
	DeleteEmailVerificationsForUser(ctx context.Context, userID string) (int64, error)
}

// PasswordResetRepository covers password-reset tokens.
type PasswordResetRepository interface {
	CreatePasswordReset(ctx context.Context, input domain.NewPasswordReset) error
	// ConsumePasswordReset atomically looks up the token and marks it used.
	// Returns the matched record or nil if not found / expired / already used.
	ConsumePasswordReset(ctx context.Context, tokenHash string) (*domain.PasswordReset, error)
	DeleteUnusedPasswordResetsForUser(ctx context.Context, userID string) (int64, error)
}

// AuditLogRepository is insert-and-list. Audit log rows are never updated or
// individually deleted — administrators query them via ListAuditLog.
type AuditLogRepository interface {
	LogAuditEvent(ctx context.Context, input domain.NewAuditLog) error
	ListAuditLog(ctx context.Context, filters domain.ListAuditFilters) ([]*domain.AuditLog, error)
}

// ChallengeRepository is an ephemeral key/value store used for CSRF, WebAuthn,
// and MFA challenges. GetChallenge is a SELECT (it does not delete on read);
// use ConsumeChallenge for the atomic single-use variant.
type ChallengeRepository interface {
	SetChallenge(ctx context.Context, key, value string, ttl time.Duration) error
	GetChallenge(ctx context.Context, key string) (*domain.Challenge, error)
	ConsumeChallenge(ctx context.Context, key string) (*domain.Challenge, error)
	DeleteChallenge(ctx context.Context, key string) error
}

// RateLimitRepository implements a fixed-window rate limit counter. Backends
// MUST be fail-open — on internal error, they should return a result whose
// Allowed field is true.
type RateLimitRepository interface {
	CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (domain.RateLimitResult, error)
}

// RevocationRepository tracks revoked bearer-token IDs (jti) with TTLs.
type RevocationRepository interface {
	RevokeToken(ctx context.Context, jti string, ttl time.Duration) error
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
}

// MagicLinkRepository covers passwordless email login tokens.
type MagicLinkRepository interface {
	CreateMagicLink(ctx context.Context, input domain.NewMagicLink) error
	// GetUnusedMagicLinkByTokenHash returns nil if the token is missing,
	// expired, or already used.
	GetUnusedMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*domain.MagicLink, error)
	// ConsumeMagicLink atomically looks up an unused, unexpired token by hash
	// and marks it used. Returns the matched record or nil if not consumable.
	ConsumeMagicLink(ctx context.Context, tokenHash string) (*domain.MagicLink, error)
	MarkMagicLinkUsed(ctx context.Context, id string) error
	DeleteMagicLink(ctx context.Context, id string) error
	DeleteUnusedMagicLinksForEmail(ctx context.Context, email string) (int64, error)
}

// PasskeyRepository covers WebAuthn / passkey credentials.
type PasskeyRepository interface {
	GetPasskeysByUserID(ctx context.Context, userID string) ([]*domain.WebauthnCredential, error)
	GetPasskeyByIDAndUser(ctx context.Context, id, userID string) (*domain.WebauthnCredential, error)
	CreatePasskey(ctx context.Context, input domain.NewWebauthnCredential) error
	UpdatePasskeyLastUsed(ctx context.Context, id string, at time.Time) error
	DeletePasskey(ctx context.Context, id string) error
}

// TOTPRepository covers per-user TOTP secrets.
type TOTPRepository interface {
	// GetTOTPByUserID returns the user's TOTP secret. If verifiedOnly is
	// non-nil, only secrets matching the supplied verified state are returned.
	GetTOTPByUserID(ctx context.Context, userID string, verifiedOnly *bool) (*domain.TOTPSecret, error)
	CreateTOTP(ctx context.Context, input domain.NewTOTPSecret) error
	MarkTOTPVerified(ctx context.Context, id string) error
	// DeleteTOTPForUser deletes the user's TOTP secret. If verifiedOnly is
	// non-nil, only matching secrets are deleted.
	DeleteTOTPForUser(ctx context.Context, userID string, verifiedOnly *bool) (int64, error)
}

// BackupCodeRepository covers MFA recovery codes.
type BackupCodeRepository interface {
	GetUnusedBackupCodesByUserID(ctx context.Context, userID string) ([]*domain.BackupCode, error)
	CreateBackupCode(ctx context.Context, input domain.NewBackupCode) error
	MarkBackupCodeUsed(ctx context.Context, id string) error
	DeleteAllBackupCodesForUser(ctx context.Context, userID string) (int64, error)
}

// OAuthAccountRepository covers external-provider account links.
type OAuthAccountRepository interface {
	GetOAuthAccountByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error)
	GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*domain.OAuthAccount, error)
	GetOAuthAccountByUserAndProvider(ctx context.Context, userID, provider string) (*domain.OAuthAccount, error)
	CreateOAuthAccount(ctx context.Context, input domain.NewOAuthAccount) error
	UpdateOAuthAccountTokens(ctx context.Context, id string, accessTokenEnc, refreshTokenEnc *string, expiresAt *time.Time, updatedAt time.Time) error
	DeleteOAuthAccount(ctx context.Context, id string) error
}

// OAuthStateRepository covers CSRF-protecting OAuth authorization-flow state
// tokens; ConsumeOAuthState is a single-use lookup-and-delete.
type OAuthStateRepository interface {
	CreateOAuthState(ctx context.Context, input domain.NewOAuthState) error
	ConsumeOAuthState(ctx context.Context, state string) (*domain.OAuthState, error)
}

// RefreshTokenRepository covers JWT refresh tokens with rotation.
type RefreshTokenRepository interface {
	CreateRefreshToken(ctx context.Context, input domain.NewRefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) (int64, error)
}

// APIKeyRepository covers long-lived API keys identified by prefix.
type APIKeyRepository interface {
	CreateAPIKey(ctx context.Context, input domain.NewAPIKey) error
	GetAPIKeyByPrefix(ctx context.Context, prefix string) (*domain.APIKey, error)
	GetAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*domain.APIKey, error)
	ListAPIKeysByUserID(ctx context.Context, userID string) ([]*domain.APIKey, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id string, at time.Time) error
	DeleteAPIKey(ctx context.Context, id string) error
}

// OAuth2ClientRepository covers registered OAuth2 server clients.
type OAuth2ClientRepository interface {
	CreateOAuth2Client(ctx context.Context, input domain.NewOAuth2Client) error
	GetOAuth2ClientByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error)
	// SetOAuth2ClientBanned bans a client when bannedAt is non-nil, otherwise
	// clears the ban. Returns true if a row was updated.
	SetOAuth2ClientBanned(ctx context.Context, clientID string, bannedAt *time.Time, reason *string) (bool, error)
	// RotateOAuth2ClientPublicKey replaces the registered private_key_jwt
	// signing key. Returns true if a row was updated.
	RotateOAuth2ClientPublicKey(ctx context.Context, clientID string, publicKeyPEM *string) (bool, error)
	ListBannedOAuth2Clients(ctx context.Context) ([]*domain.OAuth2Client, error)
}

// AuthorizationCodeRepository covers single-use OAuth2 authorization codes.
type AuthorizationCodeRepository interface {
	CreateAuthorizationCode(ctx context.Context, input domain.NewAuthorizationCode) error
	// GetAuthorizationCodeByHash returns nil if the code is expired or already
	// used.
	GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error)
	// ConsumeAuthorizationCode atomically marks a code used and returns it.
	// Returns nil if not found / expired / already used.
	ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error)
	MarkAuthorizationCodeUsed(ctx context.Context, id string) error
}

// ConsentRepository covers user-grant consent records for OAuth2 clients.
type ConsentRepository interface {
	CreateConsent(ctx context.Context, input domain.NewConsent) error
	GetConsentByUserAndClient(ctx context.Context, userID, clientID string) (*domain.Consent, error)
	UpdateConsentScopes(ctx context.Context, id string, scopes []byte) error
}

// DeviceCodeRepository covers OAuth2 device-authorization-grant codes.
type DeviceCodeRepository interface {
	CreateDeviceCode(ctx context.Context, input domain.NewDeviceCode) error
	GetDeviceCodeByUserCodePending(ctx context.Context, userCode string) (*domain.DeviceCode, error)
	GetDeviceCodeByDeviceCodeHash(ctx context.Context, deviceCodeHash string) (*domain.DeviceCode, error)
	UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error
	UpdateDeviceCodeLastPolled(ctx context.Context, id string, at time.Time) error
	UpdateDeviceCodeInterval(ctx context.Context, id string, interval int) error
}

// OIDCNonceRepository covers single-use OIDC nonce records.
type OIDCNonceRepository interface {
	CreateOIDCNonce(ctx context.Context, input domain.NewOIDCNonce) error
	GetOIDCNonceByHash(ctx context.Context, nonceHash string) (*domain.OIDCNonce, error)
	DeleteOIDCNonce(ctx context.Context, id string) error
}

// AccountLockRepository covers per-user lockout tracking.
type AccountLockRepository interface {
	GetAccountLockByUserID(ctx context.Context, userID string) (*domain.AccountLock, error)
	CreateAccountLock(ctx context.Context, input domain.NewAccountLock) (domain.AccountLock, error)
	IncrementAccountLockFailedCount(ctx context.Context, id string, updatedAt time.Time) error
	SetAccountLockState(ctx context.Context, id string, state domain.LockState, updatedAt time.Time) error
	ResetAccountLockFailedCount(ctx context.Context, id string, updatedAt time.Time) error
	AutoUnlockAccount(ctx context.Context, id string, updatedAt time.Time) error
}

// UnlockTokenRepository covers single-use account-unlock tokens.
type UnlockTokenRepository interface {
	CreateUnlockToken(ctx context.Context, input domain.NewUnlockToken) error
	GetUnlockTokenByHash(ctx context.Context, tokenHash string) (*domain.UnlockToken, error)
	// ConsumeUnlockToken atomically looks up an unexpired token and deletes it.
	// Returns nil if not found / expired.
	ConsumeUnlockToken(ctx context.Context, tokenHash string) (*domain.UnlockToken, error)
	DeleteUnlockToken(ctx context.Context, id string) error
	DeleteAllUnlockTokensForUser(ctx context.Context, userID string) (int64, error)
}

// WebhookRepository covers outbound webhook configuration.
type WebhookRepository interface {
	CreateWebhook(ctx context.Context, input domain.NewWebhook) error
	GetWebhookByID(ctx context.Context, id string) (*domain.Webhook, error)
	ListActiveWebhooks(ctx context.Context) ([]*domain.Webhook, error)
	ListWebhooks(ctx context.Context) ([]*domain.Webhook, error)
	UpdateWebhook(ctx context.Context, id string, changes domain.UpdateWebhook) (domain.Webhook, error)
	DeleteWebhook(ctx context.Context, id string) error
}

// WebhookDeliveryRepository covers webhook delivery attempts.
type WebhookDeliveryRepository interface {
	CreateWebhookDelivery(ctx context.Context, input domain.NewWebhookDelivery) error
	ListWebhookDeliveriesByWebhookID(ctx context.Context, webhookID string, limit int) ([]*domain.WebhookDelivery, error)
}

// Repository is the union of all repositories. Backends implement this.
type Repository interface {
	UserRepository
	SessionRepository
	PasswordRepository
	PasswordHistoryRepository
	EmailVerificationRepository
	PasswordResetRepository
	AuditLogRepository
	ChallengeRepository
	RateLimitRepository
	RevocationRepository
	MagicLinkRepository
	PasskeyRepository
	TOTPRepository
	BackupCodeRepository
	OAuthAccountRepository
	OAuthStateRepository
	RefreshTokenRepository
	APIKeyRepository
	OAuth2ClientRepository
	AuthorizationCodeRepository
	ConsentRepository
	DeviceCodeRepository
	OIDCNonceRepository
	AccountLockRepository
	UnlockTokenRepository
	WebhookRepository
	WebhookDeliveryRepository
}
