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

	// SetSessionActiveOrg updates the session's active_org_id column
	// (nil clears it). Returns yautherr.ErrNotFound when the session
	// row does not exist. yauth Rust #89 / Go #15.
	SetSessionActiveOrg(ctx context.Context, sessionID string, activeOrgID *string) error
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
//
// Ownership invariants (yauth #91 / yauth-go #19):
//
//   - Every row has exactly one owner: NewAPIKey.UserID XOR
//     NewAPIKey.OrganizationID is non-nil. Backends MUST reject rows
//     that violate the invariant with yautherr.ErrInvalidRequest.
//   - CreateOrgAPIKey is a convenience wrapper around CreateAPIKey
//     that fills the org slot — backends may treat the two as one
//     code path, but the interface keeps the surface explicit so
//     callers cannot accidentally mint a user-scoped key when they
//     meant an org one (and vice versa).
//   - GetAPIKeyByIDAndUser MUST scope by UserID and ignore org-scoped
//     rows; GetAPIKeyByIDAndOrg is the org-scoped twin.
//   - ListAPIKeysByOrgID returns org-scoped rows only (UserID == nil).
//   - SetAPIKeyExpiry sets ExpiresAt without otherwise touching the
//     row. Used by the grace-period rotation flow; nil clears the
//     expiry.
type APIKeyRepository interface {
	CreateAPIKey(ctx context.Context, input domain.NewAPIKey) error
	GetAPIKeyByPrefix(ctx context.Context, prefix string) (*domain.APIKey, error)
	GetAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*domain.APIKey, error)
	ListAPIKeysByUserID(ctx context.Context, userID string) ([]*domain.APIKey, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id string, at time.Time) error
	DeleteAPIKey(ctx context.Context, id string) error

	// Org-scoped API key (service-account) methods. yauth #91 /
	// yauth-go #19.

	// GetAPIKeyByIDAndOrg looks up an org-scoped key by id and
	// owning organization. Returns yautherr.ErrNotFound when the
	// row does not exist, belongs to a different org, or is
	// user-scoped.
	GetAPIKeyByIDAndOrg(ctx context.Context, id, organizationID string) (*domain.APIKey, error)
	// ListAPIKeysByOrgID returns every org-scoped key owned by
	// organizationID in deterministic order (created_at descending).
	ListAPIKeysByOrgID(ctx context.Context, organizationID string) ([]*domain.APIKey, error)
	// SetAPIKeyExpiry overwrites the ExpiresAt column on id without
	// otherwise modifying the row. Pass nil to clear the expiry.
	// Returns yautherr.ErrNotFound when id does not exist.
	SetAPIKeyExpiry(ctx context.Context, id string, expiresAt *time.Time) error
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

// OrganizationRepository covers Organization CRUD for the multi-tenant
// primitive (yauth Rust PR #98 / issue #87).
//
// Invariants every backend MUST honor:
//
//   - CreateOrganization MUST reject duplicate slugs (case-insensitive)
//     with yautherr.ErrConflict.
//   - GetOrganizationBySlug MUST be case-insensitive.
//   - DeleteOrganization MUST cascade to memberships and invitations
//     (FK ON DELETE CASCADE in SQL backends; explicit in memrepo).
type OrganizationRepository interface {
	GetOrganizationByID(ctx context.Context, id string) (*domain.Organization, error)
	// GetOrganizationBySlug is case-insensitive on slug.
	GetOrganizationBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	// CreateOrganization returns yautherr.ErrConflict when a row with
	// a matching slug (case-insensitive) already exists.
	CreateOrganization(ctx context.Context, input domain.NewOrganization) (domain.Organization, error)
	UpdateOrganization(ctx context.Context, id string, changes domain.UpdateOrganization) (domain.Organization, error)
	// DeleteOrganization removes the org and cascades to memberships
	// and invitations.
	DeleteOrganization(ctx context.Context, id string) error
	// ListOrganizationsForUser returns every org the user is a member
	// of in deterministic order (created_at ascending).
	ListOrganizationsForUser(ctx context.Context, userID string) ([]*domain.Organization, error)
	// ListOrganizations returns a page of orgs plus the total matching
	// the (optional) case-insensitive search filter on name/slug.
	ListOrganizations(ctx context.Context, search string, limit, offset int) ([]*domain.Organization, int64, error)
}

// MembershipRepository covers Membership CRUD.
//
// Invariants:
//
//   - CreateMembership MUST reject duplicate (organization_id, user_id)
//     pairs with yautherr.ErrConflict.
//   - Deleting a non-existent membership returns nil (idempotent).
//   - Owner-protection (yauth #88): UpdateMembership and
//     DeleteMembership MUST refuse to demote or remove a membership
//     whose role == "owner" when it is the last owner of the org,
//     returning yautherr.ErrOwnerProtected. The transfer-ownership
//     handler is responsible for promoting the new owner before the
//     destructive op runs against the prior owner.
type MembershipRepository interface {
	GetMembershipByID(ctx context.Context, id string) (*domain.Membership, error)
	// GetMembershipByOrgUser returns the join row tying user to org,
	// or nil if not a member. yautherr.ErrNotFound is NOT returned —
	// "not a member" is a normal state, not an error.
	GetMembershipByOrgUser(ctx context.Context, organizationID, userID string) (*domain.Membership, error)
	CreateMembership(ctx context.Context, input domain.NewMembership) (domain.Membership, error)
	UpdateMembership(ctx context.Context, id string, changes domain.UpdateMembership) (domain.Membership, error)
	DeleteMembership(ctx context.Context, id string) error
	// ListMembershipsByOrg returns all memberships in an org.
	ListMembershipsByOrg(ctx context.Context, organizationID string) ([]*domain.Membership, error)
	// ListMembershipsByUser returns all memberships for a user (one
	// per org).
	ListMembershipsByUser(ctx context.Context, userID string) ([]*domain.Membership, error)
}

// InvitationRepository covers Invitation CRUD.
//
// Invariants:
//
//   - GetInvitationByTokenHash returns nil for expired or already
//     accepted invitations. Callers do not need to filter.
//   - MarkInvitationAccepted is single-shot — once accepted, a second
//     call returns yautherr.ErrNotFound.
type InvitationRepository interface {
	GetInvitationByID(ctx context.Context, id string) (*domain.Invitation, error)
	// GetInvitationByTokenHash returns nil for expired or already
	// accepted entries.
	GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*domain.Invitation, error)
	CreateInvitation(ctx context.Context, input domain.NewInvitation) (domain.Invitation, error)
	// MarkInvitationAccepted stamps accepted_at and returns the
	// updated row. Returns yautherr.ErrNotFound if the invitation was
	// already accepted or does not exist.
	MarkInvitationAccepted(ctx context.Context, id string, acceptedAt time.Time) (domain.Invitation, error)
	DeleteInvitation(ctx context.Context, id string) error
	// ListPendingInvitationsForOrg returns invitations with
	// accepted_at IS NULL for the given org.
	ListPendingInvitationsForOrg(ctx context.Context, organizationID string) ([]*domain.Invitation, error)
}

// OrganizationDomainRepository covers OrganizationDomain CRUD plus the
// atomic verification-state transition. Port of yauth Rust #90.
//
// Invariants every backend MUST honor:
//
//   - CreateOrganizationDomain MUST reject a duplicate Domain (a row
//     whose canonicalized domain string already exists, regardless of
//     organization_id) with yautherr.ErrConflict. This is the
//     app-wide UNIQUE(domain) anti-abuse gate.
//   - GetOrganizationDomainByDomain is case-insensitive and MUST match
//     against the canonical lowercase form.
//   - SetOrganizationDomainVerification atomically updates
//     (status, verified_at, last_checked_at, updated_at).
//   - DeleteOrganizationDomain is idempotent — a non-existent id
//     returns nil.
//   - Deleting an Organization cascades to its domain rows (FK ON
//     DELETE CASCADE / explicit in memrepo).
type OrganizationDomainRepository interface {
	// CreateOrganizationDomain returns yautherr.ErrConflict on
	// duplicate Domain (app-wide uniqueness, case-insensitive).
	CreateOrganizationDomain(ctx context.Context, input domain.NewOrganizationDomain) (domain.OrganizationDomain, error)
	GetOrganizationDomainByID(ctx context.Context, id string) (*domain.OrganizationDomain, error)
	// GetOrganizationDomainByDomain is case-insensitive on the
	// domain key. Returns (nil, yautherr.ErrNotFound) when no row
	// matches.
	GetOrganizationDomainByDomain(ctx context.Context, domainStr string) (*domain.OrganizationDomain, error)
	// ListOrganizationDomainsByOrg returns every domain row for orgID
	// in deterministic order (created_at ascending, id ascending).
	ListOrganizationDomainsByOrg(ctx context.Context, organizationID string) ([]*domain.OrganizationDomain, error)
	// ListVerifiedAutoJoinOrganizationDomains returns every verified
	// row whose Domain matches domainStr (case-insensitive) AND has
	// AutoJoinOnSignup = true. Order is created_at ascending. With
	// the app-wide UNIQUE(domain) invariant this returns 0 or 1 row,
	// but the slice shape leaves room for relaxing the constraint
	// later without churning callers.
	ListVerifiedAutoJoinOrganizationDomains(ctx context.Context, domainStr string) ([]*domain.OrganizationDomain, error)
	// UpdateOrganizationDomain applies a partial update. Returns
	// yautherr.ErrNotFound when no row matches id.
	UpdateOrganizationDomain(ctx context.Context, id string, changes domain.UpdateOrganizationDomain) (domain.OrganizationDomain, error)
	// SetOrganizationDomainVerification atomically updates the
	// verification triple (status, verified_at, last_checked_at) and
	// bumps updated_at to now. Pass verifiedAt = nil to express "did
	// not verify"; pass non-nil only for status == verified. Returns
	// yautherr.ErrNotFound when no row matches id.
	SetOrganizationDomainVerification(ctx context.Context, id string, status domain.DomainStatus, verifiedAt *time.Time, lastCheckedAt time.Time) (domain.OrganizationDomain, error)
	// DeleteOrganizationDomain is idempotent.
	DeleteOrganizationDomain(ctx context.Context, id string) error
}

// WebhookRetryRepository covers persisted webhook retries — the
// crash-safe queue that survives process restarts. ClaimDueRetries is
// the linchpin: it MUST atomically remove each returned row from the
// pool of rows other claimers can see, so two dispatchers running
// against the same DB never run the same retry twice. Backends use
// SELECT ... FOR UPDATE SKIP LOCKED on PostgreSQL and a transaction-
// scoped delete-then-return on SQLite/in-memory.
type WebhookRetryRepository interface {
	CreateScheduledRetry(ctx context.Context, input domain.NewScheduledWebhookRetry) error
	// ClaimDueRetries returns up to limit rows whose NotBefore <= now,
	// removing them from the table so a parallel claimer cannot pick
	// them up. The caller is responsible for re-persisting a fresh row
	// if the retry fails again.
	ClaimDueRetries(ctx context.Context, now time.Time, limit int) ([]*domain.ScheduledWebhookRetry, error)
	DeleteScheduledRetry(ctx context.Context, id string) error
}

// OrganizationPolicyRepository covers per-org auth-policy CRUD. Port of
// yauth Rust #92.
//
// Invariants:
//
//   - There is at most one row per organization. CreateOrganizationPolicy
//     MUST reject a duplicate organization_id with yautherr.ErrConflict.
//   - GetOrganizationPolicy returns (nil, yautherr.ErrNotFound) when no
//     row exists. "No row" is a normal state (the org inherits global
//     defaults wholesale); callers must treat ErrNotFound as such.
//   - UpsertOrganizationPolicy is the convenience helper used by the
//     PATCH handler: it creates the row if absent or applies a partial
//     update if present, returning the post-state.
//   - Deleting an Organization MUST cascade to its policy row (FK ON
//     DELETE CASCADE in SQL backends; explicit in memrepo).
type OrganizationPolicyRepository interface {
	// GetOrganizationPolicy returns the per-org policy. Returns
	// (nil, yautherr.ErrNotFound) when no row exists.
	GetOrganizationPolicy(ctx context.Context, organizationID string) (*domain.OrganizationPolicy, error)
	// CreateOrganizationPolicy returns yautherr.ErrConflict on a
	// duplicate organization_id.
	CreateOrganizationPolicy(ctx context.Context, input domain.NewOrganizationPolicy) (domain.OrganizationPolicy, error)
	// UpdateOrganizationPolicy applies a partial update. Returns
	// yautherr.ErrNotFound when no row matches organizationID.
	UpdateOrganizationPolicy(ctx context.Context, organizationID string, changes domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error)
	// UpsertOrganizationPolicy creates the policy row when missing or
	// applies the partial update when present. Returns the post-state.
	UpsertOrganizationPolicy(ctx context.Context, organizationID string, changes domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error)
	// DeleteOrganizationPolicy is idempotent — a non-existent row
	// returns nil.
	DeleteOrganizationPolicy(ctx context.Context, organizationID string) error
}

// SsoConnectionRepository covers SsoConnection CRUD for the OIDC client
// (and future SAML SP) federated-sign-in path. Port of yauth Rust #93.
//
// Invariants every backend MUST honor:
//
//   - Each row is owned by exactly one organization_id; the create path
//     does NOT enforce uniqueness on (org_id, name) — admins may want
//     two connections (e.g. staging + prod IdPs) per org.
//   - Deleting an Organization MUST cascade to its SsoConnection rows
//     (FK ON DELETE CASCADE in SQL backends; explicit in memrepo).
//   - GetSsoConnectionByID returns (nil, yautherr.ErrNotFound) when no
//     row matches; backends must not return (nil, nil).
//   - ListSsoConnectionsByOrg returns rows in deterministic order
//     (created_at ascending) and includes every status (draft / active /
//     disabled) — filtering by status is the caller's job.
//   - UpdateSsoConnection applies a partial update; nil-pointer fields
//     are left untouched.
type SsoConnectionRepository interface {
	CreateSsoConnection(ctx context.Context, input domain.NewSsoConnection) (domain.SsoConnection, error)
	GetSsoConnectionByID(ctx context.Context, id string) (*domain.SsoConnection, error)
	ListSsoConnectionsByOrg(ctx context.Context, organizationID string) ([]*domain.SsoConnection, error)
	UpdateSsoConnection(ctx context.Context, id string, changes domain.UpdateSsoConnection) (domain.SsoConnection, error)
	// DeleteSsoConnection is idempotent — a non-existent id returns nil.
	DeleteSsoConnection(ctx context.Context, id string) error
}

// ExternalIdentityRepository covers the (provider, external_id) →
// user_id join used by the OIDC client to resolve a federated id_token
// to a yauth user. Port of yauth Rust #93.
//
// Invariants:
//
//   - The (provider, external_id) pair is unique across the table.
//     CreateExternalIdentity returns yautherr.ErrConflict on a
//     duplicate pair.
//   - Deleting a User MUST cascade to its ExternalIdentity rows (FK ON
//     DELETE CASCADE in SQL backends; explicit in memrepo).
//   - GetExternalIdentityByProviderAndExternalID returns
//     (nil, yautherr.ErrNotFound) on miss.
//   - UpdateExternalIdentityLastLogin stamps LastLoginAt without
//     touching any other column. Used on every successful SSO login.
type ExternalIdentityRepository interface {
	CreateExternalIdentity(ctx context.Context, input domain.NewExternalIdentity) (domain.ExternalIdentity, error)
	GetExternalIdentityByProviderAndExternalID(ctx context.Context, provider, externalID string) (*domain.ExternalIdentity, error)
	ListExternalIdentitiesByUser(ctx context.Context, userID string) ([]*domain.ExternalIdentity, error)
	UpdateExternalIdentityLastLogin(ctx context.Context, id string, at time.Time) error
	DeleteExternalIdentity(ctx context.Context, id string) error
}

// SsoLoginStateRepository covers the short-lived state row that ties an
// outbound /sso/login redirect to its eventual /sso/callback. Single-
// use: ConsumeSsoLoginState atomically looks up the row and deletes it.
type SsoLoginStateRepository interface {
	CreateSsoLoginState(ctx context.Context, input domain.NewSsoLoginState) error
	// ConsumeSsoLoginState atomically looks up the state token and
	// deletes it. Returns the matched record or nil if not found /
	// expired / already consumed.
	ConsumeSsoLoginState(ctx context.Context, state string) (*domain.SsoLoginState, error)
}

// GroupRepository covers organization-scoped groups, their membership, and
// OAuth2 client (application) group assignments used for access enforcement.
type GroupRepository interface {
	CreateGroup(ctx context.Context, input domain.NewGroup) (domain.Group, error)
	GetGroupByID(ctx context.Context, id string) (*domain.Group, error)
	GetGroupByOrgAndName(ctx context.Context, orgID, name string) (*domain.Group, error)
	GetGroupByOrgAndExternalID(ctx context.Context, orgID, externalID string) (*domain.Group, error)
	ListGroupsByOrg(ctx context.Context, orgID string) ([]*domain.Group, error)
	UpdateGroup(ctx context.Context, id string, changes domain.UpdateGroup) (domain.Group, error)
	DeleteGroup(ctx context.Context, id string) error

	// AddGroupMember is idempotent (re-adding an existing member is a no-op).
	// The caller is responsible for enforcing that the user belongs to the
	// group's organization.
	AddGroupMember(ctx context.Context, groupID, userID string, now time.Time) error
	RemoveGroupMember(ctx context.Context, groupID, userID string) error
	ListGroupMembers(ctx context.Context, groupID string) ([]*domain.User, error)
	ListGroupsForUser(ctx context.Context, orgID, userID string) ([]*domain.Group, error)
	IsGroupMember(ctx context.Context, groupID, userID string) (bool, error)

	// AssignClientGroup is idempotent. UnassignClientGroup is a no-op when the
	// assignment is absent.
	AssignClientGroup(ctx context.Context, clientID, groupID string, now time.Time) error
	UnassignClientGroup(ctx context.Context, clientID, groupID string) error
	ListClientGroups(ctx context.Context, clientID string) ([]*domain.Group, error)
	// UserInAssignedGroup reports whether userID is a member of any group
	// assigned to clientID — the /authorize enforcement check.
	UserInAssignedGroup(ctx context.Context, clientID, userID string) (bool, error)

	// SetClientEnforceGroupAssignment toggles the per-client access gate.
	SetClientEnforceGroupAssignment(ctx context.Context, clientID string, enforce bool) error
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
	WebhookRetryRepository
	OrganizationRepository
	MembershipRepository
	InvitationRepository
	OrganizationDomainRepository
	OrganizationPolicyRepository
	SsoConnectionRepository
	ExternalIdentityRepository
	SsoLoginStateRepository
	GroupRepository
}
