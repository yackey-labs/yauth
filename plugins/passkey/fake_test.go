package passkey

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// fakeRepo is a minimal in-memory repo.Repository for passkey tests. Only
// the methods this plugin actually calls have meaningful implementations;
// the rest return ErrNotFound or zero values, mirroring the convention used
// by the bearer plugin's fake_test.go.
type fakeRepo struct {
	mu         sync.Mutex
	users      map[string]domain.User
	sessions   map[string]domain.Session
	challenges map[string]domain.Challenge
	passkeys   map[string]domain.WebauthnCredential
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:      map[string]domain.User{},
		sessions:   map[string]domain.Session{},
		challenges: map[string]domain.Challenge{},
		passkeys:   map[string]domain.WebauthnCredential{},
	}
}

// --- UserRepository ---

func (f *fakeRepo) CreateUser(_ context.Context, in domain.NewUser) (domain.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Email == in.Email {
			return domain.User{}, yautherr.ErrUserExists
		}
	}
	u := domain.User{
		ID: in.ID, Email: in.Email, DisplayName: in.DisplayName,
		EmailVerified: in.EmailVerified, Role: in.Role,
		Banned: in.Banned, BannedReason: in.BannedReason, BannedUntil: in.BannedUntil,
		CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
	}
	f.users[in.ID] = u
	return u, nil
}

func (f *fakeRepo) GetUserByID(_ context.Context, id string) (*domain.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &u, nil
}

func (f *fakeRepo) GetUserByEmail(_ context.Context, email string) (*domain.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if strings.EqualFold(u.Email, email) {
			u := u
			return &u, nil
		}
	}
	return nil, yautherr.ErrNotFound
}

func (f *fakeRepo) UpdateUser(_ context.Context, _ string, _ domain.UpdateUser) (domain.User, error) {
	return domain.User{}, yautherr.ErrInternal
}
func (f *fakeRepo) DeleteUser(_ context.Context, _ string) error  { return yautherr.ErrInternal }
func (f *fakeRepo) AnyUserExists(_ context.Context) (bool, error) { return len(f.users) > 0, nil }
func (f *fakeRepo) SetUserMustChangePassword(_ context.Context, userID string, must bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return yautherr.ErrNotFound
	}
	u.MustChangePassword = must
	f.users[userID] = u
	return nil
}
func (f *fakeRepo) ListUsers(_ context.Context, _ string, _, _ int) ([]*domain.User, int64, error) {
	return nil, 0, nil
}

// --- SessionRepository ---

func (f *fakeRepo) CreateSession(_ context.Context, in domain.NewSession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[in.TokenHash] = domain.Session{
		ID: in.ID, UserID: in.UserID, TokenHash: in.TokenHash,
		IPAddress: in.IPAddress, UserAgent: in.UserAgent,
		ExpiresAt: in.ExpiresAt, CreatedAt: in.CreatedAt,
	}
	return nil
}
func (f *fakeRepo) GetSessionByID(_ context.Context, _ string) (*domain.Session, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetSessionByTokenHash(_ context.Context, h string) (*domain.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[h]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &s, nil
}
func (f *fakeRepo) DeleteSession(_ context.Context, h string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sessions[h]; !ok {
		return false, nil
	}
	delete(f.sessions, h)
	return true, nil
}
func (f *fakeRepo) DeleteSessionByID(_ context.Context, _ string) error { return yautherr.ErrNotFound }
func (f *fakeRepo) DeleteUserSessions(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) DeleteOtherUserSessions(_ context.Context, _, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) DeleteExpiredSessions(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) ListSessions(_ context.Context, _ domain.ListSessionsFilters) ([]*domain.Session, int64, error) {
	return nil, 0, nil
}
func (f *fakeRepo) SetSessionActiveOrg(_ context.Context, _ string, _ *string) error {
	return nil
}

// --- ChallengeRepository ---

func (f *fakeRepo) SetChallenge(_ context.Context, key, value string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenges[key] = domain.Challenge{Key: key, Value: value, ExpiresAt: time.Now().UTC().Add(ttl)}
	return nil
}
func (f *fakeRepo) GetChallenge(_ context.Context, key string) (*domain.Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.challenges[key]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &c, nil
}
func (f *fakeRepo) ConsumeChallenge(_ context.Context, key string) (*domain.Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.challenges[key]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	delete(f.challenges, key)
	return &c, nil
}
func (f *fakeRepo) DeleteChallenge(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.challenges, key)
	return nil
}

// --- PasskeyRepository ---

func (f *fakeRepo) GetPasskeysByUserID(_ context.Context, userID string) ([]*domain.WebauthnCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.WebauthnCredential
	for _, c := range f.passkeys {
		if c.UserID == userID {
			c := c
			out = append(out, &c)
		}
	}
	return out, nil
}
func (f *fakeRepo) GetPasskeyByIDAndUser(_ context.Context, id, userID string) (*domain.WebauthnCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.passkeys[id]
	if !ok || c.UserID != userID {
		return nil, yautherr.ErrNotFound
	}
	return &c, nil
}
func (f *fakeRepo) CreatePasskey(_ context.Context, in domain.NewWebauthnCredential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.passkeys[in.ID] = domain.WebauthnCredential{
		ID: in.ID, UserID: in.UserID, Name: in.Name, AAGUID: in.AAGUID,
		DeviceName: in.DeviceName, Credential: in.Credential, CreatedAt: in.CreatedAt,
	}
	return nil
}
func (f *fakeRepo) UpdatePasskeyLastUsed(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.passkeys[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	t := at.UTC()
	c.LastUsedAt = &t
	f.passkeys[id] = c
	return nil
}
func (f *fakeRepo) UpdatePasskeyCredential(_ context.Context, id string, credential json.RawMessage, lastUsedAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.passkeys[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	c.Credential = append(json.RawMessage(nil), credential...)
	t := lastUsedAt.UTC()
	c.LastUsedAt = &t
	f.passkeys[id] = c
	return nil
}
func (f *fakeRepo) DeletePasskey(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.passkeys[id]; !ok {
		return yautherr.ErrNotFound
	}
	delete(f.passkeys, id)
	return nil
}

// --- the rest: stubs returning zero / ErrNotFound -----------------------

func (f *fakeRepo) UpsertPassword(_ context.Context, _ domain.NewPassword) error { return nil }
func (f *fakeRepo) GetPasswordByUserID(_ context.Context, _ string) (*domain.Password, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) AppendPasswordHistory(_ context.Context, _ domain.NewPasswordHistory) error {
	return nil
}
func (f *fakeRepo) GetPasswordHistory(_ context.Context, _ string, _ int) ([]*domain.PasswordHistory, error) {
	return nil, nil
}
func (f *fakeRepo) TrimPasswordHistory(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) CreateEmailVerification(_ context.Context, _ domain.NewEmailVerification) error {
	return nil
}
func (f *fakeRepo) ConsumeEmailVerification(_ context.Context, _ string) (*domain.EmailVerification, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteEmailVerification(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteEmailVerificationsForUser(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) CreatePasswordReset(_ context.Context, _ domain.NewPasswordReset) error {
	return nil
}
func (f *fakeRepo) ConsumePasswordReset(_ context.Context, _ string) (*domain.PasswordReset, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteUnusedPasswordResetsForUser(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) LogAuditEvent(_ context.Context, _ domain.NewAuditLog) error { return nil }
func (f *fakeRepo) ListAuditLog(_ context.Context, _ domain.ListAuditFilters) ([]*domain.AuditLog, error) {
	return nil, nil
}
func (f *fakeRepo) CheckRateLimit(_ context.Context, _ string, l int, _ time.Duration) (domain.RateLimitResult, error) {
	return domain.RateLimitResult{Allowed: true, Remaining: l}, nil
}
func (f *fakeRepo) RevokeToken(_ context.Context, _ string, _ time.Duration) error { return nil }
func (f *fakeRepo) IsTokenRevoked(_ context.Context, _ string) (bool, error)       { return false, nil }
func (f *fakeRepo) CreateMagicLink(_ context.Context, _ domain.NewMagicLink) error { return nil }
func (f *fakeRepo) GetUnusedMagicLinkByTokenHash(_ context.Context, _ string) (*domain.MagicLink, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ConsumeMagicLink(_ context.Context, _ string) (*domain.MagicLink, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) MarkMagicLinkUsed(_ context.Context, _ string) error { return yautherr.ErrNotFound }
func (f *fakeRepo) DeleteMagicLink(_ context.Context, _ string) error   { return yautherr.ErrNotFound }
func (f *fakeRepo) DeleteUnusedMagicLinksForEmail(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) GetTOTPByUserID(_ context.Context, _ string, _ *bool) (*domain.TOTPSecret, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) CreateTOTP(_ context.Context, _ domain.NewTOTPSecret) error { return nil }
func (f *fakeRepo) MarkTOTPVerified(_ context.Context, _ string) error         { return yautherr.ErrNotFound }
func (f *fakeRepo) MarkTOTPUsed(_ context.Context, _ string, _ int64) error    { return nil }
func (f *fakeRepo) DeleteTOTPForUser(_ context.Context, _ string, _ *bool) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) GetUnusedBackupCodesByUserID(_ context.Context, _ string) ([]*domain.BackupCode, error) {
	return nil, nil
}
func (f *fakeRepo) CreateBackupCode(_ context.Context, _ domain.NewBackupCode) error { return nil }
func (f *fakeRepo) MarkBackupCodeUsed(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteAllBackupCodesForUser(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) GetOAuthAccountByProviderAndProviderUserID(_ context.Context, _, _ string) (*domain.OAuthAccount, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetOAuthAccountsByUserID(_ context.Context, _ string) ([]*domain.OAuthAccount, error) {
	return nil, nil
}
func (f *fakeRepo) GetOAuthAccountByUserAndProvider(_ context.Context, _, _ string) (*domain.OAuthAccount, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) CreateOAuthAccount(_ context.Context, _ domain.NewOAuthAccount) error {
	return nil
}
func (f *fakeRepo) UpdateOAuthAccountTokens(_ context.Context, _ string, _, _ *string, _ *time.Time, _ time.Time) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteOAuthAccount(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) CreateOAuthState(_ context.Context, _ domain.NewOAuthState) error { return nil }
func (f *fakeRepo) ConsumeOAuthState(_ context.Context, _ string) (*domain.OAuthState, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) CreateRefreshToken(_ context.Context, _ domain.NewRefreshToken) error {
	return nil
}
func (f *fakeRepo) GetRefreshTokenByHash(_ context.Context, _ string) (*domain.RefreshToken, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) RevokeRefreshToken(_ context.Context, _ string) error { return yautherr.ErrNotFound }
func (f *fakeRepo) RevokeRefreshTokenFamily(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) CreateAPIKey(_ context.Context, _ domain.NewAPIKey) error { return nil }
func (f *fakeRepo) GetAPIKeyByPrefix(_ context.Context, _ string) (*domain.APIKey, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetAPIKeyByIDAndUser(_ context.Context, _, _ string) (*domain.APIKey, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetAPIKeyByIDAndOrg(_ context.Context, _, _ string) (*domain.APIKey, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ListAPIKeysByUserID(_ context.Context, _ string) ([]*domain.APIKey, error) {
	return nil, nil
}
func (f *fakeRepo) ListAPIKeysByOrgID(_ context.Context, _ string) ([]*domain.APIKey, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateAPIKeyLastUsed(_ context.Context, _ string, _ time.Time) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) SetAPIKeyExpiry(_ context.Context, _ string, _ *time.Time) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteAPIKey(_ context.Context, _ string) error { return yautherr.ErrNotFound }
func (f *fakeRepo) CreateOAuth2Client(_ context.Context, _ domain.NewOAuth2Client) error {
	return nil
}
func (f *fakeRepo) GetOAuth2ClientByClientID(_ context.Context, _ string) (*domain.OAuth2Client, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) SetOAuth2ClientBanned(_ context.Context, _ string, _ *time.Time, _ *string) (bool, error) {
	return false, nil
}
func (f *fakeRepo) RotateOAuth2ClientPublicKey(_ context.Context, _ string, _ *string) (bool, error) {
	return false, nil
}
func (f *fakeRepo) ListBannedOAuth2Clients(_ context.Context) ([]*domain.OAuth2Client, error) {
	return nil, nil
}
func (f *fakeRepo) CreateAuthorizationCode(_ context.Context, _ domain.NewAuthorizationCode) error {
	return nil
}
func (f *fakeRepo) GetAuthorizationCodeByHash(_ context.Context, _ string) (*domain.AuthorizationCode, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ConsumeAuthorizationCode(_ context.Context, _ string) (*domain.AuthorizationCode, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) MarkAuthorizationCodeUsed(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) CreateConsent(_ context.Context, _ domain.NewConsent) error { return nil }
func (f *fakeRepo) GetConsentByUserAndClient(_ context.Context, _, _ string) (*domain.Consent, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) UpdateConsentScopes(_ context.Context, _ string, _ []byte) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) CreateDeviceCode(_ context.Context, _ domain.NewDeviceCode) error { return nil }
func (f *fakeRepo) GetDeviceCodeByUserCodePending(_ context.Context, _ string) (*domain.DeviceCode, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetDeviceCodeByDeviceCodeHash(_ context.Context, _ string) (*domain.DeviceCode, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) UpdateDeviceCodeStatus(_ context.Context, _, _ string, _ *string) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) UpdateDeviceCodeLastPolled(_ context.Context, _ string, _ time.Time) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) UpdateDeviceCodeInterval(_ context.Context, _ string, _ int) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) CreateOIDCNonce(_ context.Context, _ domain.NewOIDCNonce) error { return nil }
func (f *fakeRepo) GetOIDCNonceByHash(_ context.Context, _ string) (*domain.OIDCNonce, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteOIDCNonce(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) GetAccountLockByUserID(_ context.Context, _ string) (*domain.AccountLock, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) CreateAccountLock(_ context.Context, _ domain.NewAccountLock) (domain.AccountLock, error) {
	return domain.AccountLock{}, yautherr.ErrInternal
}
func (f *fakeRepo) IncrementAccountLockFailedCount(_ context.Context, _ string, _ time.Time) (int, error) {
	return 0, yautherr.ErrNotFound
}
func (f *fakeRepo) SetAccountLockState(_ context.Context, _ string, _ domain.LockState, _ time.Time) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) ResetAccountLockFailedCount(_ context.Context, _ string, _ time.Time) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) AutoUnlockAccount(_ context.Context, _ string, _ time.Time) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) CreateUnlockToken(_ context.Context, _ domain.NewUnlockToken) error { return nil }
func (f *fakeRepo) GetUnlockTokenByHash(_ context.Context, _ string) (*domain.UnlockToken, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ConsumeUnlockToken(_ context.Context, _ string) (*domain.UnlockToken, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteUnlockToken(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteAllUnlockTokensForUser(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) CreateWebhook(_ context.Context, _ domain.NewWebhook) error { return nil }
func (f *fakeRepo) GetWebhookByID(_ context.Context, _ string) (*domain.Webhook, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ListActiveWebhooks(_ context.Context) ([]*domain.Webhook, error) { return nil, nil }
func (f *fakeRepo) ListWebhooks(_ context.Context) ([]*domain.Webhook, error)       { return nil, nil }
func (f *fakeRepo) UpdateWebhook(_ context.Context, _ string, _ domain.UpdateWebhook) (domain.Webhook, error) {
	return domain.Webhook{}, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteWebhook(_ context.Context, _ string) error { return yautherr.ErrNotFound }
func (f *fakeRepo) CreateWebhookDelivery(_ context.Context, _ domain.NewWebhookDelivery) error {
	return nil
}
func (f *fakeRepo) ListWebhookDeliveriesByWebhookID(_ context.Context, _ string, _ int) ([]*domain.WebhookDelivery, error) {
	return nil, nil
}

var _ repo.Repository = (*fakeRepo)(nil)

// --- fakeHost: minimal plugin.PluginHost --------------------------------

type fakeHost struct {
	repo *fakeRepo
	mw   *middleware.Middleware
}

func newFakeHost(fr *fakeRepo) *fakeHost {
	mw := middleware.New(fr, middleware.Config{CookieName: "yauth_session"})
	return &fakeHost{repo: fr, mw: mw}
}

func (h *fakeHost) Repo() repo.Repository                 { return h.repo }
func (h *fakeHost) Middleware() *middleware.Middleware    { return h.mw }
func (h *fakeHost) SessionTTL() time.Duration             { return 30 * 24 * time.Hour }
func (h *fakeHost) CookieName() string                    { return "yauth_session" }
func (h *fakeHost) CookieDomain() string                  { return "" }
func (h *fakeHost) CookieSecure() bool                    { return false }
func (h *fakeHost) CookiePath() string                    { return "/" }
func (h *fakeHost) CookieSameSite() http.SameSite         { return http.SameSiteLaxMode }
func (h *fakeHost) SessionBinding() (bool, bool)          { return false, false }
func (h *fakeHost) RegisterEventHandler(_ events.Handler) {}
func (h *fakeHost) RegisterAuthResolver(r plugin.AuthResolver) {
	h.mw.AddResolver(r)
}
func (h *fakeHost) PluginNames() []string                  { return nil }
func (h *fakeHost) JWTSigner() plugin.JWTSigner            { return nil }
func (h *fakeHost) JWTSecret() []byte                      { return nil }
func (h *fakeHost) RegisterMFAVerifier(plugin.MFAVerifier) {}
func (h *fakeHost) RegisterEventGate(events.Handler)       {}
func (h *fakeHost) MFAVerifier() plugin.MFAVerifier        { return nil }
func (h *fakeHost) Emit(_ context.Context, _ events.AuthEvent) (events.Decision, error) {
	return events.Continue(), nil
}
func (h *fakeHost) RateLimit(name string, max int, window time.Duration) func(http.Handler) http.Handler {
	return middleware.RateLimit(h.repo, name, max, window)
}

var _ plugin.PluginHost = (*fakeHost)(nil)

// --- WebhookRetryRepository (no-op stubs; used only by webhooks plugin tests) ---

func (f *fakeRepo) CreateScheduledRetry(_ context.Context, _ domain.NewScheduledWebhookRetry) error {
	return nil
}
func (f *fakeRepo) ClaimDueRetries(_ context.Context, _ time.Time, _ int) ([]*domain.ScheduledWebhookRetry, error) {
	return nil, nil
}
func (f *fakeRepo) DeleteScheduledRetry(_ context.Context, _ string) error { return nil }

func (h *fakeHost) BaseURL() string          { return "" }
func (h *fakeHost) AllowSignups() bool       { return true }
func (h *fakeHost) AutoAdminFirstUser() bool { return false }

// --- OrganizationRepository / MembershipRepository / InvitationRepository
// no-op stubs (used only by other plugins' tests; PR #87/#98 added these
// to satisfy the repo.Repository interface extension).

func (f *fakeRepo) CreateOrganization(_ context.Context, _ domain.NewOrganization) (domain.Organization, error) {
	return domain.Organization{}, yautherr.ErrNotFound
}
func (f *fakeRepo) GetOrganizationByID(_ context.Context, _ string) (*domain.Organization, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetOrganizationBySlug(_ context.Context, _ string) (*domain.Organization, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) UpdateOrganization(_ context.Context, _ string, _ domain.UpdateOrganization) (domain.Organization, error) {
	return domain.Organization{}, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteOrganization(_ context.Context, _ string) error { return nil }
func (f *fakeRepo) ListOrganizationsForUser(_ context.Context, _ string) ([]*domain.Organization, error) {
	return nil, nil
}
func (f *fakeRepo) ListOrganizations(_ context.Context, _ string, _, _ int) ([]*domain.Organization, int64, error) {
	return nil, 0, nil
}
func (f *fakeRepo) CreateMembership(_ context.Context, _ domain.NewMembership) (domain.Membership, error) {
	return domain.Membership{}, yautherr.ErrNotFound
}
func (f *fakeRepo) GetMembershipByID(_ context.Context, _ string) (*domain.Membership, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetMembershipByOrgUser(_ context.Context, _, _ string) (*domain.Membership, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateMembership(_ context.Context, _ string, _ domain.UpdateMembership) (domain.Membership, error) {
	return domain.Membership{}, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteMembership(_ context.Context, _ string) error { return nil }
func (f *fakeRepo) ListMembershipsByOrg(_ context.Context, _ string) ([]*domain.Membership, error) {
	return nil, nil
}
func (f *fakeRepo) ListMembershipsByUser(_ context.Context, _ string) ([]*domain.Membership, error) {
	return nil, nil
}
func (f *fakeRepo) CreateInvitation(_ context.Context, _ domain.NewInvitation) (domain.Invitation, error) {
	return domain.Invitation{}, yautherr.ErrNotFound
}
func (f *fakeRepo) GetInvitationByID(_ context.Context, _ string) (*domain.Invitation, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetInvitationByTokenHash(_ context.Context, _ string) (*domain.Invitation, error) {
	return nil, nil
}
func (f *fakeRepo) MarkInvitationAccepted(_ context.Context, _ string, _ time.Time) (domain.Invitation, error) {
	return domain.Invitation{}, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteInvitation(_ context.Context, _ string) error { return nil }
func (f *fakeRepo) ListPendingInvitationsForOrg(_ context.Context, _ string) ([]*domain.Invitation, error) {
	return nil, nil
}

// OrganizationDomain stubs (yauth #90 / Go #17).
func (f *fakeRepo) CreateOrganizationDomain(_ context.Context, _ domain.NewOrganizationDomain) (domain.OrganizationDomain, error) {
	return domain.OrganizationDomain{}, yautherr.ErrNotFound
}
func (f *fakeRepo) GetOrganizationDomainByID(_ context.Context, _ string) (*domain.OrganizationDomain, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetOrganizationDomainByDomain(_ context.Context, _ string) (*domain.OrganizationDomain, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ListOrganizationDomainsByOrg(_ context.Context, _ string) ([]*domain.OrganizationDomain, error) {
	return nil, nil
}
func (f *fakeRepo) ListVerifiedAutoJoinOrganizationDomains(_ context.Context, _ string) ([]*domain.OrganizationDomain, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateOrganizationDomain(_ context.Context, _ string, _ domain.UpdateOrganizationDomain) (domain.OrganizationDomain, error) {
	return domain.OrganizationDomain{}, yautherr.ErrNotFound
}
func (f *fakeRepo) SetOrganizationDomainVerification(_ context.Context, _ string, _ domain.DomainStatus, _ *time.Time, _ time.Time) (domain.OrganizationDomain, error) {
	return domain.OrganizationDomain{}, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteOrganizationDomain(_ context.Context, _ string) error { return nil }

// OrganizationPolicy stubs (yauth #92 / yauth-go #21).
func (f *fakeRepo) GetOrganizationPolicy(_ context.Context, _ string) (*domain.OrganizationPolicy, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) CreateOrganizationPolicy(_ context.Context, _ domain.NewOrganizationPolicy) (domain.OrganizationPolicy, error) {
	return domain.OrganizationPolicy{}, yautherr.ErrNotFound
}
func (f *fakeRepo) UpdateOrganizationPolicy(_ context.Context, _ string, _ domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error) {
	return domain.OrganizationPolicy{}, yautherr.ErrNotFound
}
func (f *fakeRepo) UpsertOrganizationPolicy(_ context.Context, _ string, _ domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error) {
	return domain.OrganizationPolicy{}, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteOrganizationPolicy(_ context.Context, _ string) error { return nil }

// SSO stubs (yauth #93 / yauth-go #23).
func (f *fakeRepo) CreateSsoConnection(_ context.Context, _ domain.NewSsoConnection) (domain.SsoConnection, error) {
	return domain.SsoConnection{}, yautherr.ErrNotFound
}
func (f *fakeRepo) GetSsoConnectionByID(_ context.Context, _ string) (*domain.SsoConnection, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ListSsoConnectionsByOrg(_ context.Context, _ string) ([]*domain.SsoConnection, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateSsoConnection(_ context.Context, _ string, _ domain.UpdateSsoConnection) (domain.SsoConnection, error) {
	return domain.SsoConnection{}, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteSsoConnection(_ context.Context, _ string) error { return nil }

func (f *fakeRepo) CreateExternalIdentity(_ context.Context, _ domain.NewExternalIdentity) (domain.ExternalIdentity, error) {
	return domain.ExternalIdentity{}, yautherr.ErrNotFound
}
func (f *fakeRepo) GetExternalIdentityByProviderAndExternalID(_ context.Context, _, _ string) (*domain.ExternalIdentity, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ListExternalIdentitiesByUser(_ context.Context, _ string) ([]*domain.ExternalIdentity, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateExternalIdentityLastLogin(_ context.Context, _ string, _ time.Time) error {
	return nil
}
func (f *fakeRepo) DeleteExternalIdentity(_ context.Context, _ string) error { return nil }

func (f *fakeRepo) CreateSsoLoginState(_ context.Context, _ domain.NewSsoLoginState) error {
	return nil
}
func (f *fakeRepo) ConsumeSsoLoginState(_ context.Context, _ string) (*domain.SsoLoginState, error) {
	return nil, nil
}

func (*fakeHost) Logger() *slog.Logger { return slog.Default() }
