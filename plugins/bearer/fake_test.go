package bearer

import (
	"context"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// fakeRepo is a minimal in-memory repo.Repository for bearer tests. It
// only implements the methods bearer + middleware actually exercise; the
// rest return ErrNotFound or zero values.
type fakeRepo struct {
	users         map[string]domain.User
	passwords     map[string]domain.Password
	sessions      map[string]domain.Session // keyed by token hash
	refreshTokens map[string]domain.RefreshToken
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:         map[string]domain.User{},
		passwords:     map[string]domain.Password{},
		sessions:      map[string]domain.Session{},
		refreshTokens: map[string]domain.RefreshToken{},
	}
}

// --- UserRepository ---

func (f *fakeRepo) CreateUser(_ context.Context, in domain.NewUser) (domain.User, error) {
	if _, ok := f.users[in.ID]; ok {
		return domain.User{}, yautherr.ErrUserExists
	}
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
	u, ok := f.users[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &u, nil
}

func (f *fakeRepo) GetUserByEmail(_ context.Context, email string) (*domain.User, error) {
	for _, u := range f.users {
		if u.Email == email {
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
func (f *fakeRepo) ListUsers(_ context.Context, _ string, _, _ int) ([]*domain.User, int64, error) {
	return nil, 0, nil
}

// --- SessionRepository ---

func (f *fakeRepo) CreateSession(_ context.Context, in domain.NewSession) error {
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
	s, ok := f.sessions[h]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &s, nil
}
func (f *fakeRepo) DeleteSession(_ context.Context, h string) (bool, error) {
	if _, ok := f.sessions[h]; !ok {
		return false, nil
	}
	delete(f.sessions, h)
	return true, nil
}
func (f *fakeRepo) DeleteSessionByID(_ context.Context, _ string) error { return yautherr.ErrNotFound }
func (f *fakeRepo) DeleteUserSessions(_ context.Context, uid string) (int64, error) {
	n := int64(0)
	for k, s := range f.sessions {
		if s.UserID == uid {
			delete(f.sessions, k)
			n++
		}
	}
	return n, nil
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

// --- PasswordRepository ---

func (f *fakeRepo) UpsertPassword(_ context.Context, in domain.NewPassword) error {
	f.passwords[in.UserID] = domain.Password{UserID: in.UserID, PasswordHash: in.PasswordHash}
	return nil
}
func (f *fakeRepo) GetPasswordByUserID(_ context.Context, uid string) (*domain.Password, error) {
	pw, ok := f.passwords[uid]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &pw, nil
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

// --- RefreshTokenRepository ---

func (f *fakeRepo) CreateRefreshToken(_ context.Context, in domain.NewRefreshToken) error {
	f.refreshTokens[in.TokenHash] = domain.RefreshToken{
		ID: in.ID, UserID: in.UserID, TokenHash: in.TokenHash,
		FamilyID: in.FamilyID, ExpiresAt: in.ExpiresAt,
		Revoked: in.Revoked, CreatedAt: in.CreatedAt,
	}
	return nil
}
func (f *fakeRepo) GetRefreshTokenByHash(_ context.Context, h string) (*domain.RefreshToken, error) {
	rt, ok := f.refreshTokens[h]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &rt, nil
}
func (f *fakeRepo) RevokeRefreshToken(_ context.Context, id string) error {
	for k, rt := range f.refreshTokens {
		if rt.ID == id {
			rt.Revoked = true
			f.refreshTokens[k] = rt
			return nil
		}
	}
	return yautherr.ErrNotFound
}
func (f *fakeRepo) RevokeRefreshTokenFamily(_ context.Context, fam string) (int64, error) {
	n := int64(0)
	for k, rt := range f.refreshTokens {
		if rt.FamilyID == fam && !rt.Revoked {
			rt.Revoked = true
			f.refreshTokens[k] = rt
			n++
		}
	}
	return n, nil
}

// --- the rest: stubs returning ErrNotFound / zero ---

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
func (f *fakeRepo) SetChallenge(_ context.Context, _, _ string, _ time.Duration) error { return nil }
func (f *fakeRepo) GetChallenge(_ context.Context, _ string) (*domain.Challenge, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ConsumeChallenge(_ context.Context, _ string) (*domain.Challenge, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteChallenge(_ context.Context, _ string) error { return nil }
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
func (f *fakeRepo) GetPasskeysByUserID(_ context.Context, _ string) ([]*domain.WebauthnCredential, error) {
	return nil, nil
}
func (f *fakeRepo) GetPasskeyByIDAndUser(_ context.Context, _, _ string) (*domain.WebauthnCredential, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) CreatePasskey(_ context.Context, _ domain.NewWebauthnCredential) error {
	return nil
}
func (f *fakeRepo) UpdatePasskeyLastUsed(_ context.Context, _ string, _ time.Time) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) DeletePasskey(_ context.Context, _ string) error { return yautherr.ErrNotFound }
func (f *fakeRepo) GetTOTPByUserID(_ context.Context, _ string, _ *bool) (*domain.TOTPSecret, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) CreateTOTP(_ context.Context, _ domain.NewTOTPSecret) error { return nil }
func (f *fakeRepo) MarkTOTPVerified(_ context.Context, _ string) error         { return yautherr.ErrNotFound }
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
func (f *fakeRepo) CreateAPIKey(_ context.Context, _ domain.NewAPIKey) error { return nil }
func (f *fakeRepo) GetAPIKeyByPrefix(_ context.Context, _ string) (*domain.APIKey, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) GetAPIKeyByIDAndUser(_ context.Context, _, _ string) (*domain.APIKey, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ListAPIKeysByUserID(_ context.Context, _ string) ([]*domain.APIKey, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateAPIKeyLastUsed(_ context.Context, _ string, _ time.Time) error {
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
func (f *fakeRepo) IncrementAccountLockFailedCount(_ context.Context, _ string, _ time.Time) error {
	return yautherr.ErrNotFound
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

// --- fakeHost: minimal plugin.PluginHost ---------------------------------

type fakeHost struct {
	repo      *fakeRepo
	mw        *middleware.Middleware
	jwtSecret []byte
	resolvers []plugin.AuthResolver
}

func newFakeHost(fr *fakeRepo, jwtSecret []byte) *fakeHost {
	mw := middleware.New(fr, middleware.Config{CookieName: "yauth_session"})
	return &fakeHost{repo: fr, mw: mw, jwtSecret: jwtSecret}
}

func (h *fakeHost) Repo() repo.Repository                 { return h.repo }
func (h *fakeHost) Middleware() *middleware.Middleware    { return h.mw }
func (h *fakeHost) SessionTTL() time.Duration             { return 30 * 24 * time.Hour }
func (h *fakeHost) CookieName() string                    { return "yauth_session" }
func (h *fakeHost) CookieDomain() string                  { return "" }
func (h *fakeHost) CookieSecure() bool                    { return false }
func (h *fakeHost) CookiePath() string                    { return "/" }
func (h *fakeHost) CookieSameSite() http.SameSite         { return http.SameSiteLaxMode }
func (h *fakeHost) RegisterEventHandler(_ events.Handler) {}
func (h *fakeHost) RegisterAuthResolver(r plugin.AuthResolver) {
	h.resolvers = append(h.resolvers, r)
	h.mw.AddResolver(r)
}
func (h *fakeHost) PluginNames() []string       { return nil }
func (h *fakeHost) JWTSigner() plugin.JWTSigner { return nil }
func (h *fakeHost) JWTSecret() []byte           { return h.jwtSecret }
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

func (h *fakeHost) BaseURL() string            { return "" }
func (h *fakeHost) AllowSignups() bool         { return true }
func (h *fakeHost) AutoAdminFirstUser() bool   { return false }
