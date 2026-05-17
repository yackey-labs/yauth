package apikey

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// fakeRepo is a tiny in-memory implementation of repo.Repository covering
// the subset of methods exercised by the apikey plugin tests. Methods that
// are never invoked by these tests panic so any silent expansion of the
// surface area trips a test failure rather than silently no-op'ing.
type fakeRepo struct {
	mu       sync.Mutex
	users    map[string]domain.User
	sessions map[string]domain.Session // by token hash
	keys     map[string]domain.APIKey  // by id
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:    map[string]domain.User{},
		sessions: map[string]domain.Session{},
		keys:     map[string]domain.APIKey{},
	}
}

// --- helpers used by the test code ---

func (f *fakeRepo) putUser(u domain.User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[u.ID] = u
}

func (f *fakeRepo) putKey(k domain.APIKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[k.ID] = k
}

func (f *fakeRepo) keyByID(id string) (domain.APIKey, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[id]
	return k, ok
}

// --- UserRepository (subset) ---

func (f *fakeRepo) GetUserByID(_ context.Context, id string) (*domain.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &u, nil
}

// --- APIKeyRepository ---

func (f *fakeRepo) CreateAPIKey(_ context.Context, in domain.NewAPIKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.keys[in.ID]; exists {
		return yautherr.ErrConflict
	}
	f.keys[in.ID] = domain.APIKey{
		ID:        in.ID,
		UserID:    in.UserID,
		KeyPrefix: in.KeyPrefix,
		KeyHash:   in.KeyHash,
		Name:      in.Name,
		Scopes:    in.Scopes,
		ExpiresAt: in.ExpiresAt,
		CreatedAt: in.CreatedAt,
	}
	return nil
}

func (f *fakeRepo) GetAPIKeyByPrefix(_ context.Context, prefix string) (*domain.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.keys {
		if k.KeyPrefix == prefix {
			k := k
			if k.ExpiresAt != nil && !k.ExpiresAt.UTC().After(time.Now().UTC()) {
				return nil, yautherr.ErrNotFound
			}
			return &k, nil
		}
	}
	return nil, yautherr.ErrNotFound
}

func (f *fakeRepo) GetAPIKeyByIDAndUser(_ context.Context, id, userID string) (*domain.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[id]
	if !ok || k.UserID == nil || *k.UserID != userID {
		return nil, yautherr.ErrNotFound
	}
	return &k, nil
}

func (f *fakeRepo) GetAPIKeyByIDAndOrg(_ context.Context, id, organizationID string) (*domain.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[id]
	if !ok || k.OrganizationID == nil || *k.OrganizationID != organizationID {
		return nil, yautherr.ErrNotFound
	}
	return &k, nil
}

func (f *fakeRepo) ListAPIKeysByUserID(_ context.Context, userID string) ([]*domain.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*domain.APIKey{}
	for _, k := range f.keys {
		if k.UserID != nil && *k.UserID == userID {
			k := k
			out = append(out, &k)
		}
	}
	return out, nil
}

func (f *fakeRepo) ListAPIKeysByOrgID(_ context.Context, organizationID string) ([]*domain.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*domain.APIKey{}
	for _, k := range f.keys {
		if k.OrganizationID != nil && *k.OrganizationID == organizationID {
			k := k
			out = append(out, &k)
		}
	}
	return out, nil
}

func (f *fakeRepo) SetAPIKeyExpiry(_ context.Context, id string, expiresAt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	if expiresAt == nil {
		k.ExpiresAt = nil
	} else {
		t := expiresAt.UTC()
		k.ExpiresAt = &t
	}
	f.keys[id] = k
	return nil
}

func (f *fakeRepo) UpdateAPIKeyLastUsed(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	at = at.UTC()
	k.LastUsedAt = &at
	f.keys[id] = k
	return nil
}

func (f *fakeRepo) DeleteAPIKey(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.keys[id]; !ok {
		return yautherr.ErrNotFound
	}
	delete(f.keys, id)
	return nil
}

// --- Everything else: panic on use ---

func (f *fakeRepo) CreateUser(_ context.Context, _ domain.NewUser) (domain.User, error) {
	panic("fakeRepo: CreateUser not implemented for these tests")
}
func (f *fakeRepo) GetUserByEmail(_ context.Context, _ string) (*domain.User, error) {
	panic("fakeRepo: GetUserByEmail not implemented")
}
func (f *fakeRepo) UpdateUser(_ context.Context, _ string, _ domain.UpdateUser) (domain.User, error) {
	panic("fakeRepo: UpdateUser not implemented")
}
func (f *fakeRepo) DeleteUser(_ context.Context, _ string) error {
	panic("fakeRepo: DeleteUser not implemented")
}
func (f *fakeRepo) AnyUserExists(_ context.Context) (bool, error) {
	panic("fakeRepo: AnyUserExists not implemented")
}
func (f *fakeRepo) ListUsers(_ context.Context, _ string, _, _ int) ([]*domain.User, int64, error) {
	panic("fakeRepo: ListUsers not implemented")
}
func (f *fakeRepo) CreateSession(_ context.Context, _ domain.NewSession) error {
	panic("fakeRepo: CreateSession not implemented")
}
func (f *fakeRepo) GetSessionByID(_ context.Context, _ string) (*domain.Session, error) {
	panic("fakeRepo: GetSessionByID not implemented")
}
func (f *fakeRepo) GetSessionByTokenHash(_ context.Context, _ string) (*domain.Session, error) {
	// Session lookup must always miss in these tests — auth is via the
	// X-Api-Key resolver path or a stub resolver, never via cookie.
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteSession(_ context.Context, _ string) (bool, error) {
	panic("fakeRepo: DeleteSession not implemented")
}
func (f *fakeRepo) DeleteSessionByID(_ context.Context, _ string) error {
	panic("fakeRepo: DeleteSessionByID not implemented")
}
func (f *fakeRepo) DeleteUserSessions(_ context.Context, _ string) (int64, error) {
	panic("fakeRepo: DeleteUserSessions not implemented")
}
func (f *fakeRepo) DeleteOtherUserSessions(_ context.Context, _, _ string) (int64, error) {
	panic("fakeRepo: DeleteOtherUserSessions not implemented")
}
func (f *fakeRepo) DeleteExpiredSessions(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (f *fakeRepo) ListSessions(_ context.Context, _ domain.ListSessionsFilters) ([]*domain.Session, int64, error) {
	panic("fakeRepo: ListSessions not implemented")
}
func (f *fakeRepo) SetSessionActiveOrg(_ context.Context, _ string, _ *string) error {
	panic("fakeRepo: SetSessionActiveOrg not implemented")
}
func (f *fakeRepo) UpsertPassword(_ context.Context, _ domain.NewPassword) error {
	panic("fakeRepo: UpsertPassword not implemented")
}
func (f *fakeRepo) GetPasswordByUserID(_ context.Context, _ string) (*domain.Password, error) {
	panic("fakeRepo: GetPasswordByUserID not implemented")
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
	panic("fakeRepo: CreateEmailVerification not implemented")
}
func (f *fakeRepo) ConsumeEmailVerification(_ context.Context, _ string) (*domain.EmailVerification, error) {
	panic("fakeRepo: ConsumeEmailVerification not implemented")
}
func (f *fakeRepo) DeleteEmailVerification(_ context.Context, _ string) error {
	panic("fakeRepo: DeleteEmailVerification not implemented")
}
func (f *fakeRepo) DeleteEmailVerificationsForUser(_ context.Context, _ string) (int64, error) {
	panic("fakeRepo: DeleteEmailVerificationsForUser not implemented")
}
func (f *fakeRepo) CreatePasswordReset(_ context.Context, _ domain.NewPasswordReset) error {
	panic("fakeRepo: CreatePasswordReset not implemented")
}
func (f *fakeRepo) ConsumePasswordReset(_ context.Context, _ string) (*domain.PasswordReset, error) {
	panic("fakeRepo: ConsumePasswordReset not implemented")
}
func (f *fakeRepo) DeleteUnusedPasswordResetsForUser(_ context.Context, _ string) (int64, error) {
	panic("fakeRepo: DeleteUnusedPasswordResetsForUser not implemented")
}
func (f *fakeRepo) LogAuditEvent(_ context.Context, _ domain.NewAuditLog) error { return nil }
func (f *fakeRepo) ListAuditLog(_ context.Context, _ domain.ListAuditFilters) ([]*domain.AuditLog, error) {
	return nil, nil
}
func (f *fakeRepo) SetChallenge(_ context.Context, _, _ string, _ time.Duration) error { return nil }
func (f *fakeRepo) GetChallenge(_ context.Context, _ string) (*domain.Challenge, error) {
	panic("fakeRepo: GetChallenge not implemented")
}
func (f *fakeRepo) ConsumeChallenge(_ context.Context, _ string) (*domain.Challenge, error) {
	panic("fakeRepo: ConsumeChallenge not implemented")
}
func (f *fakeRepo) DeleteChallenge(_ context.Context, _ string) error { return nil }
func (f *fakeRepo) CheckRateLimit(_ context.Context, _ string, limit int, _ time.Duration) (domain.RateLimitResult, error) {
	return domain.RateLimitResult{Allowed: true, Remaining: limit, RetryAfter: 0}, nil
}
func (f *fakeRepo) RevokeToken(_ context.Context, _ string, _ time.Duration) error { return nil }
func (f *fakeRepo) IsTokenRevoked(_ context.Context, _ string) (bool, error)       { return false, nil }
func (f *fakeRepo) CreateMagicLink(_ context.Context, _ domain.NewMagicLink) error {
	panic("fakeRepo: CreateMagicLink not implemented")
}
func (f *fakeRepo) GetUnusedMagicLinkByTokenHash(_ context.Context, _ string) (*domain.MagicLink, error) {
	panic("fakeRepo: GetUnusedMagicLinkByTokenHash not implemented")
}
func (f *fakeRepo) ConsumeMagicLink(_ context.Context, _ string) (*domain.MagicLink, error) {
	panic("fakeRepo: ConsumeMagicLink not implemented")
}
func (f *fakeRepo) MarkMagicLinkUsed(_ context.Context, _ string) error {
	panic("fakeRepo: MarkMagicLinkUsed not implemented")
}
func (f *fakeRepo) DeleteMagicLink(_ context.Context, _ string) error {
	panic("fakeRepo: DeleteMagicLink not implemented")
}
func (f *fakeRepo) DeleteUnusedMagicLinksForEmail(_ context.Context, _ string) (int64, error) {
	panic("fakeRepo: DeleteUnusedMagicLinksForEmail not implemented")
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
func (f *fakeRepo) CreateRefreshToken(_ context.Context, _ domain.NewRefreshToken) error {
	return nil
}
func (f *fakeRepo) GetRefreshTokenByHash(_ context.Context, _ string) (*domain.RefreshToken, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) RevokeRefreshToken(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}
func (f *fakeRepo) RevokeRefreshTokenFamily(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
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

// fakeHost is a minimal plugin.PluginHost wired against fakeRepo so the
// apikey plugin can be exercised end-to-end without depending on the root
// yauth package or gormrepo.
type fakeHost struct {
	repo      repo.Repository
	mw        *middleware.Middleware
	resolvers []middleware.AuthResolver
	pluginSet []plugin.Plugin
}

func newFakeHost(r repo.Repository) *fakeHost {
	return &fakeHost{repo: r, mw: middleware.New(r, middleware.Config{CookieName: "yauth_session"})}
}

func (h *fakeHost) Repo() repo.Repository                 { return h.repo }
func (h *fakeHost) Middleware() *middleware.Middleware    { return h.mw }
func (h *fakeHost) SessionTTL() time.Duration             { return time.Hour }
func (h *fakeHost) CookieName() string                    { return "yauth_session" }
func (h *fakeHost) CookieDomain() string                  { return "" }
func (h *fakeHost) CookieSecure() bool                    { return false }
func (h *fakeHost) CookiePath() string                    { return "/" }
func (h *fakeHost) CookieSameSite() http.SameSite         { return http.SameSiteLaxMode }
func (h *fakeHost) SessionBinding() (bool, bool)          { return false, false }
func (h *fakeHost) RegisterEventHandler(_ events.Handler) {}
func (h *fakeHost) RegisterAuthResolver(r plugin.AuthResolver) {
	h.resolvers = append(h.resolvers, r)
	h.mw.AddResolver(r)
}
func (h *fakeHost) PluginNames() []string {
	out := make([]string, len(h.pluginSet))
	for i, p := range h.pluginSet {
		out[i] = p.Name()
	}
	return out
}
func (h *fakeHost) JWTSigner() plugin.JWTSigner { return nil }
func (h *fakeHost) JWTSecret() []byte           { return nil }
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
