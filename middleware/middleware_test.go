package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// fakeRepo is a minimal in-memory implementation of repo.Repository used
// to drive the middleware tests without dragging in gormrepo (which would
// transitively import the root yauth package and form a cycle through
// middleware itself).
type fakeRepo struct {
	users    map[string]domain.User
	sessions map[string]domain.Session // keyed by token hash
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:    map[string]domain.User{},
		sessions: map[string]domain.Session{},
	}
}

// --- UserRepository ---

func (f *fakeRepo) CreateUser(_ context.Context, in domain.NewUser) (domain.User, error) {
	if _, ok := f.users[in.ID]; ok {
		return domain.User{}, yautherr.ErrUserExists
	}
	u := domain.User{
		ID:            in.ID,
		Email:         in.Email,
		DisplayName:   in.DisplayName,
		EmailVerified: in.EmailVerified,
		Role:          in.Role,
		Banned:        in.Banned,
		BannedReason:  in.BannedReason,
		BannedUntil:   in.BannedUntil,
		CreatedAt:     in.CreatedAt,
		UpdatedAt:     in.UpdatedAt,
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

func (f *fakeRepo) DeleteUser(_ context.Context, _ string) error {
	return yautherr.ErrInternal
}

// --- SessionRepository ---

func (f *fakeRepo) CreateSession(_ context.Context, in domain.NewSession) error {
	f.sessions[in.TokenHash] = domain.Session{
		ID:        in.ID,
		UserID:    in.UserID,
		TokenHash: in.TokenHash,
		IPAddress: in.IPAddress,
		UserAgent: in.UserAgent,
		ExpiresAt: in.ExpiresAt,
		CreatedAt: in.CreatedAt,
	}
	return nil
}

func (f *fakeRepo) GetSessionByTokenHash(_ context.Context, tokenHash string) (*domain.Session, error) {
	s, ok := f.sessions[tokenHash]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return &s, nil
}

func (f *fakeRepo) DeleteSession(_ context.Context, tokenHash string) (bool, error) {
	if _, ok := f.sessions[tokenHash]; !ok {
		return false, nil
	}
	delete(f.sessions, tokenHash)
	return true, nil
}

func (f *fakeRepo) DeleteUserSessions(_ context.Context, userID string) (int64, error) {
	n := int64(0)
	for k, s := range f.sessions {
		if s.UserID == userID {
			delete(f.sessions, k)
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) DeleteExpiredSessions(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

// --- Other repos (unused by middleware tests) ---

func (f *fakeRepo) UpsertPassword(_ context.Context, _ domain.NewPassword) error {
	return nil
}
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
func (f *fakeRepo) CreatePasswordReset(_ context.Context, _ domain.NewPasswordReset) error {
	return nil
}
func (f *fakeRepo) ConsumePasswordReset(_ context.Context, _ string) (*domain.PasswordReset, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) LogAuditEvent(_ context.Context, _ domain.NewAuditLog) error {
	return nil
}

// --- User extras ---

func (f *fakeRepo) AnyUserExists(_ context.Context) (bool, error) {
	return len(f.users) > 0, nil
}

func (f *fakeRepo) ListUsers(_ context.Context, _ string, _, _ int) ([]*domain.User, int64, error) {
	return nil, 0, nil
}

// --- Session extras ---

func (f *fakeRepo) GetSessionByID(_ context.Context, _ string) (*domain.Session, error) {
	return nil, yautherr.ErrNotFound
}

func (f *fakeRepo) DeleteSessionByID(_ context.Context, _ string) error { return yautherr.ErrNotFound }

func (f *fakeRepo) DeleteOtherUserSessions(_ context.Context, _, _ string) (int64, error) {
	return 0, nil
}

func (f *fakeRepo) ListSessions(_ context.Context, _ domain.ListSessionsFilters) ([]*domain.Session, int64, error) {
	return nil, 0, nil
}

// --- Audit list ---

func (f *fakeRepo) ListAuditLog(_ context.Context, _ domain.ListAuditFilters) ([]*domain.AuditLog, error) {
	return nil, nil
}

// --- EmailVerification extras ---

func (f *fakeRepo) DeleteEmailVerification(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}

func (f *fakeRepo) DeleteEmailVerificationsForUser(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// --- PasswordReset extras ---

func (f *fakeRepo) DeleteUnusedPasswordResetsForUser(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// --- Challenge ---

func (f *fakeRepo) SetChallenge(_ context.Context, _, _ string, _ time.Duration) error { return nil }
func (f *fakeRepo) GetChallenge(_ context.Context, _ string) (*domain.Challenge, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) ConsumeChallenge(_ context.Context, _ string) (*domain.Challenge, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteChallenge(_ context.Context, _ string) error { return nil }

// --- RateLimit ---

func (f *fakeRepo) CheckRateLimit(_ context.Context, _ string, limit int, _ time.Duration) (domain.RateLimitResult, error) {
	return domain.RateLimitResult{Allowed: true, Remaining: limit, RetryAfter: 0}, nil
}

// --- Revocation ---

func (f *fakeRepo) RevokeToken(_ context.Context, _ string, _ time.Duration) error { return nil }
func (f *fakeRepo) IsTokenRevoked(_ context.Context, _ string) (bool, error)       { return false, nil }

// --- MagicLink ---

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

// --- Passkey ---

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

// --- TOTP ---

func (f *fakeRepo) GetTOTPByUserID(_ context.Context, _ string, _ *bool) (*domain.TOTPSecret, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) CreateTOTP(_ context.Context, _ domain.NewTOTPSecret) error { return nil }
func (f *fakeRepo) MarkTOTPVerified(_ context.Context, _ string) error         { return yautherr.ErrNotFound }
func (f *fakeRepo) DeleteTOTPForUser(_ context.Context, _ string, _ *bool) (int64, error) {
	return 0, nil
}

// --- BackupCode ---

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

// --- OAuthAccount / OAuthState ---

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

// --- RefreshToken ---

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

// --- APIKey ---

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

// --- OAuth2Client ---

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

// --- AuthorizationCode ---

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

// --- Consent ---

func (f *fakeRepo) CreateConsent(_ context.Context, _ domain.NewConsent) error { return nil }
func (f *fakeRepo) GetConsentByUserAndClient(_ context.Context, _, _ string) (*domain.Consent, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) UpdateConsentScopes(_ context.Context, _ string, _ []byte) error {
	return yautherr.ErrNotFound
}

// --- DeviceCode ---

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

// --- OIDCNonce ---

func (f *fakeRepo) CreateOIDCNonce(_ context.Context, _ domain.NewOIDCNonce) error { return nil }
func (f *fakeRepo) GetOIDCNonceByHash(_ context.Context, _ string) (*domain.OIDCNonce, error) {
	return nil, yautherr.ErrNotFound
}
func (f *fakeRepo) DeleteOIDCNonce(_ context.Context, _ string) error {
	return yautherr.ErrNotFound
}

// --- AccountLock ---

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

// --- UnlockToken ---

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

// --- Webhook ---

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

// --- WebhookDelivery ---

func (f *fakeRepo) CreateWebhookDelivery(_ context.Context, _ domain.NewWebhookDelivery) error {
	return nil
}
func (f *fakeRepo) ListWebhookDeliveriesByWebhookID(_ context.Context, _ string, _ int) ([]*domain.WebhookDelivery, error) {
	return nil, nil
}

var _ repo.Repository = (*fakeRepo)(nil)

// ---------------------------------------------------------------------------

func TestRequireAuth_Cookie(t *testing.T) {
	r := newFakeRepo()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	user, err := r.CreateUser(ctx, domain.NewUser{
		ID:        uuid.NewString(),
		Email:     "alice@example.com",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	raw, _, err := auth.IssueSession(ctx, r, user.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	mw := New(r, Config{CookieName: "yauth_session"})

	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		au, ok := AuthUserFromContext(req.Context())
		if !ok {
			t.Errorf("expected AuthUser in context")
			http.Error(w, "no auth", http.StatusInternalServerError)
			return
		}
		if au.User.Email != "alice@example.com" {
			t.Errorf("unexpected email: %q", au.User.Email)
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Authenticated hit
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rec.Code, rec.Body.String())
	}

	// No cookie
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec2.Code)
	}

	// Garbage cookie
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.AddCookie(&http.Cookie{Name: "yauth_session", Value: "not-a-real-token"})
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad cookie, got %d", rec3.Code)
	}
}

func TestOptionalAuth_PassesThrough(t *testing.T) {
	r := newFakeRepo()
	mw := New(r, Config{CookieName: "yauth_session"})

	handler := mw.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, ok := AuthUserFromContext(req.Context())
		if ok {
			t.Errorf("expected no AuthUser when no cookie present")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("OptionalAuth should always proceed, got %d", rec.Code)
	}
}

func TestRequireAdmin(t *testing.T) {
	r := newFakeRepo()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	admin, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "admin@example.com", Role: "admin",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser admin: %v", err)
	}
	user, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "user@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser user: %v", err)
	}

	adminTok, _, err := auth.IssueSession(ctx, r, admin.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue admin session: %v", err)
	}
	userTok, _, err := auth.IssueSession(ctx, r, user.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue user session: %v", err)
	}

	mw := New(r, Config{CookieName: "yauth_session"})
	handler := mw.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Admin → 200
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminTok})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin: expected 200, got %d", rec.Code)
	}

	// Non-admin user → 403
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "yauth_session", Value: userTok})
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("regular user: expected 403, got %d", rec2.Code)
	}

	// No cookie → 401
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: expected 401, got %d", rec3.Code)
	}
}

// fakeResolver lets us drive the AuthResolver iteration in ResolveAuth.
type fakeResolver struct {
	name       string
	user       *domain.AuthUser
	recognized bool
	err        error
}

func (f *fakeResolver) Name() string { return f.name }
func (f *fakeResolver) Resolve(_ *http.Request) (*domain.AuthUser, bool, error) {
	return f.user, f.recognized, f.err
}

func TestResolveAuth_FallsThroughResolvers(t *testing.T) {
	r := newFakeRepo()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	u, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "x@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	au := &domain.AuthUser{User: u}

	skip := &fakeResolver{name: "skip", recognized: false}
	hit := &fakeResolver{name: "hit", recognized: true, user: au}
	never := &fakeResolver{name: "never", recognized: true, err: errors.New("must not be called")}

	mw := New(r, Config{CookieName: "yauth_session"}, skip, hit, never)
	got, err := mw.ResolveAuth(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("ResolveAuth: %v", err)
	}
	if got != au {
		t.Fatalf("expected hit's AuthUser to win")
	}
}

func TestResolveAuth_RecognizedErrorShortCircuits(t *testing.T) {
	r := newFakeRepo()
	bad := &fakeResolver{name: "bad", recognized: true, err: yautherr.ErrInvalidToken}
	never := &fakeResolver{name: "never", recognized: true, err: errors.New("must not be called")}

	mw := New(r, Config{CookieName: "yauth_session"}, bad, never)
	_, err := mw.ResolveAuth(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, yautherr.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

// auditCapturingRepo wraps fakeRepo to record audit log writes so
// session-binding tests can assert on them without poking at internal
// state.
type auditCapturingRepo struct {
	*fakeRepo
	audits []domain.NewAuditLog
}

func (a *auditCapturingRepo) LogAuditEvent(ctx context.Context, in domain.NewAuditLog) error {
	a.audits = append(a.audits, in)
	return a.fakeRepo.LogAuditEvent(ctx, in)
}

func setupBindingHarness(t *testing.T, sessIP, sessUA string) (*auditCapturingRepo, string, string) {
	t.Helper()
	r := newFakeRepo()
	cap := &auditCapturingRepo{fakeRepo: r}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	user, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "alice@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var ipPtr, uaPtr *string
	if sessIP != "" {
		ipPtr = &sessIP
	}
	if sessUA != "" {
		uaPtr = &sessUA
	}
	raw, _, err := auth.IssueSession(ctx, r, user.ID, ipPtr, uaPtr, time.Hour)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	tokenHash := auth.HashToken(raw)
	return cap, raw, tokenHash
}

func TestRequireAuth_BindIP_Match(t *testing.T) {
	cap, raw, _ := setupBindingHarness(t, "203.0.113.10", "")
	mw := New(cap, Config{CookieName: "yauth_session", BindIP: true, IPMismatchAction: MismatchActionInvalidate})

	hit := false
	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:55555"
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("matched IP should pass, got %d", rec.Code)
	}
	if !hit {
		t.Fatalf("expected handler to be called")
	}
	if len(cap.audits) != 0 {
		t.Errorf("expected zero audits on match, got %d", len(cap.audits))
	}
}

func TestRequireAuth_BindIP_Warn(t *testing.T) {
	cap, raw, _ := setupBindingHarness(t, "203.0.113.10", "")
	mw := New(cap, Config{CookieName: "yauth_session", BindIP: true, IPMismatchAction: MismatchActionWarn})

	hit := false
	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.99:55555"
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("warn-mode mismatch should still pass, got %d", rec.Code)
	}
	if !hit {
		t.Fatalf("expected handler to run on warn-mode mismatch")
	}
	if len(cap.audits) != 1 || cap.audits[0].EventType != "session_ip_mismatch" {
		t.Fatalf("expected one session_ip_mismatch audit, got %+v", cap.audits)
	}
}

func TestRequireAuth_BindIP_Invalidate(t *testing.T) {
	cap, raw, tokenHash := setupBindingHarness(t, "203.0.113.10", "")
	mw := New(cap, Config{CookieName: "yauth_session", BindIP: true, IPMismatchAction: MismatchActionInvalidate})

	hit := false
	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.99:55555"
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalidate-mode mismatch should 401, got %d", rec.Code)
	}
	if hit {
		t.Fatalf("handler must not run on invalidated session")
	}
	if _, ok := cap.fakeRepo.sessions[tokenHash]; ok {
		t.Fatalf("session row should be deleted on invalidate")
	}
	if len(cap.audits) != 1 || cap.audits[0].EventType != "session_ip_mismatch_invalidate" {
		t.Fatalf("expected session_ip_mismatch_invalidate audit, got %+v", cap.audits)
	}
}

func TestRequireAuth_BindUA_Mismatch(t *testing.T) {
	cap, raw, tokenHash := setupBindingHarness(t, "", "Mozilla/5.0 (legit)")
	mw := New(cap, Config{CookieName: "yauth_session", BindUA: true, UAMismatchAction: MismatchActionInvalidate})

	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:1"
	req.Header.Set("User-Agent", "curl/8.0 (attacker)")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("UA mismatch with invalidate should 401, got %d", rec.Code)
	}
	if _, ok := cap.fakeRepo.sessions[tokenHash]; ok {
		t.Fatalf("session row should be deleted on UA-invalidate")
	}
	if len(cap.audits) != 1 || cap.audits[0].EventType != "session_ua_mismatch_invalidate" {
		t.Fatalf("expected session_ua_mismatch_invalidate audit, got %+v", cap.audits)
	}
}

func TestRequireAuth_BindIP_NilSessionIPSkipsCheck(t *testing.T) {
	// Sessions issued before binding was enabled may have a nil IPAddress.
	// The middleware must not invalidate them just because the session
	// row pre-dates the policy.
	cap, raw, _ := setupBindingHarness(t, "", "")
	mw := New(cap, Config{CookieName: "yauth_session", BindIP: true, IPMismatchAction: MismatchActionInvalidate})

	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:1"
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("nil session IP should skip binding check, got %d", rec.Code)
	}
	if len(cap.audits) != 0 {
		t.Errorf("expected no audits when session IP is nil, got %d", len(cap.audits))
	}
}
