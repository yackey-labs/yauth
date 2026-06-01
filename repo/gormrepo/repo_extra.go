package gormrepo

import (
	"context"
	"errors"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// withRowLock wraps q with a SELECT … FOR UPDATE locking clause when the
// connection is Postgres or MySQL. SQLite serializes writes via a global lock,
// so the hint is a no-op there.
func withRowLock(q *gorm.DB) *gorm.DB {
	switch q.Dialector.Name() {
	case "postgres", "mysql":
		return q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return q
}

// keyEq returns a Where-clause-friendly predicate for the column named
// `key`. `key` is a reserved word in MySQL so the raw SQL needs the
// dialect-appropriate identifier quote (backticks on MySQL, double
// quotes on Postgres). Postgres accepts the unquoted form too, but
// being explicit keeps the helper trivially correct on every dialect.
func keyEq(db *gorm.DB) string {
	if db.Dialector.Name() == "mysql" {
		return "`key` = ?"
	}
	return `"key" = ?`
}

// --- User extras ---

func (r *Repo) AnyUserExists(ctx context.Context) (bool, error) {
	var count int64
	if err := r.ctx(ctx).Model(&User{}).Limit(1).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *Repo) ListUsers(ctx context.Context, search string, limit, offset int) ([]*domain.User, int64, error) {
	q := r.ctx(ctx).Model(&User{})
	if search != "" {
		// Case-insensitive substring on email or display_name.
		like := "%" + search + "%"
		q = q.Where("LOWER(email) LIKE LOWER(?) OR LOWER(COALESCE(display_name, '')) LIKE LOWER(?)", like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := q.Order("created_at DESC")
	if limit > 0 {
		page = page.Limit(limit)
	}
	if offset > 0 {
		page = page.Offset(offset)
	}

	var rows []User
	if err := page.Find(&rows).Error; err != nil {
		return nil, 0, err
	}

	out := make([]*domain.User, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, total, nil
}

// --- Session extras ---

func (r *Repo) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	var m Session
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) DeleteSessionByID(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&Session{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteOtherUserSessions(ctx context.Context, userID, keepTokenHash string) (int64, error) {
	res := r.ctx(ctx).Where("user_id = ? AND token_hash <> ?", userID, keepTokenHash).Delete(&Session{})
	return res.RowsAffected, res.Error
}

func (r *Repo) ListSessions(ctx context.Context, filters domain.ListSessionsFilters) ([]*domain.Session, int64, error) {
	q := r.ctx(ctx).Model(&Session{})
	if filters.UserID != nil && *filters.UserID != "" {
		q = q.Where("user_id = ?", *filters.UserID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	page := q.Order("created_at DESC")
	if filters.Limit > 0 {
		page = page.Limit(filters.Limit)
	}
	if filters.Offset > 0 {
		page = page.Offset(filters.Offset)
	}
	var rows []Session
	if err := page.Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]*domain.Session, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, total, nil
}

// --- EmailVerification extras ---

func (r *Repo) DeleteEmailVerification(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&EmailVerification{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteEmailVerificationsForUser(ctx context.Context, userID string) (int64, error) {
	res := r.ctx(ctx).Where("user_id = ?", userID).Delete(&EmailVerification{})
	return res.RowsAffected, res.Error
}

// --- PasswordReset extras ---

func (r *Repo) DeleteUnusedPasswordResetsForUser(ctx context.Context, userID string) (int64, error) {
	res := r.ctx(ctx).Where("user_id = ? AND used_at IS NULL", userID).Delete(&PasswordReset{})
	return res.RowsAffected, res.Error
}

// --- AuditLog list ---

func (r *Repo) ListAuditLog(ctx context.Context, filters domain.ListAuditFilters) ([]*domain.AuditLog, error) {
	q := r.ctx(ctx).Model(&AuditLog{})
	if filters.UserID != nil {
		q = q.Where("user_id = ?", *filters.UserID)
	}
	if filters.EventType != nil {
		q = q.Where("event_type = ?", *filters.EventType)
	}
	q = q.Order("created_at DESC")
	if filters.Limit > 0 {
		q = q.Limit(filters.Limit)
	}
	if filters.Offset > 0 {
		q = q.Offset(filters.Offset)
	}
	var rows []AuditLog
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.AuditLog, len(rows))
	for i := range rows {
		var meta []byte
		if rows[i].Metadata != nil {
			meta = []byte(*rows[i].Metadata)
		}
		d := domain.AuditLog{
			ID:        rows[i].ID,
			UserID:    rows[i].UserID,
			EventType: rows[i].EventType,
			Metadata:  meta,
			IPAddress: rows[i].IPAddress,
			CreatedAt: rows[i].CreatedAt.UTC(),
		}
		out[i] = &d
	}
	return out, nil
}

// --- Challenge ---

func (r *Repo) SetChallenge(ctx context.Context, key, value string, ttl time.Duration) error {
	expires := time.Now().UTC().Add(ttl)
	m := Challenge{Key: key, Value: value, ExpiresAt: expires}
	return r.ctx(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "expires_at"}),
	}).Create(&m).Error
}

func (r *Repo) GetChallenge(ctx context.Context, key string) (*domain.Challenge, error) {
	db := r.ctx(ctx)
	var m Challenge
	if err := db.Where(keyEq(db), key).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		_ = db.Where(keyEq(db), key).Delete(&Challenge{}).Error
		return nil, yautherr.ErrNotFound
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ConsumeChallenge(ctx context.Context, key string) (*domain.Challenge, error) {
	var out *domain.Challenge
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m Challenge
		if err := withRowLock(tx).Where(keyEq(tx), key).First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		if err := tx.Where(keyEq(tx), key).Delete(&Challenge{}).Error; err != nil {
			return err
		}
		if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
			return yautherr.ErrNotFound
		}
		d := m.toDomain()
		out = &d
		return nil
	})
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

func (r *Repo) DeleteChallenge(ctx context.Context, key string) error {
	db := r.ctx(ctx)
	return db.Where(keyEq(db), key).Delete(&Challenge{}).Error
}

// --- RateLimit ---

func (r *Repo) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (domain.RateLimitResult, error) {
	now := time.Now().UTC()
	windowStart := now.Add(-window)
	allow := domain.RateLimitResult{Allowed: true, Remaining: limit, RetryAfter: 0}

	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m RateLimit
		err := withRowLock(tx).Where(keyEq(tx), key).First(&m).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			row := RateLimit{Key: key, Count: 1, WindowStart: now}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
			allow.Remaining = limit - 1
			if allow.Remaining < 0 {
				allow.Remaining = 0
			}
			return nil
		}
		if err != nil {
			return err
		}

		if m.WindowStart.UTC().Before(windowStart) {
			if err := tx.Model(&RateLimit{}).Where(keyEq(tx), key).
				Updates(map[string]any{"count": 1, "window_start": now}).Error; err != nil {
				return err
			}
			allow.Remaining = limit - 1
			if allow.Remaining < 0 {
				allow.Remaining = 0
			}
			return nil
		}

		if m.Count >= limit {
			retry := window - now.Sub(m.WindowStart.UTC())
			if retry < 0 {
				retry = 0
			}
			allow = domain.RateLimitResult{
				Allowed:    false,
				Remaining:  0,
				RetryAfter: retry,
			}
			return nil
		}

		newCount := m.Count + 1
		if err := tx.Model(&RateLimit{}).Where(keyEq(tx), key).
			Update("count", newCount).Error; err != nil {
			return err
		}
		allow.Remaining = limit - newCount
		if allow.Remaining < 0 {
			allow.Remaining = 0
		}
		return nil
	})
	if err != nil {
		// Fail-open: on internal error, allow the request.
		return domain.RateLimitResult{Allowed: true, Remaining: limit, RetryAfter: 0}, nil
	}
	return allow, nil
}

// --- Revocation ---

func (r *Repo) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	expires := time.Now().UTC().Add(ttl)
	m := Revocation{Key: jti, ExpiresAt: expires}
	return r.ctx(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"expires_at"}),
	}).Create(&m).Error
}

func (r *Repo) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	db := r.ctx(ctx)
	var m Revocation
	err := db.Where(keyEq(db), jti).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		_ = db.Where(keyEq(db), jti).Delete(&Revocation{}).Error
		return false, nil
	}
	return true, nil
}

// --- MagicLink ---

func (r *Repo) CreateMagicLink(ctx context.Context, input domain.NewMagicLink) error {
	m := magicLinkFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetUnusedMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*domain.MagicLink, error) {
	var m MagicLink
	err := r.ctx(ctx).Where("token_hash = ? AND used = ?", tokenHash, false).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ConsumeMagicLink(ctx context.Context, tokenHash string) (*domain.MagicLink, error) {
	var out *domain.MagicLink
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m MagicLink
		err := withRowLock(tx).Where("token_hash = ?", tokenHash).First(&m).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return yautherr.ErrNotFound
		}
		if err != nil {
			return err
		}
		if m.Used {
			return yautherr.ErrNotFound
		}
		if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
			return yautherr.ErrNotFound
		}
		if err := tx.Model(&MagicLink{}).Where("id = ? AND used = ?", m.ID, false).
			Update("used", true).Error; err != nil {
			return err
		}
		m.Used = true
		d := m.toDomain()
		out = &d
		return nil
	})
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

func (r *Repo) MarkMagicLinkUsed(ctx context.Context, id string) error {
	res := r.ctx(ctx).Model(&MagicLink{}).Where("id = ?", id).Update("used", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteMagicLink(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&MagicLink{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteUnusedMagicLinksForEmail(ctx context.Context, email string) (int64, error) {
	res := r.ctx(ctx).Where("email = ? AND used = ?", email, false).Delete(&MagicLink{})
	return res.RowsAffected, res.Error
}

// --- Passkey ---

func (r *Repo) GetPasskeysByUserID(ctx context.Context, userID string) ([]*domain.WebauthnCredential, error) {
	var rows []WebauthnCredential
	if err := r.ctx(ctx).Where("user_id = ?", userID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.WebauthnCredential, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) GetPasskeyByIDAndUser(ctx context.Context, id, userID string) (*domain.WebauthnCredential, error) {
	var m WebauthnCredential
	err := r.ctx(ctx).Where("id = ? AND user_id = ?", id, userID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) CreatePasskey(ctx context.Context, input domain.NewWebauthnCredential) error {
	m := webauthnCredentialFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) UpdatePasskeyLastUsed(ctx context.Context, id string, at time.Time) error {
	res := r.ctx(ctx).Model(&WebauthnCredential{}).Where("id = ?", id).Update("last_used_at", at.UTC())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeletePasskey(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&WebauthnCredential{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- TOTP ---

func (r *Repo) GetTOTPByUserID(ctx context.Context, userID string, verifiedOnly *bool) (*domain.TOTPSecret, error) {
	q := r.ctx(ctx).Where("user_id = ?", userID)
	if verifiedOnly != nil {
		q = q.Where("verified = ?", *verifiedOnly)
	}
	var m TOTPSecret
	err := q.First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) CreateTOTP(ctx context.Context, input domain.NewTOTPSecret) error {
	m := totpFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) MarkTOTPVerified(ctx context.Context, id string) error {
	res := r.ctx(ctx).Model(&TOTPSecret{}).Where("id = ?", id).Update("verified", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteTOTPForUser(ctx context.Context, userID string, verifiedOnly *bool) (int64, error) {
	q := r.ctx(ctx).Where("user_id = ?", userID)
	if verifiedOnly != nil {
		q = q.Where("verified = ?", *verifiedOnly)
	}
	res := q.Delete(&TOTPSecret{})
	return res.RowsAffected, res.Error
}

// --- BackupCode ---

func (r *Repo) GetUnusedBackupCodesByUserID(ctx context.Context, userID string) ([]*domain.BackupCode, error) {
	var rows []BackupCode
	if err := r.ctx(ctx).Where("user_id = ? AND used = ?", userID, false).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.BackupCode, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) CreateBackupCode(ctx context.Context, input domain.NewBackupCode) error {
	m := backupCodeFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) MarkBackupCodeUsed(ctx context.Context, id string) error {
	res := r.ctx(ctx).Model(&BackupCode{}).Where("id = ? AND used = ?", id, false).Update("used", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteAllBackupCodesForUser(ctx context.Context, userID string) (int64, error) {
	res := r.ctx(ctx).Where("user_id = ?", userID).Delete(&BackupCode{})
	return res.RowsAffected, res.Error
}

// --- OAuthAccount ---

func (r *Repo) GetOAuthAccountByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error) {
	var m OAuthAccount
	err := r.ctx(ctx).Where("provider = ? AND provider_user_id = ?", provider, providerUserID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*domain.OAuthAccount, error) {
	var rows []OAuthAccount
	if err := r.ctx(ctx).Where("user_id = ?", userID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.OAuthAccount, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) GetOAuthAccountByUserAndProvider(ctx context.Context, userID, provider string) (*domain.OAuthAccount, error) {
	var m OAuthAccount
	err := r.ctx(ctx).Where("user_id = ? AND provider = ?", userID, provider).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) CreateOAuthAccount(ctx context.Context, input domain.NewOAuthAccount) error {
	m := oauthAccountFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) UpdateOAuthAccountTokens(ctx context.Context, id string, accessTokenEnc, refreshTokenEnc *string, expiresAt *time.Time, updatedAt time.Time) error {
	updates := map[string]any{
		"access_token_enc":  accessTokenEnc,
		"refresh_token_enc": refreshTokenEnc,
		"updated_at":        updatedAt.UTC(),
	}
	if expiresAt != nil {
		u := expiresAt.UTC()
		updates["expires_at"] = &u
	} else {
		updates["expires_at"] = nil
	}
	res := r.ctx(ctx).Model(&OAuthAccount{}).Where("id = ?", id).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteOAuthAccount(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&OAuthAccount{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- OAuthState ---

func (r *Repo) CreateOAuthState(ctx context.Context, input domain.NewOAuthState) error {
	m := oauthStateFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) ConsumeOAuthState(ctx context.Context, state string) (*domain.OAuthState, error) {
	var out *domain.OAuthState
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m OAuthState
		err := withRowLock(tx).Where("state = ?", state).First(&m).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return yautherr.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := tx.Where("state = ?", state).Delete(&OAuthState{}).Error; err != nil {
			return err
		}
		if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
			return yautherr.ErrNotFound
		}
		d := m.toDomain()
		out = &d
		return nil
	})
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

// --- RefreshToken ---

func (r *Repo) CreateRefreshToken(ctx context.Context, input domain.NewRefreshToken) error {
	m := refreshTokenFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	var m RefreshToken
	err := r.ctx(ctx).Where("token_hash = ?", tokenHash).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) RevokeRefreshToken(ctx context.Context, id string) error {
	res := r.ctx(ctx).Model(&RefreshToken{}).Where("id = ?", id).Update("revoked", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) RevokeRefreshTokenFamily(ctx context.Context, familyID string) (int64, error) {
	res := r.ctx(ctx).Model(&RefreshToken{}).Where("family_id = ? AND revoked = ?", familyID, false).Update("revoked", true)
	return res.RowsAffected, res.Error
}

// --- APIKey ---

// validateAPIKeyOwner enforces the "exactly one of UserID /
// OrganizationID is set" invariant (yauth #91 / yauth-go #19).
func validateAPIKeyOwner(in domain.NewAPIKey) error {
	hasUser := in.UserID != nil && *in.UserID != ""
	hasOrg := in.OrganizationID != nil && *in.OrganizationID != ""
	if hasUser == hasOrg {
		return yautherr.ErrInvalidRequest
	}
	return nil
}

func (r *Repo) CreateAPIKey(ctx context.Context, input domain.NewAPIKey) error {
	if err := validateAPIKeyOwner(input); err != nil {
		return err
	}
	m := apiKeyFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*domain.APIKey, error) {
	var m APIKey
	err := r.ctx(ctx).Where("key_prefix = ?", prefix).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if m.ExpiresAt != nil && !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*domain.APIKey, error) {
	var m APIKey
	err := r.ctx(ctx).Where("id = ? AND user_id = ?", id, userID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetAPIKeyByIDAndOrg(ctx context.Context, id, organizationID string) (*domain.APIKey, error) {
	var m APIKey
	err := r.ctx(ctx).Where("id = ? AND organization_id = ?", id, organizationID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*domain.APIKey, error) {
	var rows []APIKey
	if err := r.ctx(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.APIKey, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) ListAPIKeysByOrgID(ctx context.Context, organizationID string) ([]*domain.APIKey, error) {
	var rows []APIKey
	if err := r.ctx(ctx).Where("organization_id = ?", organizationID).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.APIKey, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) UpdateAPIKeyLastUsed(ctx context.Context, id string, at time.Time) error {
	res := r.ctx(ctx).Model(&APIKey{}).Where("id = ?", id).Update("last_used_at", at.UTC())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) SetAPIKeyExpiry(ctx context.Context, id string, expiresAt *time.Time) error {
	var val *time.Time
	if expiresAt != nil {
		v := expiresAt.UTC()
		val = &v
	}
	res := r.ctx(ctx).Model(&APIKey{}).Where("id = ?", id).Update("expires_at", val)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteAPIKey(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&APIKey{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- OAuth2Client ---

func (r *Repo) CreateOAuth2Client(ctx context.Context, input domain.NewOAuth2Client) error {
	m := oauth2ClientFromDomain(input)
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return yautherr.ErrConflict
		}
		return err
	}
	return nil
}

func (r *Repo) GetOAuth2ClientByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	var m OAuth2Client
	err := r.ctx(ctx).Where("client_id = ?", clientID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) SetOAuth2ClientBanned(ctx context.Context, clientID string, bannedAt *time.Time, reason *string) (bool, error) {
	updates := map[string]any{
		"banned_reason": reason,
	}
	if bannedAt != nil {
		u := bannedAt.UTC()
		updates["banned_at"] = &u
	} else {
		updates["banned_at"] = nil
	}
	res := r.ctx(ctx).Model(&OAuth2Client{}).Where("client_id = ?", clientID).Updates(updates)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *Repo) RotateOAuth2ClientPublicKey(ctx context.Context, clientID string, publicKeyPEM *string) (bool, error) {
	res := r.ctx(ctx).Model(&OAuth2Client{}).Where("client_id = ?", clientID).Update("public_key_pem", publicKeyPEM)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *Repo) ListBannedOAuth2Clients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	var rows []OAuth2Client
	if err := r.ctx(ctx).Where("banned_at IS NOT NULL").Order("banned_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.OAuth2Client, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) ListOAuth2Clients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	var rows []OAuth2Client
	if err := r.ctx(ctx).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.OAuth2Client, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

// --- AuthorizationCode ---

func (r *Repo) CreateAuthorizationCode(ctx context.Context, input domain.NewAuthorizationCode) error {
	m := authorizationCodeFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	var m AuthorizationCode
	err := r.ctx(ctx).Where("code_hash = ?", codeHash).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if m.Used {
		return nil, yautherr.ErrNotFound
	}
	if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	var out *domain.AuthorizationCode
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m AuthorizationCode
		err := withRowLock(tx).Where("code_hash = ?", codeHash).First(&m).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return yautherr.ErrNotFound
		}
		if err != nil {
			return err
		}
		if m.Used {
			return yautherr.ErrNotFound
		}
		if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
			return yautherr.ErrNotFound
		}
		if err := tx.Model(&AuthorizationCode{}).Where("id = ? AND used = ?", m.ID, false).
			Update("used", true).Error; err != nil {
			return err
		}
		m.Used = true
		d := m.toDomain()
		out = &d
		return nil
	})
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

func (r *Repo) MarkAuthorizationCodeUsed(ctx context.Context, id string) error {
	res := r.ctx(ctx).Model(&AuthorizationCode{}).Where("id = ?", id).Update("used", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- Consent ---

func (r *Repo) CreateConsent(ctx context.Context, input domain.NewConsent) error {
	m := consentFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetConsentByUserAndClient(ctx context.Context, userID, clientID string) (*domain.Consent, error) {
	var m Consent
	err := r.ctx(ctx).Where("user_id = ? AND client_id = ?", userID, clientID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) UpdateConsentScopes(ctx context.Context, id string, scopes []byte) error {
	var v *string
	if len(scopes) > 0 {
		s := string(scopes)
		v = &s
	}
	res := r.ctx(ctx).Model(&Consent{}).Where("id = ?", id).Update("scopes", v)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- DeviceCode ---

func (r *Repo) CreateDeviceCode(ctx context.Context, input domain.NewDeviceCode) error {
	m := deviceCodeFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetDeviceCodeByUserCodePending(ctx context.Context, userCode string) (*domain.DeviceCode, error) {
	var m DeviceCode
	err := r.ctx(ctx).Where("user_code = ? AND status = ?", userCode, "pending").First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetDeviceCodeByDeviceCodeHash(ctx context.Context, deviceCodeHash string) (*domain.DeviceCode, error) {
	var m DeviceCode
	err := r.ctx(ctx).Where("device_code_hash = ?", deviceCodeHash).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	updates := map[string]any{"status": status}
	if userID != nil {
		updates["user_id"] = userID
	}
	res := r.ctx(ctx).Model(&DeviceCode{}).Where("id = ?", id).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) UpdateDeviceCodeLastPolled(ctx context.Context, id string, at time.Time) error {
	res := r.ctx(ctx).Model(&DeviceCode{}).Where("id = ?", id).Update("last_polled_at", at.UTC())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) UpdateDeviceCodeInterval(ctx context.Context, id string, interval int) error {
	res := r.ctx(ctx).Model(&DeviceCode{}).Where("id = ?", id).Update("interval", interval)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- OIDCNonce ---

func (r *Repo) CreateOIDCNonce(ctx context.Context, input domain.NewOIDCNonce) error {
	m := oidcNonceFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetOIDCNonceByHash(ctx context.Context, nonceHash string) (*domain.OIDCNonce, error) {
	var m OIDCNonce
	err := r.ctx(ctx).Where("nonce_hash = ?", nonceHash).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) DeleteOIDCNonce(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&OIDCNonce{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- AccountLock ---

func (r *Repo) GetAccountLockByUserID(ctx context.Context, userID string) (*domain.AccountLock, error) {
	var m AccountLock
	err := r.ctx(ctx).Where("user_id = ?", userID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) CreateAccountLock(ctx context.Context, input domain.NewAccountLock) (domain.AccountLock, error) {
	m := accountLockFromDomain(input)
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		return domain.AccountLock{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) IncrementAccountLockFailedCount(ctx context.Context, id string, updatedAt time.Time) error {
	res := r.ctx(ctx).Model(&AccountLock{}).Where("id = ?", id).Updates(map[string]any{
		"failed_count": gorm.Expr("failed_count + 1"),
		"updated_at":   updatedAt.UTC(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) SetAccountLockState(ctx context.Context, id string, state domain.LockState, updatedAt time.Time) error {
	updates := map[string]any{
		"locked_reason": state.LockedReason,
		"lock_count":    state.LockCount,
		"updated_at":    updatedAt.UTC(),
	}
	if state.LockedUntil != nil {
		u := state.LockedUntil.UTC()
		updates["locked_until"] = &u
	} else {
		updates["locked_until"] = nil
	}
	res := r.ctx(ctx).Model(&AccountLock{}).Where("id = ?", id).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) ResetAccountLockFailedCount(ctx context.Context, id string, updatedAt time.Time) error {
	res := r.ctx(ctx).Model(&AccountLock{}).Where("id = ?", id).Updates(map[string]any{
		"failed_count": 0,
		"updated_at":   updatedAt.UTC(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) AutoUnlockAccount(ctx context.Context, id string, updatedAt time.Time) error {
	res := r.ctx(ctx).Model(&AccountLock{}).Where("id = ?", id).Updates(map[string]any{
		"locked_until":  nil,
		"locked_reason": nil,
		"updated_at":    updatedAt.UTC(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- UnlockToken ---

func (r *Repo) CreateUnlockToken(ctx context.Context, input domain.NewUnlockToken) error {
	m := unlockTokenFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetUnlockTokenByHash(ctx context.Context, tokenHash string) (*domain.UnlockToken, error) {
	var m UnlockToken
	err := r.ctx(ctx).Where("token_hash = ?", tokenHash).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ConsumeUnlockToken(ctx context.Context, tokenHash string) (*domain.UnlockToken, error) {
	var out *domain.UnlockToken
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m UnlockToken
		err := withRowLock(tx).Where("token_hash = ?", tokenHash).First(&m).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return yautherr.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := tx.Where("id = ?", m.ID).Delete(&UnlockToken{}).Error; err != nil {
			return err
		}
		if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
			return yautherr.ErrNotFound
		}
		d := m.toDomain()
		out = &d
		return nil
	})
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

func (r *Repo) DeleteUnlockToken(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&UnlockToken{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteAllUnlockTokensForUser(ctx context.Context, userID string) (int64, error) {
	res := r.ctx(ctx).Where("user_id = ?", userID).Delete(&UnlockToken{})
	return res.RowsAffected, res.Error
}

// --- Webhook ---

func (r *Repo) CreateWebhook(ctx context.Context, input domain.NewWebhook) error {
	m := webhookFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetWebhookByID(ctx context.Context, id string) (*domain.Webhook, error) {
	var m Webhook
	err := r.ctx(ctx).Where("id = ?", id).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, yautherr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) ListActiveWebhooks(ctx context.Context) ([]*domain.Webhook, error) {
	var rows []Webhook
	if err := r.ctx(ctx).Where("active = ?", true).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Webhook, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) ListWebhooks(ctx context.Context) ([]*domain.Webhook, error) {
	var rows []Webhook
	if err := r.ctx(ctx).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Webhook, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) UpdateWebhook(ctx context.Context, id string, changes domain.UpdateWebhook) (domain.Webhook, error) {
	updates := map[string]any{}
	if changes.URL != nil {
		updates["url"] = *changes.URL
	}
	if changes.Secret != nil {
		updates["secret"] = *changes.Secret
	}
	if changes.Events != nil {
		updates["events"] = string(*changes.Events)
	}
	if changes.Active != nil {
		updates["active"] = *changes.Active
	}
	if changes.UpdatedAt != nil {
		updates["updated_at"] = changes.UpdatedAt.UTC()
	}

	if len(updates) > 0 {
		res := r.ctx(ctx).Model(&Webhook{}).Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			return domain.Webhook{}, res.Error
		}
		if res.RowsAffected == 0 {
			return domain.Webhook{}, yautherr.ErrNotFound
		}
	}

	var m Webhook
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.Webhook{}, yautherr.ErrNotFound
		}
		return domain.Webhook{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteWebhook(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&Webhook{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- WebhookDelivery ---

func (r *Repo) CreateWebhookDelivery(ctx context.Context, input domain.NewWebhookDelivery) error {
	m := webhookDeliveryFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) ListWebhookDeliveriesByWebhookID(ctx context.Context, webhookID string, limit int) ([]*domain.WebhookDelivery, error) {
	q := r.ctx(ctx).Where("webhook_id = ?", webhookID).Order("created_at DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []WebhookDelivery
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.WebhookDelivery, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

// --- WebhookRetry ---

func (r *Repo) CreateScheduledRetry(ctx context.Context, input domain.NewScheduledWebhookRetry) error {
	m := webhookRetryFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

// ClaimDueRetries selects up to limit due rows, deletes them in the
// same transaction, and returns the deleted rows. The locking strategy
// per dialect:
//
//   - Postgres / MySQL 8+: SELECT … FOR UPDATE SKIP LOCKED so two
//     concurrent dispatchers never see the same row.
//   - SQLite: the surrounding Transaction() takes a RESERVED then EXCLUSIVE
//     lock on commit, which is enough to serialise claimers on the
//     single-writer engine.
//
// On any backend, deleting in the same tx as the SELECT means a row
// can only be returned to one caller — even if a future caller reuses
// the same not_before, it'll find no rows.
func (r *Repo) ClaimDueRetries(ctx context.Context, now time.Time, limit int) ([]*domain.ScheduledWebhookRetry, error) {
	if limit <= 0 {
		return nil, nil
	}
	var claimed []WebhookRetry
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		q := tx.Where("not_before <= ?", now.UTC()).
			Order("not_before ASC, id ASC").
			Limit(limit)
		switch tx.Dialector.Name() {
		case "postgres", "mysql":
			q = q.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
		}
		var rows []WebhookRetry
		if err := q.Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		ids := make([]string, len(rows))
		for i := range rows {
			ids[i] = rows[i].ID
		}
		if err := tx.Where("id IN ?", ids).Delete(&WebhookRetry{}).Error; err != nil {
			return err
		}
		claimed = rows
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ScheduledWebhookRetry, len(claimed))
	for i := range claimed {
		d := claimed[i].toDomain()
		out[i] = &d
	}
	return out, nil
}

func (r *Repo) DeleteScheduledRetry(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&WebhookRetry{})
	return res.Error
}
