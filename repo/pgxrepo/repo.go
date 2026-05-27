// Package pgxrepo provides a sqlc + pgx/v5-backed implementation of
// repo.Repository for PostgreSQL. Migrations are managed by goose via the
// migrate package. Use pgxrepo.Open to create a pool, then pgxrepo.New to
// build the repo.
package pgxrepo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yackey-labs/yauth-go/domain"
	yauthrepo "github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/repo/pgxrepo/gen"
	"github.com/yackey-labs/yauth-go/yautherr"
)

var _ yauthrepo.Repository = (*Repo)(nil)

// Repo is a pgx/v5 + sqlc-backed implementation of repo.Repository.
type Repo struct {
	pool *pgxpool.Pool
	q    *pgxgen.Queries
}

// New returns a Repo bound to the given pgxpool.
func New(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool, q: pgxgen.New(pool)}
}

// withTx runs fn inside a read-committed transaction, rolling back on error.
func (r *Repo) withTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// ─── User ────────────────────────────────────────────────────────────────────

func (r *Repo) CreateUser(ctx context.Context, input domain.NewUser) (domain.User, error) {
	row, err := r.q.CreateUser(ctx, pgxgen.CreateUserParams{
		ID:            input.ID,
		Email:         input.Email,
		DisplayName:   input.DisplayName,
		EmailVerified: input.EmailVerified,
		Role:          input.Role,
		Banned:        input.Banned,
		BannedReason:  input.BannedReason,
		BannedUntil:   tsPtr(input.BannedUntil),
		CreatedAt:     ts(input.CreatedAt),
		UpdatedAt:     ts(input.UpdatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.User{}, yautherr.ErrUserExists
		}
		return domain.User{}, err
	}
	return userToDomain(row), nil
}

func (r *Repo) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	row, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	u := userToDomain(row)
	return &u, nil
}

func (r *Repo) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	row, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, notFound(err)
	}
	u := userToDomain(row)
	return &u, nil
}

func (r *Repo) UpdateUser(ctx context.Context, id string, changes domain.UpdateUser) (domain.User, error) {
	now := time.Now().UTC()
	updatedAt := ts(now)
	if changes.UpdatedAt != nil {
		updatedAt = ts(*changes.UpdatedAt)
	}

	params := pgxgen.UpdateUserFullParams{
		ID:        id,
		UpdatedAt: updatedAt,
	}
	if changes.Email != nil {
		params.Email = changes.Email
	}
	if changes.DisplayName != nil {
		params.SetDisplayName = true
		params.DisplayName = *changes.DisplayName
	}
	if changes.EmailVerified != nil {
		params.EmailVerified = changes.EmailVerified
	}
	if changes.Role != nil {
		params.Role = changes.Role
	}
	if changes.Banned != nil {
		params.Banned = changes.Banned
	}
	if changes.BannedReason != nil {
		params.SetBannedReason = true
		params.BannedReason = *changes.BannedReason
	}
	if changes.BannedUntil != nil {
		params.SetBannedUntil = true
		params.BannedUntil = tsPtr(*changes.BannedUntil)
	}

	row, err := r.q.UpdateUserFull(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, yautherr.ErrNotFound
		}
		if isUniqueViolation(err) {
			return domain.User{}, yautherr.ErrUserExists
		}
		return domain.User{}, err
	}
	return userToDomain(row), nil
}

func (r *Repo) DeleteUser(ctx context.Context, id string) error {
	n, err := r.q.DeleteUser(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) AnyUserExists(ctx context.Context) (bool, error) {
	return r.q.AnyUserExists(ctx)
}

func (r *Repo) ListUsers(ctx context.Context, search string, limit, offset int) ([]*domain.User, int64, error) {
	rows, err := r.q.ListUsersSearch(ctx, pgxgen.ListUsersSearchParams{
		Column1: search,
		Column2: int32(limit),
		Column3: int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.q.CountUsersSearch(ctx, search)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*domain.User, len(rows))
	for i, row := range rows {
		u := userToDomain(row)
		out[i] = &u
	}
	return out, total, nil
}

// ─── Session ─────────────────────────────────────────────────────────────────

func (r *Repo) CreateSession(ctx context.Context, input domain.NewSession) error {
	return r.q.CreateSession(ctx, pgxgen.CreateSessionParams{
		ID:          input.ID,
		UserID:      input.UserID,
		TokenHash:   input.TokenHash,
		IpAddress:   input.IPAddress,
		UserAgent:   input.UserAgent,
		ActiveOrgID: input.ActiveOrgID,
		ExpiresAt:   ts(input.ExpiresAt),
		CreatedAt:   ts(input.CreatedAt),
	})
}

func (r *Repo) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	row, err := r.q.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, notFound(err)
	}
	s := sessionToDomain(row)
	return &s, nil
}

func (r *Repo) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	row, err := r.q.GetSessionByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	s := sessionToDomain(row)
	return &s, nil
}

func (r *Repo) DeleteSession(ctx context.Context, tokenHash string) (bool, error) {
	row, err := r.q.DeleteSession(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return row != "", nil
}

func (r *Repo) DeleteSessionByID(ctx context.Context, id string) error {
	n, err := r.q.DeleteSessionByID(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	return r.q.DeleteUserSessions(ctx, userID)
}

func (r *Repo) DeleteOtherUserSessions(ctx context.Context, userID, keepTokenHash string) (int64, error) {
	return r.q.DeleteOtherUserSessions(ctx, pgxgen.DeleteOtherUserSessionsParams{
		UserID:    userID,
		TokenHash: keepTokenHash,
	})
}

func (r *Repo) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	return r.q.DeleteExpiredSessions(ctx, ts(now))
}

func (r *Repo) SetSessionActiveOrg(ctx context.Context, sessionID string, activeOrgID *string) error {
	n, err := r.q.SetSessionActiveOrg(ctx, pgxgen.SetSessionActiveOrgParams{
		ID:          sessionID,
		ActiveOrgID: activeOrgID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) ListSessions(ctx context.Context, filters domain.ListSessionsFilters) ([]*domain.Session, int64, error) {
	var rows []pgxgen.YauthSession
	var total int64
	var err error

	if filters.UserID != nil && *filters.UserID != "" {
		rows, err = r.q.ListSessionsByUser(ctx, pgxgen.ListSessionsByUserParams{
			UserID:  *filters.UserID,
			Column2: int32(filters.Limit),
			Column3: int32(filters.Offset),
		})
		if err != nil {
			return nil, 0, err
		}
		total, err = r.q.CountSessionsByUser(ctx, *filters.UserID)
	} else {
		rows, err = r.q.ListAllSessions(ctx, pgxgen.ListAllSessionsParams{
			Column1: int32(filters.Limit),
			Column2: int32(filters.Offset),
		})
		if err != nil {
			return nil, 0, err
		}
		total, err = r.q.CountAllSessions(ctx)
	}
	if err != nil {
		return nil, 0, err
	}
	out := make([]*domain.Session, len(rows))
	for i, row := range rows {
		s := sessionToDomain(row)
		out[i] = &s
	}
	return out, total, nil
}

// ─── Password ────────────────────────────────────────────────────────────────

func (r *Repo) UpsertPassword(ctx context.Context, input domain.NewPassword) error {
	return r.q.UpsertPassword(ctx, pgxgen.UpsertPasswordParams{
		UserID:       input.UserID,
		PasswordHash: input.PasswordHash,
	})
}

func (r *Repo) GetPasswordByUserID(ctx context.Context, userID string) (*domain.Password, error) {
	row, err := r.q.GetPasswordByUserID(ctx, userID)
	if err != nil {
		return nil, notFound(err)
	}
	p := domain.Password{UserID: row.UserID, PasswordHash: row.PasswordHash}
	return &p, nil
}

func (r *Repo) AppendPasswordHistory(ctx context.Context, input domain.NewPasswordHistory) error {
	return r.q.AppendPasswordHistory(ctx, pgxgen.AppendPasswordHistoryParams{
		ID:           input.ID,
		UserID:       input.UserID,
		PasswordHash: input.PasswordHash,
		CreatedAt:    ts(input.CreatedAt),
	})
}

func (r *Repo) GetPasswordHistory(ctx context.Context, userID string, n int) ([]*domain.PasswordHistory, error) {
	if n <= 0 {
		return nil, nil
	}
	rows, err := r.q.GetPasswordHistory(ctx, pgxgen.GetPasswordHistoryParams{
		UserID: userID,
		Limit:  int32(n),
	})
	if err != nil {
		return nil, err
	}
	out := make([]*domain.PasswordHistory, len(rows))
	for i, row := range rows {
		ph := domain.PasswordHistory{
			ID:           row.ID,
			UserID:       row.UserID,
			PasswordHash: row.PasswordHash,
			CreatedAt:    fromTS(row.CreatedAt),
		}
		out[i] = &ph
	}
	return out, nil
}

func (r *Repo) TrimPasswordHistory(ctx context.Context, userID string, keep int) (int64, error) {
	return r.q.TrimPasswordHistory(ctx, pgxgen.TrimPasswordHistoryParams{
		UserID: userID,
		Offset: int32(keep),
	})
}

// ─── EmailVerification ───────────────────────────────────────────────────────

func (r *Repo) CreateEmailVerification(ctx context.Context, input domain.NewEmailVerification) error {
	return r.q.CreateEmailVerification(ctx, pgxgen.CreateEmailVerificationParams{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		ExpiresAt: ts(input.ExpiresAt),
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) ConsumeEmailVerification(ctx context.Context, tokenHash string) (*domain.EmailVerification, error) {
	row, err := r.q.ConsumeEmailVerification(ctx, tokenHash)
	if err != nil {
		return nil, notFound(err)
	}
	ev := domain.EmailVerification{
		ID:        row.ID,
		UserID:    row.UserID,
		TokenHash: row.TokenHash,
		ExpiresAt: fromTS(row.ExpiresAt),
		CreatedAt: fromTS(row.CreatedAt),
	}
	return &ev, nil
}

func (r *Repo) DeleteEmailVerification(ctx context.Context, id string) error {
	n, err := r.q.DeleteEmailVerification(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteEmailVerificationsForUser(ctx context.Context, userID string) (int64, error) {
	return r.q.DeleteEmailVerificationsForUser(ctx, userID)
}

// ─── PasswordReset ───────────────────────────────────────────────────────────

func (r *Repo) CreatePasswordReset(ctx context.Context, input domain.NewPasswordReset) error {
	return r.q.CreatePasswordReset(ctx, pgxgen.CreatePasswordResetParams{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		ExpiresAt: ts(input.ExpiresAt),
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) ConsumePasswordReset(ctx context.Context, tokenHash string) (*domain.PasswordReset, error) {
	row, err := r.q.ConsumePasswordReset(ctx, tokenHash)
	if err != nil {
		return nil, notFound(err)
	}
	usedAt := fromTS(row.UsedAt)
	pr := domain.PasswordReset{
		ID:        row.ID,
		UserID:    row.UserID,
		TokenHash: row.TokenHash,
		ExpiresAt: fromTS(row.ExpiresAt),
		UsedAt:    &usedAt,
		CreatedAt: fromTS(row.CreatedAt),
	}
	return &pr, nil
}

func (r *Repo) DeleteUnusedPasswordResetsForUser(ctx context.Context, userID string) (int64, error) {
	return r.q.DeleteUnusedPasswordResetsForUser(ctx, userID)
}

// ─── AuditLog ────────────────────────────────────────────────────────────────

func (r *Repo) LogAuditEvent(ctx context.Context, input domain.NewAuditLog) error {
	var meta *string
	if len(input.Metadata) > 0 {
		s := string(input.Metadata)
		meta = &s
	}
	return r.q.LogAuditEvent(ctx, pgxgen.LogAuditEventParams{
		ID:        input.ID,
		UserID:    input.UserID,
		EventType: input.EventType,
		Metadata:  meta,
		IpAddress: input.IPAddress,
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) ListAuditLog(ctx context.Context, filters domain.ListAuditFilters) ([]*domain.AuditLog, error) {
	userFilter := ""
	if filters.UserID != nil {
		userFilter = *filters.UserID
	}
	typeFilter := ""
	if filters.EventType != nil {
		typeFilter = *filters.EventType
	}
	limit := filters.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.q.ListAuditLogByUserAndType(ctx, pgxgen.ListAuditLogByUserAndTypeParams{
		Column1: userFilter,
		Column2: typeFilter,
		Column3: int32(limit),
		Column4: int32(filters.Offset),
	})
	if err != nil {
		return nil, err
	}
	out := make([]*domain.AuditLog, len(rows))
	for i, row := range rows {
		var meta json.RawMessage
		if row.Metadata != nil {
			meta = json.RawMessage(*row.Metadata)
		}
		al := domain.AuditLog{
			ID:        row.ID,
			UserID:    row.UserID,
			EventType: row.EventType,
			Metadata:  meta,
			IPAddress: row.IpAddress,
			CreatedAt: fromTS(row.CreatedAt),
		}
		out[i] = &al
	}
	return out, nil
}

// ─── Challenge ───────────────────────────────────────────────────────────────

func (r *Repo) SetChallenge(ctx context.Context, key, value string, ttl time.Duration) error {
	expires := time.Now().Add(ttl).UTC()
	return r.q.UpsertChallenge(ctx, pgxgen.UpsertChallengeParams{
		Key:       key,
		Value:     value,
		ExpiresAt: ts(expires),
	})
}

func (r *Repo) GetChallenge(ctx context.Context, key string) (*domain.Challenge, error) {
	row, err := r.q.GetChallenge(ctx, key)
	if err != nil {
		return nil, notFound(err)
	}
	if !row.ExpiresAt.Time.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	c := domain.Challenge{Key: row.Key, Value: row.Value, ExpiresAt: fromTS(row.ExpiresAt)}
	return &c, nil
}

func (r *Repo) ConsumeChallenge(ctx context.Context, key string) (*domain.Challenge, error) {
	row, err := r.q.ConsumeChallenge(ctx, key)
	if err != nil {
		return nil, notFound(err)
	}
	c := domain.Challenge{Key: row.Key, Value: row.Value, ExpiresAt: fromTS(row.ExpiresAt)}
	return &c, nil
}

func (r *Repo) DeleteChallenge(ctx context.Context, key string) error {
	_, err := r.q.DeleteChallenge(ctx, key)
	return err
}

// ─── RateLimit ───────────────────────────────────────────────────────────────

func (r *Repo) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (domain.RateLimitResult, error) {
	windowMicros := window.Microseconds()
	row, err := r.q.UpsertRateLimit(ctx, pgxgen.UpsertRateLimitParams{
		Key:         key,
		WindowStart: ts(time.Now().UTC()),
		Column3:     windowMicros,
	})
	if err != nil {
		return domain.RateLimitResult{}, err
	}
	count := int(row.Count)
	if count > limit {
		windowStart := fromTS(row.WindowStart)
		retry := window - time.Since(windowStart)
		if retry < 0 {
			retry = 0
		}
		return domain.RateLimitResult{Allowed: false, Remaining: 0, RetryAfter: retry}, nil
	}
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	return domain.RateLimitResult{Allowed: true, Remaining: remaining}, nil
}

// ─── Revocation ──────────────────────────────────────────────────────────────

func (r *Repo) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	expires := time.Now().Add(ttl).UTC()
	return r.q.RevokeToken(ctx, pgxgen.RevokeTokenParams{
		Key:       jti,
		ExpiresAt: ts(expires),
	})
}

func (r *Repo) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	row, err := r.q.GetRevocation(ctx, jti)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if !row.ExpiresAt.Time.UTC().After(time.Now().UTC()) {
		return false, nil
	}
	return true, nil
}

// ─── MagicLink ───────────────────────────────────────────────────────────────

func (r *Repo) CreateMagicLink(ctx context.Context, input domain.NewMagicLink) error {
	return r.q.CreateMagicLink(ctx, pgxgen.CreateMagicLinkParams{
		ID:        input.ID,
		Email:     input.Email,
		TokenHash: input.TokenHash,
		ExpiresAt: ts(input.ExpiresAt),
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) GetUnusedMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*domain.MagicLink, error) {
	row, err := r.q.GetUnusedMagicLinkByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, notFound(err)
	}
	ml := magicLinkToDomain(row)
	return &ml, nil
}

func (r *Repo) ConsumeMagicLink(ctx context.Context, tokenHash string) (*domain.MagicLink, error) {
	row, err := r.q.ConsumeMagicLink(ctx, tokenHash)
	if err != nil {
		return nil, notFound(err)
	}
	ml := magicLinkToDomain(row)
	return &ml, nil
}

func (r *Repo) MarkMagicLinkUsed(ctx context.Context, id string) error {
	n, err := r.q.MarkMagicLinkUsed(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteMagicLink(ctx context.Context, id string) error {
	n, err := r.q.DeleteMagicLink(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteUnusedMagicLinksForEmail(ctx context.Context, email string) (int64, error) {
	return r.q.DeleteUnusedMagicLinksForEmail(ctx, email)
}

// ─── Passkey ─────────────────────────────────────────────────────────────────

func (r *Repo) GetPasskeysByUserID(ctx context.Context, userID string) ([]*domain.WebauthnCredential, error) {
	rows, err := r.q.GetPasskeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.WebauthnCredential, len(rows))
	for i, row := range rows {
		wc := passKeyToDomain(row)
		out[i] = &wc
	}
	return out, nil
}

func (r *Repo) GetPasskeyByIDAndUser(ctx context.Context, id, userID string) (*domain.WebauthnCredential, error) {
	row, err := r.q.GetPasskeyByIDAndUser(ctx, pgxgen.GetPasskeyByIDAndUserParams{
		ID:     id,
		UserID: userID,
	})
	if err != nil {
		return nil, notFound(err)
	}
	wc := passKeyToDomain(row)
	return &wc, nil
}

func (r *Repo) CreatePasskey(ctx context.Context, input domain.NewWebauthnCredential) error {
	return r.q.CreatePasskey(ctx, pgxgen.CreatePasskeyParams{
		ID:         input.ID,
		UserID:     input.UserID,
		Name:       input.Name,
		Aaguid:     input.AAGUID,
		DeviceName: input.DeviceName,
		Credential: string(input.Credential),
		CreatedAt:  ts(input.CreatedAt),
		LastUsedAt: tsPtr(nil),
	})
}

func (r *Repo) UpdatePasskeyLastUsed(ctx context.Context, id string, at time.Time) error {
	n, err := r.q.UpdatePasskeyLastUsed(ctx, pgxgen.UpdatePasskeyLastUsedParams{
		ID:         id,
		LastUsedAt: ts(at),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeletePasskey(ctx context.Context, id string) error {
	n, err := r.q.DeletePasskey(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// ─── TOTP ────────────────────────────────────────────────────────────────────

func (r *Repo) GetTOTPByUserID(ctx context.Context, userID string, verifiedOnly *bool) (*domain.TOTPSecret, error) {
	filterVerified := false
	if verifiedOnly != nil && *verifiedOnly {
		filterVerified = true
	}
	row, err := r.q.GetTOTPByUserID(ctx, pgxgen.GetTOTPByUserIDParams{
		UserID: userID,
		Column2: filterVerified,
	})
	if err != nil {
		return nil, notFound(err)
	}
	t := domain.TOTPSecret{
		ID:              row.ID,
		UserID:          row.UserID,
		EncryptedSecret: row.EncryptedSecret,
		Verified:        row.Verified,
		CreatedAt:       fromTS(row.CreatedAt),
	}
	return &t, nil
}

func (r *Repo) CreateTOTP(ctx context.Context, input domain.NewTOTPSecret) error {
	return r.q.CreateTOTP(ctx, pgxgen.CreateTOTPParams{
		ID:              input.ID,
		UserID:          input.UserID,
		EncryptedSecret: input.EncryptedSecret,
		Verified:        input.Verified,
		CreatedAt:       ts(input.CreatedAt),
	})
}

func (r *Repo) MarkTOTPVerified(ctx context.Context, id string) error {
	n, err := r.q.MarkTOTPVerified(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteTOTPForUser(ctx context.Context, userID string, verifiedOnly *bool) (int64, error) {
	filterVerified := false
	if verifiedOnly != nil && *verifiedOnly {
		filterVerified = true
	}
	return r.q.DeleteTOTPForUser(ctx, pgxgen.DeleteTOTPForUserParams{
		UserID:  userID,
		Column2: filterVerified,
	})
}

// ─── BackupCode ──────────────────────────────────────────────────────────────

func (r *Repo) GetUnusedBackupCodesByUserID(ctx context.Context, userID string) ([]*domain.BackupCode, error) {
	rows, err := r.q.GetUnusedBackupCodesByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.BackupCode, len(rows))
	for i, row := range rows {
		bc := domain.BackupCode{
			ID:        row.ID,
			UserID:    row.UserID,
			CodeHash:  row.CodeHash,
			Used:      row.Used,
			CreatedAt: fromTS(row.CreatedAt),
		}
		out[i] = &bc
	}
	return out, nil
}

func (r *Repo) CreateBackupCode(ctx context.Context, input domain.NewBackupCode) error {
	return r.q.CreateBackupCode(ctx, pgxgen.CreateBackupCodeParams{
		ID:        input.ID,
		UserID:    input.UserID,
		CodeHash:  input.CodeHash,
		Used:      input.Used,
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) MarkBackupCodeUsed(ctx context.Context, id string) error {
	n, err := r.q.MarkBackupCodeUsed(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteAllBackupCodesForUser(ctx context.Context, userID string) (int64, error) {
	return r.q.DeleteAllBackupCodesForUser(ctx, userID)
}

// ─── OAuthAccount ────────────────────────────────────────────────────────────

func (r *Repo) GetOAuthAccountByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error) {
	row, err := r.q.GetOAuthAccountByProviderAndProviderUserID(ctx, pgxgen.GetOAuthAccountByProviderAndProviderUserIDParams{
		Provider:       provider,
		ProviderUserID: providerUserID,
	})
	if err != nil {
		return nil, notFound(err)
	}
	oa := oauthAccountToDomain(row)
	return &oa, nil
}

func (r *Repo) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*domain.OAuthAccount, error) {
	rows, err := r.q.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.OAuthAccount, len(rows))
	for i, row := range rows {
		oa := oauthAccountToDomain(row)
		out[i] = &oa
	}
	return out, nil
}

func (r *Repo) GetOAuthAccountByUserAndProvider(ctx context.Context, userID, provider string) (*domain.OAuthAccount, error) {
	row, err := r.q.GetOAuthAccountByUserAndProvider(ctx, pgxgen.GetOAuthAccountByUserAndProviderParams{
		UserID:   userID,
		Provider: provider,
	})
	if err != nil {
		return nil, notFound(err)
	}
	oa := oauthAccountToDomain(row)
	return &oa, nil
}

func (r *Repo) CreateOAuthAccount(ctx context.Context, input domain.NewOAuthAccount) error {
	return r.q.CreateOAuthAccount(ctx, pgxgen.CreateOAuthAccountParams{
		ID:              input.ID,
		UserID:          input.UserID,
		Provider:        input.Provider,
		ProviderUserID:  input.ProviderUserID,
		AccessTokenEnc:  input.AccessTokenEnc,
		RefreshTokenEnc: input.RefreshTokenEnc,
		CreatedAt:       ts(input.CreatedAt),
		ExpiresAt:       tsPtr(input.ExpiresAt),
		UpdatedAt:       ts(input.UpdatedAt),
	})
}

func (r *Repo) UpdateOAuthAccountTokens(ctx context.Context, id string, accessTokenEnc, refreshTokenEnc *string, expiresAt *time.Time, updatedAt time.Time) error {
	n, err := r.q.UpdateOAuthAccountTokens(ctx, pgxgen.UpdateOAuthAccountTokensParams{
		ID:              id,
		AccessTokenEnc:  accessTokenEnc,
		RefreshTokenEnc: refreshTokenEnc,
		ExpiresAt:       tsPtr(expiresAt),
		UpdatedAt:       ts(updatedAt),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteOAuthAccount(ctx context.Context, id string) error {
	n, err := r.q.DeleteOAuthAccount(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// ─── OAuthState ──────────────────────────────────────────────────────────────

func (r *Repo) CreateOAuthState(ctx context.Context, input domain.NewOAuthState) error {
	return r.q.CreateOAuthState(ctx, pgxgen.CreateOAuthStateParams{
		State:       input.State,
		Provider:    input.Provider,
		RedirectUrl: input.RedirectURL,
		ExpiresAt:   ts(input.ExpiresAt),
		CreatedAt:   ts(input.CreatedAt),
	})
}

func (r *Repo) ConsumeOAuthState(ctx context.Context, state string) (*domain.OAuthState, error) {
	row, err := r.q.GetAndDeleteOAuthState(ctx, state)
	if err != nil {
		return nil, notFound(err)
	}
	if !row.ExpiresAt.Time.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	os := domain.OAuthState{
		State:       row.State,
		Provider:    row.Provider,
		RedirectURL: row.RedirectUrl,
		ExpiresAt:   fromTS(row.ExpiresAt),
		CreatedAt:   fromTS(row.CreatedAt),
	}
	return &os, nil
}

// ─── RefreshToken ────────────────────────────────────────────────────────────

func (r *Repo) CreateRefreshToken(ctx context.Context, input domain.NewRefreshToken) error {
	return r.q.CreateRefreshToken(ctx, pgxgen.CreateRefreshTokenParams{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		FamilyID:  input.FamilyID,
		ExpiresAt: ts(input.ExpiresAt),
		Revoked:   input.Revoked,
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	row, err := r.q.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, notFound(err)
	}
	rt := domain.RefreshToken{
		ID:        row.ID,
		UserID:    row.UserID,
		TokenHash: row.TokenHash,
		FamilyID:  row.FamilyID,
		ExpiresAt: fromTS(row.ExpiresAt),
		Revoked:   row.Revoked,
		CreatedAt: fromTS(row.CreatedAt),
	}
	return &rt, nil
}

func (r *Repo) RevokeRefreshToken(ctx context.Context, id string) error {
	n, err := r.q.RevokeRefreshToken(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) RevokeRefreshTokenFamily(ctx context.Context, familyID string) (int64, error) {
	return r.q.RevokeRefreshTokenFamily(ctx, familyID)
}

// ─── APIKey ──────────────────────────────────────────────────────────────────

func (r *Repo) CreateAPIKey(ctx context.Context, input domain.NewAPIKey) error {
	hasUser := input.UserID != nil && *input.UserID != ""
	hasOrg := input.OrganizationID != nil && *input.OrganizationID != ""
	if hasUser == hasOrg {
		return yautherr.ErrInvalidRequest
	}
	return r.q.CreateAPIKey(ctx, pgxgen.CreateAPIKeyParams{
		ID:              input.ID,
		UserID:          input.UserID,
		OrganizationID:  input.OrganizationID,
		KeyPrefix:       input.KeyPrefix,
		KeyHash:         input.KeyHash,
		Name:            input.Name,
		Scopes:          jsonStringPtr(input.Scopes),
		Role:            input.Role,
		LastUsedAt:      tsPtr(nil),
		ExpiresAt:       tsPtr(input.ExpiresAt),
		CreatedAt:       ts(input.CreatedAt),
		CreatedByUserID: input.CreatedByUserID,
	})
}

func (r *Repo) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*domain.APIKey, error) {
	row, err := r.q.GetAPIKeyByPrefix(ctx, prefix)
	if err != nil {
		return nil, notFound(err)
	}
	ak := apiKeyToDomain(row)
	return &ak, nil
}

func (r *Repo) GetAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*domain.APIKey, error) {
	row, err := r.q.GetAPIKeyByIDAndUser(ctx, pgxgen.GetAPIKeyByIDAndUserParams{ID: id, UserID: &userID})
	if err != nil {
		return nil, notFound(err)
	}
	ak := apiKeyToDomain(row)
	return &ak, nil
}

func (r *Repo) GetAPIKeyByIDAndOrg(ctx context.Context, id, organizationID string) (*domain.APIKey, error) {
	row, err := r.q.GetAPIKeyByIDAndOrg(ctx, pgxgen.GetAPIKeyByIDAndOrgParams{ID: id, OrganizationID: &organizationID})
	if err != nil {
		return nil, notFound(err)
	}
	ak := apiKeyToDomain(row)
	return &ak, nil
}

func (r *Repo) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*domain.APIKey, error) {
	rows, err := r.q.ListAPIKeysByUserID(ctx, &userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.APIKey, len(rows))
	for i, row := range rows {
		ak := apiKeyToDomain(row)
		out[i] = &ak
	}
	return out, nil
}

func (r *Repo) ListAPIKeysByOrgID(ctx context.Context, organizationID string) ([]*domain.APIKey, error) {
	rows, err := r.q.ListAPIKeysByOrgID(ctx, &organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.APIKey, len(rows))
	for i, row := range rows {
		ak := apiKeyToDomain(row)
		out[i] = &ak
	}
	return out, nil
}

func (r *Repo) UpdateAPIKeyLastUsed(ctx context.Context, id string, at time.Time) error {
	n, err := r.q.UpdateAPIKeyLastUsed(ctx, pgxgen.UpdateAPIKeyLastUsedParams{ID: id, LastUsedAt: ts(at)})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) SetAPIKeyExpiry(ctx context.Context, id string, expiresAt *time.Time) error {
	n, err := r.q.SetAPIKeyExpiry(ctx, pgxgen.SetAPIKeyExpiryParams{ID: id, ExpiresAt: tsPtr(expiresAt)})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteAPIKey(ctx context.Context, id string) error {
	n, err := r.q.DeleteAPIKey(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// ─── OAuth2Client ────────────────────────────────────────────────────────────

func (r *Repo) CreateOAuth2Client(ctx context.Context, input domain.NewOAuth2Client) error {
	return r.q.CreateOAuth2Client(ctx, pgxgen.CreateOAuth2ClientParams{
		ID:                      input.ID,
		ClientID:                input.ClientID,
		ClientSecretHash:        input.ClientSecretHash,
		RedirectUris:            string(input.RedirectURIs),
		ClientName:              input.ClientName,
		GrantTypes:              string(input.GrantTypes),
		Scopes:                  jsonStringPtr(input.Scopes),
		IsPublic:                input.IsPublic,
		CreatedAt:               ts(input.CreatedAt),
		TokenEndpointAuthMethod: input.TokenEndpointAuthMethod,
		PublicKeyPem:            input.PublicKeyPEM,
		JwksUri:                 input.JWKSURI,
		BannedAt:                tsPtr(nil),
		BannedReason:            nil,
	})
}

func (r *Repo) GetOAuth2ClientByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	row, err := r.q.GetOAuth2ClientByClientID(ctx, clientID)
	if err != nil {
		return nil, notFound(err)
	}
	c := oauth2ClientToDomain(row)
	return &c, nil
}

func (r *Repo) SetOAuth2ClientBanned(ctx context.Context, clientID string, bannedAt *time.Time, reason *string) (bool, error) {
	row, err := r.q.SetOAuth2ClientBanned(ctx, pgxgen.SetOAuth2ClientBannedParams{
		ClientID:     clientID,
		BannedAt:     tsPtr(bannedAt),
		BannedReason: reason,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	_ = row
	return true, nil
}

func (r *Repo) RotateOAuth2ClientPublicKey(ctx context.Context, clientID string, publicKeyPEM *string) (bool, error) {
	n, err := r.q.RotateOAuth2ClientPublicKey(ctx, pgxgen.RotateOAuth2ClientPublicKeyParams{
		ClientID:     clientID,
		PublicKeyPem: publicKeyPEM,
	})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (r *Repo) ListBannedOAuth2Clients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	rows, err := r.q.ListBannedOAuth2Clients(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.OAuth2Client, len(rows))
	for i, row := range rows {
		c := oauth2ClientToDomain(row)
		out[i] = &c
	}
	return out, nil
}

// ─── AuthorizationCode ───────────────────────────────────────────────────────

func (r *Repo) CreateAuthorizationCode(ctx context.Context, input domain.NewAuthorizationCode) error {
	return r.q.CreateAuthorizationCode(ctx, pgxgen.CreateAuthorizationCodeParams{
		ID:                  input.ID,
		CodeHash:            input.CodeHash,
		ClientID:            input.ClientID,
		UserID:              input.UserID,
		Scopes:              jsonStringPtr(input.Scopes),
		RedirectUri:         input.RedirectURI,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		ExpiresAt:           ts(input.ExpiresAt),
		Used:                input.Used,
		Nonce:               input.Nonce,
		CreatedAt:           ts(input.CreatedAt),
	})
}

func (r *Repo) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	row, err := r.q.GetAuthorizationCodeByHash(ctx, codeHash)
	if err != nil {
		return nil, notFound(err)
	}
	ac := authCodeToDomain(row)
	return &ac, nil
}

func (r *Repo) ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	row, err := r.q.ConsumeAuthorizationCode(ctx, codeHash)
	if err != nil {
		return nil, notFound(err)
	}
	ac := authCodeToDomain(row)
	return &ac, nil
}

func (r *Repo) MarkAuthorizationCodeUsed(ctx context.Context, id string) error {
	n, err := r.q.MarkAuthorizationCodeUsed(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// ─── Consent ─────────────────────────────────────────────────────────────────

func (r *Repo) CreateConsent(ctx context.Context, input domain.NewConsent) error {
	return r.q.CreateConsent(ctx, pgxgen.CreateConsentParams{
		ID:        input.ID,
		UserID:    input.UserID,
		ClientID:  input.ClientID,
		Scopes:    jsonStringPtr(input.Scopes),
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) GetConsentByUserAndClient(ctx context.Context, userID, clientID string) (*domain.Consent, error) {
	row, err := r.q.GetConsentByUserAndClient(ctx, pgxgen.GetConsentByUserAndClientParams{
		UserID:   userID,
		ClientID: clientID,
	})
	if err != nil {
		return nil, notFound(err)
	}
	c := domain.Consent{
		ID:        row.ID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		Scopes:    jsonBytesPtr(row.Scopes),
		CreatedAt: fromTS(row.CreatedAt),
	}
	return &c, nil
}

func (r *Repo) UpdateConsentScopes(ctx context.Context, id string, scopes []byte) error {
	var s *string
	if len(scopes) > 0 {
		str := string(scopes)
		s = &str
	}
	n, err := r.q.UpdateConsentScopes(ctx, pgxgen.UpdateConsentScopesParams{ID: id, Scopes: s})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// ─── DeviceCode ──────────────────────────────────────────────────────────────

func (r *Repo) CreateDeviceCode(ctx context.Context, input domain.NewDeviceCode) error {
	return r.q.CreateDeviceCode(ctx, pgxgen.CreateDeviceCodeParams{
		ID:             input.ID,
		DeviceCodeHash: input.DeviceCodeHash,
		UserCode:       input.UserCode,
		ClientID:       input.ClientID,
		Scopes:         jsonStringPtr(input.Scopes),
		UserID:         input.UserID,
		Status:         input.Status,
		Interval:       int32(input.Interval),
		ExpiresAt:      ts(input.ExpiresAt),
		LastPolledAt:   tsPtr(nil),
		CreatedAt:      ts(input.CreatedAt),
	})
}

func (r *Repo) GetDeviceCodeByUserCodePending(ctx context.Context, userCode string) (*domain.DeviceCode, error) {
	row, err := r.q.GetDeviceCodeByUserCodePending(ctx, userCode)
	if err != nil {
		return nil, notFound(err)
	}
	dc := deviceCodeToDomain(row)
	return &dc, nil
}

func (r *Repo) GetDeviceCodeByDeviceCodeHash(ctx context.Context, deviceCodeHash string) (*domain.DeviceCode, error) {
	row, err := r.q.GetDeviceCodeByDeviceCodeHash(ctx, deviceCodeHash)
	if err != nil {
		return nil, notFound(err)
	}
	dc := deviceCodeToDomain(row)
	return &dc, nil
}

func (r *Repo) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	n, err := r.q.UpdateDeviceCodeStatus(ctx, pgxgen.UpdateDeviceCodeStatusParams{
		ID:     id,
		Status: status,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) UpdateDeviceCodeLastPolled(ctx context.Context, id string, at time.Time) error {
	n, err := r.q.UpdateDeviceCodeLastPolled(ctx, pgxgen.UpdateDeviceCodeLastPolledParams{
		ID:           id,
		LastPolledAt: ts(at),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) UpdateDeviceCodeInterval(ctx context.Context, id string, interval int) error {
	n, err := r.q.UpdateDeviceCodeInterval(ctx, pgxgen.UpdateDeviceCodeIntervalParams{
		ID:       id,
		Interval: int32(interval),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// ─── OIDCNonce ───────────────────────────────────────────────────────────────

func (r *Repo) CreateOIDCNonce(ctx context.Context, input domain.NewOIDCNonce) error {
	return r.q.CreateOIDCNonce(ctx, pgxgen.CreateOIDCNonceParams{
		ID:                  input.ID,
		NonceHash:           input.NonceHash,
		AuthorizationCodeID: input.AuthorizationCodeID,
		CreatedAt:           ts(input.CreatedAt),
	})
}

func (r *Repo) GetOIDCNonceByHash(ctx context.Context, nonceHash string) (*domain.OIDCNonce, error) {
	row, err := r.q.GetOIDCNonceByHash(ctx, nonceHash)
	if err != nil {
		return nil, notFound(err)
	}
	n := domain.OIDCNonce{
		ID:                  row.ID,
		NonceHash:           row.NonceHash,
		AuthorizationCodeID: row.AuthorizationCodeID,
		CreatedAt:           fromTS(row.CreatedAt),
	}
	return &n, nil
}

func (r *Repo) DeleteOIDCNonce(ctx context.Context, id string) error {
	n, err := r.q.DeleteOIDCNonce(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// ─── AccountLock ─────────────────────────────────────────────────────────────

func (r *Repo) GetAccountLockByUserID(ctx context.Context, userID string) (*domain.AccountLock, error) {
	row, err := r.q.GetAccountLockByUserID(ctx, userID)
	if err != nil {
		return nil, notFound(err)
	}
	al := accountLockToDomain(row)
	return &al, nil
}

func (r *Repo) CreateAccountLock(ctx context.Context, input domain.NewAccountLock) (domain.AccountLock, error) {
	row, err := r.q.CreateAccountLock(ctx, pgxgen.CreateAccountLockParams{
		ID:           input.ID,
		UserID:       input.UserID,
		FailedCount:  int32(input.FailedCount),
		LockedUntil:  tsPtr(input.LockedUntil),
		LockCount:    int32(input.LockCount),
		LockedReason: input.LockedReason,
		CreatedAt:    ts(input.CreatedAt),
		UpdatedAt:    ts(input.UpdatedAt),
	})
	if err != nil {
		return domain.AccountLock{}, err
	}
	return accountLockToDomain(row), nil
}

func (r *Repo) IncrementAccountLockFailedCount(ctx context.Context, id string, updatedAt time.Time) error {
	n, err := r.q.IncrementAccountLockFailedCount(ctx, pgxgen.IncrementAccountLockFailedCountParams{
		ID:        id,
		UpdatedAt: ts(updatedAt),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) SetAccountLockState(ctx context.Context, id string, state domain.LockState, updatedAt time.Time) error {
	n, err := r.q.SetAccountLockState(ctx, pgxgen.SetAccountLockStateParams{
		ID:           id,
		LockedReason: state.LockedReason,
		LockCount:    int32(state.LockCount),
		LockedUntil:  tsPtr(state.LockedUntil),
		UpdatedAt:    ts(updatedAt),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) ResetAccountLockFailedCount(ctx context.Context, id string, updatedAt time.Time) error {
	n, err := r.q.ResetAccountLockFailedCount(ctx, pgxgen.ResetAccountLockFailedCountParams{
		ID:        id,
		UpdatedAt: ts(updatedAt),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) AutoUnlockAccount(ctx context.Context, id string, updatedAt time.Time) error {
	n, err := r.q.AutoUnlockAccount(ctx, pgxgen.AutoUnlockAccountParams{
		ID:        id,
		UpdatedAt: ts(updatedAt),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// ─── UnlockToken ─────────────────────────────────────────────────────────────

func (r *Repo) CreateUnlockToken(ctx context.Context, input domain.NewUnlockToken) error {
	return r.q.CreateUnlockToken(ctx, pgxgen.CreateUnlockTokenParams{
		ID:        input.ID,
		UserID:    input.UserID,
		TokenHash: input.TokenHash,
		ExpiresAt: ts(input.ExpiresAt),
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) GetUnlockTokenByHash(ctx context.Context, tokenHash string) (*domain.UnlockToken, error) {
	row, err := r.q.GetUnlockTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, notFound(err)
	}
	if !row.ExpiresAt.Time.UTC().After(time.Now().UTC()) {
		return nil, yautherr.ErrNotFound
	}
	ut := domain.UnlockToken{
		ID:        row.ID,
		UserID:    row.UserID,
		TokenHash: row.TokenHash,
		ExpiresAt: fromTS(row.ExpiresAt),
		CreatedAt: fromTS(row.CreatedAt),
	}
	return &ut, nil
}

func (r *Repo) ConsumeUnlockToken(ctx context.Context, tokenHash string) (*domain.UnlockToken, error) {
	row, err := r.q.ConsumeUnlockToken(ctx, tokenHash)
	if err != nil {
		return nil, notFound(err)
	}
	ut := domain.UnlockToken{
		ID:        row.ID,
		UserID:    row.UserID,
		TokenHash: row.TokenHash,
		ExpiresAt: fromTS(row.ExpiresAt),
		CreatedAt: fromTS(row.CreatedAt),
	}
	return &ut, nil
}

func (r *Repo) DeleteUnlockToken(ctx context.Context, id string) error {
	n, err := r.q.DeleteUnlockToken(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteAllUnlockTokensForUser(ctx context.Context, userID string) (int64, error) {
	return r.q.DeleteAllUnlockTokensForUser(ctx, userID)
}

// ─── Webhook ─────────────────────────────────────────────────────────────────

func (r *Repo) CreateWebhook(ctx context.Context, input domain.NewWebhook) error {
	return r.q.CreateWebhook(ctx, pgxgen.CreateWebhookParams{
		ID:        input.ID,
		Url:       input.URL,
		Secret:    input.Secret,
		Events:    string(input.Events),
		Active:    input.Active,
		CreatedAt: ts(input.CreatedAt),
		UpdatedAt: ts(input.UpdatedAt),
	})
}

func (r *Repo) GetWebhookByID(ctx context.Context, id string) (*domain.Webhook, error) {
	row, err := r.q.GetWebhookByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	wh := webhookToDomain(row)
	return &wh, nil
}

func (r *Repo) ListActiveWebhooks(ctx context.Context) ([]*domain.Webhook, error) {
	rows, err := r.q.ListActiveWebhooks(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Webhook, len(rows))
	for i, row := range rows {
		wh := webhookToDomain(row)
		out[i] = &wh
	}
	return out, nil
}

func (r *Repo) ListWebhooks(ctx context.Context) ([]*domain.Webhook, error) {
	rows, err := r.q.ListWebhooks(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Webhook, len(rows))
	for i, row := range rows {
		wh := webhookToDomain(row)
		out[i] = &wh
	}
	return out, nil
}

func (r *Repo) UpdateWebhook(ctx context.Context, id string, changes domain.UpdateWebhook) (domain.Webhook, error) {
	now := time.Now().UTC()
	updatedAt := ts(now)
	if changes.UpdatedAt != nil {
		updatedAt = ts(*changes.UpdatedAt)
	}
	var urlPtr, secretPtr, eventsPtr *string
	var activePtr *bool
	if changes.URL != nil {
		urlPtr = changes.URL
	}
	if changes.Secret != nil {
		secretPtr = changes.Secret
	}
	if changes.Events != nil {
		s := string(*changes.Events)
		eventsPtr = &s
	}
	if changes.Active != nil {
		activePtr = changes.Active
	}
	row, err := r.q.UpdateWebhook(ctx, pgxgen.UpdateWebhookParams{
		UpdatedAt: updatedAt,
		ID:        id,
		Url:       urlPtr,
		Secret:    secretPtr,
		Events:    eventsPtr,
		Active:    activePtr,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Webhook{}, yautherr.ErrNotFound
		}
		return domain.Webhook{}, err
	}
	return webhookToDomain(row), nil
}

func (r *Repo) DeleteWebhook(ctx context.Context, id string) error {
	n, err := r.q.DeleteWebhook(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) CreateWebhookDelivery(ctx context.Context, input domain.NewWebhookDelivery) error {
	return r.q.CreateWebhookDelivery(ctx, pgxgen.CreateWebhookDeliveryParams{
		ID:           input.ID,
		WebhookID:    input.WebhookID,
		EventType:    input.EventType,
		Payload:      string(input.Payload),
		StatusCode:   input.StatusCode,
		ResponseBody: input.ResponseBody,
		Success:      input.Success,
		Attempt:      int32(input.Attempt),
		CreatedAt:    ts(input.CreatedAt),
	})
}

func (r *Repo) ListWebhookDeliveriesByWebhookID(ctx context.Context, webhookID string, limit int) ([]*domain.WebhookDelivery, error) {
	rows, err := r.q.ListWebhookDeliveriesByWebhookID(ctx, pgxgen.ListWebhookDeliveriesByWebhookIDParams{
		WebhookID: webhookID,
		Column2:   int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]*domain.WebhookDelivery, len(rows))
	for i, row := range rows {
		wd := domain.WebhookDelivery{
			ID:           row.ID,
			WebhookID:    row.WebhookID,
			EventType:    row.EventType,
			Payload:      json.RawMessage(row.Payload),
			StatusCode:   row.StatusCode,
			ResponseBody: row.ResponseBody,
			Success:      row.Success,
			Attempt:      int(row.Attempt),
			CreatedAt:    fromTS(row.CreatedAt),
		}
		out[i] = &wd
	}
	return out, nil
}

func (r *Repo) CreateScheduledRetry(ctx context.Context, input domain.NewScheduledWebhookRetry) error {
	payload := append([]byte(nil), input.Payload...)
	return r.q.CreateScheduledRetry(ctx, pgxgen.CreateScheduledRetryParams{
		ID:        input.ID,
		WebhookID: input.WebhookID,
		EventType: input.EventType,
		Payload:   payload,
		Attempt:   int32(input.Attempt),
		NotBefore: ts(input.NotBefore),
		CreatedAt: ts(input.CreatedAt),
	})
}

func (r *Repo) ClaimDueRetries(ctx context.Context, now time.Time, limit int) ([]*domain.ScheduledWebhookRetry, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := r.q.ClaimDueRetries(ctx, pgxgen.ClaimDueRetriesParams{
		NotBefore: ts(now),
		Limit:     int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ScheduledWebhookRetry, len(rows))
	for i, row := range rows {
		sr := domain.ScheduledWebhookRetry{
			ID:        row.ID,
			WebhookID: row.WebhookID,
			EventType: row.EventType,
			Attempt:   int(row.Attempt),
			NotBefore: fromTS(row.NotBefore),
			CreatedAt: fromTS(row.CreatedAt),
		}
		if len(row.Payload) > 0 {
			sr.Payload = append([]byte(nil), row.Payload...)
		}
		out[i] = &sr
	}
	return out, nil
}

func (r *Repo) DeleteScheduledRetry(ctx context.Context, id string) error {
	_, err := r.q.DeleteScheduledRetry(ctx, id)
	return err
}

// ─── Organization ────────────────────────────────────────────────────────────

func (r *Repo) CreateOrganization(ctx context.Context, input domain.NewOrganization) (domain.Organization, error) {
	row, err := r.q.CreateOrganization(ctx, pgxgen.CreateOrganizationParams{
		ID:          input.ID,
		Name:        input.Name,
		Slug:        input.Slug,
		SlugLower:   strings.ToLower(input.Slug),
		DisplayName: input.DisplayName,
		AvatarUrl:   input.AvatarURL,
		Metadata:    jsonStringPtr(input.Metadata),
		CreatedAt:   ts(input.CreatedAt),
		UpdatedAt:   ts(input.UpdatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.Organization{}, yautherr.ErrConflict
		}
		return domain.Organization{}, err
	}
	return orgToDomain(row), nil
}

func (r *Repo) GetOrganizationByID(ctx context.Context, id string) (*domain.Organization, error) {
	row, err := r.q.GetOrganizationByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	o := orgToDomain(row)
	return &o, nil
}

func (r *Repo) GetOrganizationBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	row, err := r.q.GetOrganizationBySlug(ctx, strings.ToLower(slug))
	if err != nil {
		return nil, notFound(err)
	}
	o := orgToDomain(row)
	return &o, nil
}

func (r *Repo) UpdateOrganization(ctx context.Context, id string, changes domain.UpdateOrganization) (domain.Organization, error) {
	now := time.Now().UTC()
	updatedAt := ts(now)
	if changes.UpdatedAt != nil {
		updatedAt = ts(*changes.UpdatedAt)
	}
	var namePtr, slugPtr, slugLowerPtr *string
	if changes.Name != nil {
		namePtr = changes.Name
	}
	if changes.Slug != nil {
		slugPtr = changes.Slug
		lower := strings.ToLower(*changes.Slug)
		slugLowerPtr = &lower
	}

	params := pgxgen.UpdateOrganizationParams{
		ID:        id,
		UpdatedAt: updatedAt,
		Name:      namePtr,
		Slug:      slugPtr,
		SlugLower: slugLowerPtr,
	}
	if changes.DisplayName != nil {
		params.SetDisplayName = true
		params.DisplayName = *changes.DisplayName
	}
	if changes.AvatarURL != nil {
		params.SetAvatarUrl = true
		params.AvatarUrl = *changes.AvatarURL
	}
	if changes.Metadata != nil {
		params.SetMetadata = true
		params.Metadata = jsonStringPtr(*changes.Metadata)
	}

	row, err := r.q.UpdateOrganization(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Organization{}, yautherr.ErrNotFound
		}
		if isUniqueViolation(err) {
			return domain.Organization{}, yautherr.ErrConflict
		}
		return domain.Organization{}, err
	}
	return orgToDomain(row), nil
}

func (r *Repo) DeleteOrganization(ctx context.Context, id string) error {
	return r.withTx(ctx, func(tx pgx.Tx) error {
		q := pgxgen.New(tx)
		if _, err := tx.Exec(ctx, "DELETE FROM yauth_invitations WHERE organization_id = $1", id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM yauth_memberships WHERE organization_id = $1", id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM yauth_organization_domains WHERE organization_id = $1", id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM yauth_api_keys WHERE organization_id = $1", id); err != nil {
			return err
		}
		return q.DeleteOrganization(ctx, id)
	})
}

func (r *Repo) ListOrganizationsForUser(ctx context.Context, userID string) ([]*domain.Organization, error) {
	rows, err := r.q.ListOrganizationsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Organization, len(rows))
	for i, row := range rows {
		o := orgToDomain(row)
		out[i] = &o
	}
	return out, nil
}

func (r *Repo) ListOrganizations(ctx context.Context, search string, limit, offset int) ([]*domain.Organization, int64, error) {
	rows, err := r.q.ListOrganizationsSearch(ctx, pgxgen.ListOrganizationsSearchParams{
		Column1: search,
		Column2: int32(limit),
		Column3: int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.q.CountOrganizationsSearch(ctx, search)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*domain.Organization, len(rows))
	for i, row := range rows {
		o := orgToDomain(row)
		out[i] = &o
	}
	return out, total, nil
}

// ─── Membership ──────────────────────────────────────────────────────────────

func (r *Repo) CreateMembership(ctx context.Context, input domain.NewMembership) (domain.Membership, error) {
	row, err := r.q.CreateMembership(ctx, pgxgen.CreateMembershipParams{
		ID:             input.ID,
		OrganizationID: input.OrganizationID,
		UserID:         input.UserID,
		Role:           input.Role,
		Status:         string(input.Status),
		InvitedAt:      tsPtr(input.InvitedAt),
		JoinedAt:       tsPtr(input.JoinedAt),
		CreatedAt:      ts(input.CreatedAt),
		UpdatedAt:      ts(input.UpdatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.Membership{}, yautherr.ErrConflict
		}
		return domain.Membership{}, err
	}
	return membershipToDomain(row), nil
}

func (r *Repo) GetMembershipByID(ctx context.Context, id string) (*domain.Membership, error) {
	row, err := r.q.GetMembershipByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	m := membershipToDomain(row)
	return &m, nil
}

func (r *Repo) GetMembershipByOrgUser(ctx context.Context, orgID, userID string) (*domain.Membership, error) {
	row, err := r.q.GetMembershipByOrgUser(ctx, pgxgen.GetMembershipByOrgUserParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	m := membershipToDomain(row)
	return &m, nil
}

const pgxOwnerRole = "owner"

func (r *Repo) UpdateMembership(ctx context.Context, id string, changes domain.UpdateMembership) (domain.Membership, error) {
	var out domain.Membership
	err := r.withTx(ctx, func(tx pgx.Tx) error {
		q := pgxgen.New(tx)
		row, err := q.GetMembershipByID(ctx, id)
		if err != nil {
			return notFound(err)
		}
		if changes.Role != nil && row.Role == pgxOwnerRole && *changes.Role != pgxOwnerRole {
			count, err := q.CountOrgOwners(ctx, row.OrganizationID)
			if err != nil {
				return err
			}
			if count <= 1 {
				return yautherr.ErrOwnerProtected
			}
		}
		now := time.Now().UTC()
		updatedAt := ts(now)
		if changes.UpdatedAt != nil {
			updatedAt = ts(*changes.UpdatedAt)
		}
		params := pgxgen.UpdateMembershipParams{
			ID:        id,
			UpdatedAt: updatedAt,
		}
		if changes.Role != nil {
			params.Role = changes.Role
		}
		if changes.Status != nil {
			s := string(*changes.Status)
			params.Status = &s
		}
		if changes.JoinedAt != nil {
			params.SetJoinedAt = true
			params.JoinedAt = tsPtr(*changes.JoinedAt)
		}
		updated, err := q.UpdateMembership(ctx, params)
		if err != nil {
			return err
		}
		out = membershipToDomain(updated)
		return nil
	})
	if err != nil {
		return domain.Membership{}, err
	}
	return out, nil
}

func (r *Repo) DeleteMembership(ctx context.Context, id string) error {
	return r.withTx(ctx, func(tx pgx.Tx) error {
		q := pgxgen.New(tx)
		row, err := q.GetMembershipByID(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if row.Role == pgxOwnerRole {
			count, err := q.CountOrgOwners(ctx, row.OrganizationID)
			if err != nil {
				return err
			}
			if count <= 1 {
				return yautherr.ErrOwnerProtected
			}
		}
		_, err = q.DeleteMembership(ctx, id)
		return err
	})
}

func (r *Repo) ListMembershipsByOrg(ctx context.Context, orgID string) ([]*domain.Membership, error) {
	rows, err := r.q.ListMembershipsByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Membership, len(rows))
	for i, row := range rows {
		m := membershipToDomain(row)
		out[i] = &m
	}
	return out, nil
}

func (r *Repo) ListMembershipsByUser(ctx context.Context, userID string) ([]*domain.Membership, error) {
	rows, err := r.q.ListMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Membership, len(rows))
	for i, row := range rows {
		m := membershipToDomain(row)
		out[i] = &m
	}
	return out, nil
}

// ─── Invitation ──────────────────────────────────────────────────────────────

func (r *Repo) CreateInvitation(ctx context.Context, input domain.NewInvitation) (domain.Invitation, error) {
	row, err := r.q.CreateInvitation(ctx, pgxgen.CreateInvitationParams{
		ID:              input.ID,
		OrganizationID:  input.OrganizationID,
		Email:           input.Email,
		Role:            input.Role,
		TokenHash:       input.TokenHash,
		InvitedByUserID: input.InvitedByUserID,
		ExpiresAt:       ts(input.ExpiresAt),
		AcceptedAt:      tsPtr(input.AcceptedAt),
		CreatedAt:       ts(input.CreatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.Invitation{}, yautherr.ErrConflict
		}
		return domain.Invitation{}, err
	}
	return invitationToDomain(row), nil
}

func (r *Repo) GetInvitationByID(ctx context.Context, id string) (*domain.Invitation, error) {
	row, err := r.q.GetInvitationByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	inv := invitationToDomain(row)
	return &inv, nil
}

func (r *Repo) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*domain.Invitation, error) {
	row, err := r.q.GetInvitationByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	inv := invitationToDomain(row)
	return &inv, nil
}

func (r *Repo) MarkInvitationAccepted(ctx context.Context, id string, acceptedAt time.Time) (domain.Invitation, error) {
	var out domain.Invitation
	err := r.withTx(ctx, func(tx pgx.Tx) error {
		q := pgxgen.New(tx)
		row, err := q.MarkInvitationAccepted(ctx, pgxgen.MarkInvitationAcceptedParams{
			ID:         id,
			AcceptedAt: ts(acceptedAt),
		})
		if err != nil {
			return notFound(err)
		}
		out = invitationToDomain(row)
		return nil
	})
	if err != nil {
		return domain.Invitation{}, err
	}
	return out, nil
}

func (r *Repo) DeleteInvitation(ctx context.Context, id string) error {
	_, err := r.q.DeleteInvitation(ctx, id)
	return err
}

func (r *Repo) ListPendingInvitationsForOrg(ctx context.Context, orgID string) ([]*domain.Invitation, error) {
	rows, err := r.q.ListPendingInvitationsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Invitation, len(rows))
	for i, row := range rows {
		inv := invitationToDomain(row)
		out[i] = &inv
	}
	return out, nil
}

// ─── OrganizationDomain ──────────────────────────────────────────────────────

func (r *Repo) CreateOrganizationDomain(ctx context.Context, input domain.NewOrganizationDomain) (domain.OrganizationDomain, error) {
	canon := strings.ToLower(strings.TrimSpace(input.Domain))
	row, err := r.q.CreateOrganizationDomain(ctx, pgxgen.CreateOrganizationDomainParams{
		ID:                    input.ID,
		OrganizationID:        input.OrganizationID,
		Domain:                canon,
		DomainCanonical:       canon,
		Status:                string(input.Status),
		VerificationToken:     input.VerificationToken,
		VerifiedAt:            tsPtr(nil),
		LastCheckedAt:         tsPtr(nil),
		AutoJoinOnSignup:      input.AutoJoinOnSignup,
		DefaultRoleOnAutoJoin: input.DefaultRoleOnAutoJoin,
		RequireEmailVerified:  input.RequireEmailVerified,
		CreatedAt:             ts(input.CreatedAt),
		UpdatedAt:             ts(input.UpdatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.OrganizationDomain{}, yautherr.ErrConflict
		}
		return domain.OrganizationDomain{}, err
	}
	return orgDomainToDomain(row), nil
}

func (r *Repo) GetOrganizationDomainByID(ctx context.Context, id string) (*domain.OrganizationDomain, error) {
	row, err := r.q.GetOrganizationDomainByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	od := orgDomainToDomain(row)
	return &od, nil
}

func (r *Repo) GetOrganizationDomainByDomain(ctx context.Context, domainStr string) (*domain.OrganizationDomain, error) {
	canon := strings.ToLower(strings.TrimSpace(domainStr))
	row, err := r.q.GetOrganizationDomainByDomain(ctx, canon)
	if err != nil {
		return nil, notFound(err)
	}
	od := orgDomainToDomain(row)
	return &od, nil
}

func (r *Repo) ListOrganizationDomainsByOrg(ctx context.Context, organizationID string) ([]*domain.OrganizationDomain, error) {
	rows, err := r.q.ListOrganizationDomainsByOrg(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.OrganizationDomain, len(rows))
	for i, row := range rows {
		od := orgDomainToDomain(row)
		out[i] = &od
	}
	return out, nil
}

func (r *Repo) ListVerifiedAutoJoinOrganizationDomains(ctx context.Context, domainStr string) ([]*domain.OrganizationDomain, error) {
	canon := strings.ToLower(strings.TrimSpace(domainStr))
	rows, err := r.q.ListVerifiedAutoJoinOrganizationDomains(ctx, canon)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.OrganizationDomain, len(rows))
	for i, row := range rows {
		od := orgDomainToDomain(row)
		out[i] = &od
	}
	return out, nil
}

func (r *Repo) UpdateOrganizationDomain(ctx context.Context, id string, changes domain.UpdateOrganizationDomain) (domain.OrganizationDomain, error) {
	now := time.Now().UTC()
	updatedAt := ts(now)
	if changes.UpdatedAt != nil {
		updatedAt = ts(*changes.UpdatedAt)
	}
	params := pgxgen.UpdateOrganizationDomainParams{
		ID:        id,
		UpdatedAt: updatedAt,
	}
	if changes.AutoJoinOnSignup != nil {
		params.AutoJoinOnSignup = changes.AutoJoinOnSignup
	}
	if changes.DefaultRoleOnAutoJoin != nil {
		params.DefaultRoleOnAutoJoin = changes.DefaultRoleOnAutoJoin
	}
	if changes.RequireEmailVerified != nil {
		params.RequireEmailVerified = changes.RequireEmailVerified
	}
	row, err := r.q.UpdateOrganizationDomain(ctx, params)
	if err != nil {
		return domain.OrganizationDomain{}, notFound(err)
	}
	return orgDomainToDomain(row), nil
}

func (r *Repo) SetOrganizationDomainVerification(ctx context.Context, id string, status domain.DomainStatus, verifiedAt *time.Time, lastCheckedAt time.Time) (domain.OrganizationDomain, error) {
	row, err := r.q.SetOrganizationDomainVerification(ctx, pgxgen.SetOrganizationDomainVerificationParams{
		ID:            id,
		Status:        string(status),
		VerifiedAt:    tsPtr(verifiedAt),
		LastCheckedAt: ts(lastCheckedAt),
	})
	if err != nil {
		return domain.OrganizationDomain{}, notFound(err)
	}
	return orgDomainToDomain(row), nil
}

func (r *Repo) DeleteOrganizationDomain(ctx context.Context, id string) error {
	_, err := r.q.DeleteOrganizationDomain(ctx, id)
	return err
}

// ─── OrganizationPolicy ──────────────────────────────────────────────────────

func (r *Repo) GetOrganizationPolicy(ctx context.Context, organizationID string) (*domain.OrganizationPolicy, error) {
	row, err := r.q.GetOrganizationPolicy(ctx, organizationID)
	if err != nil {
		return nil, notFound(err)
	}
	op := orgPolicyToDomain(row)
	return &op, nil
}

func (r *Repo) CreateOrganizationPolicy(ctx context.Context, input domain.NewOrganizationPolicy) (domain.OrganizationPolicy, error) {
	binding := input.SessionBinding
	if !binding.IsValid() {
		binding = domain.SessionBindingUnset
	}
	row, err := r.q.CreateOrganizationPolicy(ctx, pgxgen.CreateOrganizationPolicyParams{
		OrganizationID:         input.OrganizationID,
		MaxSessionDurationSecs: input.MaxSessionDurationSecs,
		IdleTimeoutSecs:        input.IdleTimeoutSecs,
		MfaRequired:            input.MfaRequired,
		MfaGracePeriodDays:     input.MfaGracePeriodDays,
		IpAllowlistJson:        encodeStrSlice(input.IPAllowlist),
		MaxConcurrentSessions:  input.MaxConcurrentSessions,
		AuthMethodsJson:        encodeStrSlice(input.AllowedAuthMethods),
		SessionBinding:         string(binding),
		CreatedAt:              ts(input.CreatedAt),
		UpdatedAt:              ts(input.UpdatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.OrganizationPolicy{}, yautherr.ErrConflict
		}
		return domain.OrganizationPolicy{}, err
	}
	return orgPolicyToDomain(row), nil
}

func (r *Repo) UpdateOrganizationPolicy(ctx context.Context, organizationID string, changes domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error) {
	now := time.Now().UTC()
	updatedAt := ts(now)
	if changes.UpdatedAt != nil {
		updatedAt = ts(*changes.UpdatedAt)
	}
	params := pgxgen.UpdateOrganizationPolicyParams{
		OrganizationID: organizationID,
		UpdatedAt:      updatedAt,
	}
	applyOrgPolicyChanges(&params, changes)
	row, err := r.q.UpdateOrganizationPolicy(ctx, params)
	if err != nil {
		return domain.OrganizationPolicy{}, notFound(err)
	}
	return orgPolicyToDomain(row), nil
}

func (r *Repo) UpsertOrganizationPolicy(ctx context.Context, organizationID string, changes domain.UpdateOrganizationPolicy) (domain.OrganizationPolicy, error) {
	now := time.Now().UTC()
	updatedAt := ts(now)
	if changes.UpdatedAt != nil {
		updatedAt = ts(*changes.UpdatedAt)
	}
	// Build a NewOrganizationPolicy from changes, defaulting unset fields.
	p := pgxgen.UpsertOrganizationPolicyParams{
		OrganizationID: organizationID,
		SessionBinding: string(domain.SessionBindingUnset),
		CreatedAt:      updatedAt,
		UpdatedAt:      updatedAt,
	}
	if changes.MaxSessionDurationSecs != nil {
		p.MaxSessionDurationSecs = *changes.MaxSessionDurationSecs
	}
	if changes.IdleTimeoutSecs != nil {
		p.IdleTimeoutSecs = *changes.IdleTimeoutSecs
	}
	if changes.MfaRequired != nil {
		p.MfaRequired = *changes.MfaRequired
	}
	if changes.MfaGracePeriodDays != nil {
		p.MfaGracePeriodDays = *changes.MfaGracePeriodDays
	}
	if changes.IPAllowlist != nil {
		p.IpAllowlistJson = encodeStrSlice(*changes.IPAllowlist)
	}
	if changes.MaxConcurrentSessions != nil {
		p.MaxConcurrentSessions = *changes.MaxConcurrentSessions
	}
	if changes.AllowedAuthMethods != nil {
		p.AuthMethodsJson = encodeStrSlice(*changes.AllowedAuthMethods)
	}
	if changes.SessionBinding != nil && changes.SessionBinding.IsValid() {
		p.SessionBinding = string(*changes.SessionBinding)
	}
	row, err := r.q.UpsertOrganizationPolicy(ctx, p)
	if err != nil {
		return domain.OrganizationPolicy{}, err
	}
	return orgPolicyToDomain(row), nil
}

func (r *Repo) DeleteOrganizationPolicy(ctx context.Context, organizationID string) error {
	_, err := r.q.DeleteOrganizationPolicy(ctx, organizationID)
	return err
}

// ─── SsoConnection ───────────────────────────────────────────────────────────

func (r *Repo) CreateSsoConnection(ctx context.Context, input domain.NewSsoConnection) (domain.SsoConnection, error) {
	kind := input.Kind
	if !kind.IsValid() {
		kind = domain.ConnectionKindOIDCClient
	}
	status := input.Status
	if !status.IsValid() {
		status = domain.ConnectionStatusDraft
	}
	now := time.Now().UTC()
	createdAt := input.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := input.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = createdAt
	}
	row, err := r.q.CreateSsoConnection(ctx, pgxgen.CreateSsoConnectionParams{
		ID:                     input.ID,
		OrganizationID:         input.OrganizationID,
		Kind:                   string(kind),
		Name:                   input.Name,
		Status:                 string(status),
		Config:                 string(input.Config),
		JitProvisioningEnabled: input.JitProvisioningEnabled,
		DefaultRoleOnJit:       input.DefaultRoleOnJit,
		CreatedAt:              ts(createdAt),
		UpdatedAt:              ts(updatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.SsoConnection{}, yautherr.ErrConflict
		}
		return domain.SsoConnection{}, err
	}
	return ssoConnToDomain(row), nil
}

func (r *Repo) GetSsoConnectionByID(ctx context.Context, id string) (*domain.SsoConnection, error) {
	row, err := r.q.GetSsoConnectionByID(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	c := ssoConnToDomain(row)
	return &c, nil
}

func (r *Repo) ListSsoConnectionsByOrg(ctx context.Context, organizationID string) ([]*domain.SsoConnection, error) {
	rows, err := r.q.ListSsoConnectionsByOrg(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.SsoConnection, len(rows))
	for i, row := range rows {
		c := ssoConnToDomain(row)
		out[i] = &c
	}
	return out, nil
}

func (r *Repo) UpdateSsoConnection(ctx context.Context, id string, changes domain.UpdateSsoConnection) (domain.SsoConnection, error) {
	now := time.Now().UTC()
	updatedAt := ts(now)
	if changes.UpdatedAt != nil {
		updatedAt = ts(*changes.UpdatedAt)
	}
	params := pgxgen.UpdateSsoConnectionParams{
		ID:        id,
		UpdatedAt: updatedAt,
	}
	if changes.Name != nil {
		params.Name = changes.Name
	}
	if changes.Status != nil && changes.Status.IsValid() {
		s := string(*changes.Status)
		params.Status = &s
	}
	if changes.Config != nil {
		s := string(*changes.Config)
		params.Config = &s
	}
	if changes.JitProvisioningEnabled != nil {
		params.JitProvisioningEnabled = changes.JitProvisioningEnabled
	}
	if changes.DefaultRoleOnJit != nil {
		params.DefaultRoleOnJit = changes.DefaultRoleOnJit
	}
	row, err := r.q.UpdateSsoConnection(ctx, params)
	if err != nil {
		return domain.SsoConnection{}, notFound(err)
	}
	return ssoConnToDomain(row), nil
}

func (r *Repo) DeleteSsoConnection(ctx context.Context, id string) error {
	_, err := r.q.DeleteSsoConnection(ctx, id)
	return err
}

// ─── ExternalIdentity ────────────────────────────────────────────────────────

func (r *Repo) CreateExternalIdentity(ctx context.Context, input domain.NewExternalIdentity) (domain.ExternalIdentity, error) {
	now := time.Now().UTC()
	linked := input.LinkedAt
	if linked.IsZero() {
		linked = now
	}
	last := input.LastLoginAt
	if last.IsZero() {
		last = linked
	}
	row, err := r.q.CreateExternalIdentity(ctx, pgxgen.CreateExternalIdentityParams{
		ID:          input.ID,
		UserID:      input.UserID,
		Provider:    input.Provider,
		ExternalID:  input.ExternalID,
		LinkedAt:    ts(linked),
		LastLoginAt: ts(last),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ExternalIdentity{}, yautherr.ErrConflict
		}
		return domain.ExternalIdentity{}, err
	}
	return extIdentityToDomain(row), nil
}

func (r *Repo) GetExternalIdentityByProviderAndExternalID(ctx context.Context, provider, externalID string) (*domain.ExternalIdentity, error) {
	row, err := r.q.GetExternalIdentityByProviderAndExternalID(ctx, pgxgen.GetExternalIdentityByProviderAndExternalIDParams{
		Provider:   provider,
		ExternalID: externalID,
	})
	if err != nil {
		return nil, notFound(err)
	}
	ei := extIdentityToDomain(row)
	return &ei, nil
}

func (r *Repo) ListExternalIdentitiesByUser(ctx context.Context, userID string) ([]*domain.ExternalIdentity, error) {
	rows, err := r.q.ListExternalIdentitiesByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ExternalIdentity, len(rows))
	for i, row := range rows {
		ei := extIdentityToDomain(row)
		out[i] = &ei
	}
	return out, nil
}

func (r *Repo) UpdateExternalIdentityLastLogin(ctx context.Context, id string, at time.Time) error {
	n, err := r.q.UpdateExternalIdentityLastLogin(ctx, pgxgen.UpdateExternalIdentityLastLoginParams{
		ID:          id,
		LastLoginAt: ts(at),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

func (r *Repo) DeleteExternalIdentity(ctx context.Context, id string) error {
	_, err := r.q.DeleteExternalIdentity(ctx, id)
	return err
}

// ─── SsoLoginState ───────────────────────────────────────────────────────────

func (r *Repo) CreateSsoLoginState(ctx context.Context, input domain.NewSsoLoginState) error {
	now := time.Now().UTC()
	created := input.CreatedAt
	if created.IsZero() {
		created = now
	}
	return r.q.CreateSsoLoginState(ctx, pgxgen.CreateSsoLoginStateParams{
		State:        input.State,
		ConnectionID: input.ConnectionID,
		Nonce:        input.Nonce,
		PkceVerifier: input.PKCEVerifier,
		RedirectUrl:  input.RedirectURL,
		CreatedAt:    ts(created),
		ExpiresAt:    ts(input.ExpiresAt),
	})
}

func (r *Repo) ConsumeSsoLoginState(ctx context.Context, state string) (*domain.SsoLoginState, error) {
	row, err := r.q.ConsumeSsoLoginState(ctx, state)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if !row.ExpiresAt.Time.UTC().After(time.Now().UTC()) {
		return nil, nil
	}
	s := domain.SsoLoginState{
		State:        row.State,
		ConnectionID: row.ConnectionID,
		Nonce:        row.Nonce,
		PKCEVerifier: row.PkceVerifier,
		RedirectURL:  row.RedirectUrl,
		CreatedAt:    fromTS(row.CreatedAt),
		ExpiresAt:    fromTS(row.ExpiresAt),
	}
	return &s, nil
}

// ─── Domain mappers ──────────────────────────────────────────────────────────

func userToDomain(m pgxgen.YauthUser) domain.User {
	return domain.User{
		ID:            m.ID,
		Email:         m.Email,
		DisplayName:   m.DisplayName,
		EmailVerified: m.EmailVerified,
		Role:          m.Role,
		Banned:        m.Banned,
		BannedReason:  m.BannedReason,
		BannedUntil:   fromTSPtr(m.BannedUntil),
		CreatedAt:     fromTS(m.CreatedAt),
		UpdatedAt:     fromTS(m.UpdatedAt),
	}
}

func sessionToDomain(m pgxgen.YauthSession) domain.Session {
	return domain.Session{
		ID:          m.ID,
		UserID:      m.UserID,
		TokenHash:   m.TokenHash,
		IPAddress:   m.IpAddress,
		UserAgent:   m.UserAgent,
		ActiveOrgID: m.ActiveOrgID,
		ExpiresAt:   fromTS(m.ExpiresAt),
		CreatedAt:   fromTS(m.CreatedAt),
	}
}

func magicLinkToDomain(m pgxgen.YauthMagicLink) domain.MagicLink {
	return domain.MagicLink{
		ID:        m.ID,
		Email:     m.Email,
		TokenHash: m.TokenHash,
		ExpiresAt: fromTS(m.ExpiresAt),
		Used:      m.Used,
		CreatedAt: fromTS(m.CreatedAt),
	}
}

func passKeyToDomain(m pgxgen.YauthWebauthnCredential) domain.WebauthnCredential {
	return domain.WebauthnCredential{
		ID:         m.ID,
		UserID:     m.UserID,
		Name:       m.Name,
		AAGUID:     m.Aaguid,
		DeviceName: m.DeviceName,
		Credential: json.RawMessage(m.Credential),
		CreatedAt:  fromTS(m.CreatedAt),
		LastUsedAt: fromTSPtr(m.LastUsedAt),
	}
}

func oauthAccountToDomain(m pgxgen.YauthOauthAccount) domain.OAuthAccount {
	return domain.OAuthAccount{
		ID:              m.ID,
		UserID:          m.UserID,
		Provider:        m.Provider,
		ProviderUserID:  m.ProviderUserID,
		AccessTokenEnc:  m.AccessTokenEnc,
		RefreshTokenEnc: m.RefreshTokenEnc,
		CreatedAt:       fromTS(m.CreatedAt),
		ExpiresAt:       fromTSPtr(m.ExpiresAt),
		UpdatedAt:       fromTS(m.UpdatedAt),
	}
}

func apiKeyToDomain(m pgxgen.YauthApiKey) domain.APIKey {
	return domain.APIKey{
		ID:              m.ID,
		UserID:          copyStrPtr(m.UserID),
		OrganizationID:  copyStrPtr(m.OrganizationID),
		KeyPrefix:       m.KeyPrefix,
		KeyHash:         m.KeyHash,
		Name:            m.Name,
		Scopes:          jsonBytesPtr(m.Scopes),
		Role:            copyStrPtr(m.Role),
		LastUsedAt:      fromTSPtr(m.LastUsedAt),
		ExpiresAt:       fromTSPtr(m.ExpiresAt),
		CreatedAt:       fromTS(m.CreatedAt),
		CreatedByUserID: m.CreatedByUserID,
	}
}

func oauth2ClientToDomain(m pgxgen.YauthOauth2Client) domain.OAuth2Client {
	return domain.OAuth2Client{
		ID:                      m.ID,
		ClientID:                m.ClientID,
		ClientSecretHash:        m.ClientSecretHash,
		RedirectURIs:            json.RawMessage(m.RedirectUris),
		ClientName:              m.ClientName,
		GrantTypes:              json.RawMessage(m.GrantTypes),
		Scopes:                  jsonBytesPtr(m.Scopes),
		IsPublic:                m.IsPublic,
		CreatedAt:               fromTS(m.CreatedAt),
		TokenEndpointAuthMethod: m.TokenEndpointAuthMethod,
		PublicKeyPEM:            m.PublicKeyPem,
		JWKSURI:                 m.JwksUri,
		BannedAt:                fromTSPtr(m.BannedAt),
		BannedReason:            m.BannedReason,
	}
}

func authCodeToDomain(m pgxgen.YauthAuthorizationCode) domain.AuthorizationCode {
	return domain.AuthorizationCode{
		ID:                  m.ID,
		CodeHash:            m.CodeHash,
		ClientID:            m.ClientID,
		UserID:              m.UserID,
		Scopes:              jsonBytesPtr(m.Scopes),
		RedirectURI:         m.RedirectUri,
		CodeChallenge:       m.CodeChallenge,
		CodeChallengeMethod: m.CodeChallengeMethod,
		ExpiresAt:           fromTS(m.ExpiresAt),
		Used:                m.Used,
		Nonce:               m.Nonce,
		CreatedAt:           fromTS(m.CreatedAt),
	}
}

func deviceCodeToDomain(m pgxgen.YauthDeviceCode) domain.DeviceCode {
	return domain.DeviceCode{
		ID:             m.ID,
		DeviceCodeHash: m.DeviceCodeHash,
		UserCode:       m.UserCode,
		ClientID:       m.ClientID,
		Scopes:         jsonBytesPtr(m.Scopes),
		UserID:         m.UserID,
		Status:         m.Status,
		Interval:       int(m.Interval),
		ExpiresAt:      fromTS(m.ExpiresAt),
		LastPolledAt:   fromTSPtr(m.LastPolledAt),
		CreatedAt:      fromTS(m.CreatedAt),
	}
}

func accountLockToDomain(m pgxgen.YauthAccountLock) domain.AccountLock {
	return domain.AccountLock{
		ID:           m.ID,
		UserID:       m.UserID,
		FailedCount:  int(m.FailedCount),
		LockedUntil:  fromTSPtr(m.LockedUntil),
		LockCount:    int(m.LockCount),
		LockedReason: m.LockedReason,
		CreatedAt:    fromTS(m.CreatedAt),
		UpdatedAt:    fromTS(m.UpdatedAt),
	}
}

func webhookToDomain(m pgxgen.YauthWebhook) domain.Webhook {
	return domain.Webhook{
		ID:        m.ID,
		URL:       m.Url,
		Secret:    m.Secret,
		Events:    json.RawMessage(m.Events),
		Active:    m.Active,
		CreatedAt: fromTS(m.CreatedAt),
		UpdatedAt: fromTS(m.UpdatedAt),
	}
}

func orgToDomain(m pgxgen.YauthOrganization) domain.Organization {
	return domain.Organization{
		ID:          m.ID,
		Name:        m.Name,
		Slug:        m.Slug,
		DisplayName: m.DisplayName,
		AvatarURL:   m.AvatarUrl,
		Metadata:    jsonBytesPtr(m.Metadata),
		CreatedAt:   fromTS(m.CreatedAt),
		UpdatedAt:   fromTS(m.UpdatedAt),
	}
}

func membershipToDomain(m pgxgen.YauthMembership) domain.Membership {
	return domain.Membership{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		UserID:         m.UserID,
		Role:           m.Role,
		Status:         domain.MembershipStatus(m.Status),
		InvitedAt:      fromTSPtr(m.InvitedAt),
		JoinedAt:       fromTSPtr(m.JoinedAt),
		CreatedAt:      fromTS(m.CreatedAt),
		UpdatedAt:      fromTS(m.UpdatedAt),
	}
}

func invitationToDomain(m pgxgen.YauthInvitation) domain.Invitation {
	return domain.Invitation{
		ID:              m.ID,
		OrganizationID:  m.OrganizationID,
		Email:           m.Email,
		Role:            m.Role,
		TokenHash:       m.TokenHash,
		InvitedByUserID: m.InvitedByUserID,
		ExpiresAt:       fromTS(m.ExpiresAt),
		AcceptedAt:      fromTSPtr(m.AcceptedAt),
		CreatedAt:       fromTS(m.CreatedAt),
	}
}

func orgDomainToDomain(m pgxgen.YauthOrganizationDomain) domain.OrganizationDomain {
	return domain.OrganizationDomain{
		ID:                    m.ID,
		OrganizationID:        m.OrganizationID,
		Domain:                m.Domain,
		Status:                domain.DomainStatus(m.Status),
		VerificationToken:     m.VerificationToken,
		VerifiedAt:            fromTSPtr(m.VerifiedAt),
		LastCheckedAt:         fromTSPtr(m.LastCheckedAt),
		AutoJoinOnSignup:      m.AutoJoinOnSignup,
		DefaultRoleOnAutoJoin: m.DefaultRoleOnAutoJoin,
		RequireEmailVerified:  m.RequireEmailVerified,
		CreatedAt:             fromTS(m.CreatedAt),
		UpdatedAt:             fromTS(m.UpdatedAt),
	}
}

func orgPolicyToDomain(m pgxgen.YauthOrganizationPolicy) domain.OrganizationPolicy {
	binding, _ := domain.ParseSessionBindingMode(m.SessionBinding)
	return domain.OrganizationPolicy{
		OrganizationID:         m.OrganizationID,
		MaxSessionDurationSecs: m.MaxSessionDurationSecs,
		IdleTimeoutSecs:        m.IdleTimeoutSecs,
		MfaRequired:            m.MfaRequired,
		MfaGracePeriodDays:     m.MfaGracePeriodDays,
		IPAllowlist:            decodeStrSlice(m.IpAllowlistJson),
		MaxConcurrentSessions:  m.MaxConcurrentSessions,
		AllowedAuthMethods:     decodeStrSlice(m.AuthMethodsJson),
		SessionBinding:         binding,
		CreatedAt:              fromTS(m.CreatedAt),
		UpdatedAt:              fromTS(m.UpdatedAt),
	}
}

func ssoConnToDomain(m pgxgen.YauthSsoConnection) domain.SsoConnection {
	kind, _ := domain.ParseConnectionKind(m.Kind)
	status, _ := domain.ParseConnectionStatus(m.Status)
	return domain.SsoConnection{
		ID:                     m.ID,
		OrganizationID:         m.OrganizationID,
		Kind:                   kind,
		Name:                   m.Name,
		Status:                 status,
		Config:                 []byte(m.Config),
		JitProvisioningEnabled: m.JitProvisioningEnabled,
		DefaultRoleOnJit:       m.DefaultRoleOnJit,
		CreatedAt:              fromTS(m.CreatedAt),
		UpdatedAt:              fromTS(m.UpdatedAt),
	}
}

func extIdentityToDomain(m pgxgen.YauthExternalIdentity) domain.ExternalIdentity {
	return domain.ExternalIdentity{
		ID:          m.ID,
		UserID:      m.UserID,
		Provider:    m.Provider,
		ExternalID:  m.ExternalID,
		LinkedAt:    fromTS(m.LinkedAt),
		LastLoginAt: fromTS(m.LastLoginAt),
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func jsonStringPtr(b json.RawMessage) *string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	return &s
}

func jsonBytesPtr(s *string) json.RawMessage {
	if s == nil {
		return nil
	}
	return json.RawMessage(*s)
}

func copyStrPtr(s *string) *string {
	if s == nil {
		return nil
	}
	v := *s
	return &v
}

func encodeStrSlice(s []string) *string {
	if len(s) == 0 {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	v := string(b)
	return &v
}

func decodeStrSlice(p *string) []string {
	if p == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*p)
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return nil
	}
	return out
}

func applyOrgPolicyChanges(p *pgxgen.UpdateOrganizationPolicyParams, changes domain.UpdateOrganizationPolicy) {
	if changes.MaxSessionDurationSecs != nil {
		p.SetMaxSession = true
		p.MaxSessionDurationSecs = *changes.MaxSessionDurationSecs
	}
	if changes.IdleTimeoutSecs != nil {
		p.SetIdleTimeout = true
		p.IdleTimeoutSecs = *changes.IdleTimeoutSecs
	}
	if changes.MfaRequired != nil {
		p.MfaRequired = changes.MfaRequired
	}
	if changes.MfaGracePeriodDays != nil {
		p.MfaGracePeriodDays = changes.MfaGracePeriodDays
	}
	if changes.IPAllowlist != nil {
		p.SetIpAllowlist = true
		p.IpAllowlistJson = encodeStrSlice(*changes.IPAllowlist)
	}
	if changes.MaxConcurrentSessions != nil {
		p.SetMaxConcurrent = true
		p.MaxConcurrentSessions = *changes.MaxConcurrentSessions
	}
	if changes.AllowedAuthMethods != nil {
		p.SetAuthMethods = true
		p.AuthMethodsJson = encodeStrSlice(*changes.AllowedAuthMethods)
	}
	if changes.SessionBinding != nil && changes.SessionBinding.IsValid() {
		s := string(*changes.SessionBinding)
		p.SessionBinding = &s
	}
}
