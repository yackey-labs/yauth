package gormrepo

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var _ repo.Repository = (*Repo)(nil)

// Repo is a GORM-backed implementation of repo.Repository.
//
// Lookup methods returning (*T, error) return (nil, yautherr.ErrNotFound) on
// not-found; they never return (nil, nil).
type Repo struct {
	db *gorm.DB
}

// New returns a Repo bound to the given GORM DB.
func New(db *gorm.DB) *Repo { return &Repo{db: db} }

func (r *Repo) ctx(ctx context.Context) *gorm.DB { return r.db.WithContext(ctx) }

// --- User ---

func (r *Repo) CreateUser(ctx context.Context, input domain.NewUser) (domain.User, error) {
	m := userFromDomain(input)
	if err := r.ctx(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return domain.User{}, yautherr.ErrUserExists
		}
		return domain.User{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	var m User
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	var m User
	if err := r.ctx(ctx).Where("email = ?", email).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) UpdateUser(ctx context.Context, id string, changes domain.UpdateUser) (domain.User, error) {
	updates := map[string]any{}
	if changes.Email != nil {
		updates["email"] = *changes.Email
	}
	if changes.DisplayName != nil {
		updates["display_name"] = *changes.DisplayName
	}
	if changes.EmailVerified != nil {
		updates["email_verified"] = *changes.EmailVerified
	}
	if changes.Role != nil {
		updates["role"] = *changes.Role
	}
	if changes.Banned != nil {
		updates["banned"] = *changes.Banned
	}
	if changes.BannedReason != nil {
		updates["banned_reason"] = *changes.BannedReason
	}
	if changes.BannedUntil != nil {
		if v := *changes.BannedUntil; v != nil {
			u := v.UTC()
			updates["banned_until"] = &u
		} else {
			updates["banned_until"] = nil
		}
	}
	if changes.SuspendedAt != nil {
		if v := *changes.SuspendedAt; v != nil {
			u := v.UTC()
			updates["suspended_at"] = &u
		} else {
			updates["suspended_at"] = nil
		}
	}
	if changes.SuspendedReason != nil {
		updates["suspended_reason"] = *changes.SuspendedReason
	}
	if changes.ActivatesAt != nil {
		if v := *changes.ActivatesAt; v != nil {
			u := v.UTC()
			updates["activates_at"] = &u
		} else {
			updates["activates_at"] = nil
		}
	}
	if changes.UpdatedAt != nil {
		updates["updated_at"] = changes.UpdatedAt.UTC()
	}

	tx := r.ctx(ctx).Model(&User{}).Where("id = ?", id)
	if len(updates) > 0 {
		res := tx.Updates(updates)
		if res.Error != nil {
			if isUniqueViolation(res.Error) {
				return domain.User{}, yautherr.ErrUserExists
			}
			return domain.User{}, res.Error
		}
		if res.RowsAffected == 0 {
			return domain.User{}, yautherr.ErrNotFound
		}
	}

	var m User
	if err := r.ctx(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.User{}, yautherr.ErrNotFound
		}
		return domain.User{}, err
	}
	return m.toDomain(), nil
}

func (r *Repo) DeleteUser(ctx context.Context, id string) error {
	res := r.ctx(ctx).Where("id = ?", id).Delete(&User{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- Session ---

func (r *Repo) CreateSession(ctx context.Context, input domain.NewSession) error {
	m := sessionFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	var m Session
	if err := r.ctx(ctx).Where("token_hash = ?", tokenHash).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

func (r *Repo) DeleteSession(ctx context.Context, tokenHash string) (bool, error) {
	res := r.ctx(ctx).Where("token_hash = ?", tokenHash).Delete(&Session{})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *Repo) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	res := r.ctx(ctx).Where("user_id = ?", userID).Delete(&Session{})
	return res.RowsAffected, res.Error
}

func (r *Repo) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res := r.ctx(ctx).Where("expires_at <= ?", now.UTC()).Delete(&Session{})
	return res.RowsAffected, res.Error
}

// SetSessionActiveOrg writes the session's active_org_id column. nil
// clears it. yauth Rust #89 / Go #15.
func (r *Repo) SetSessionActiveOrg(ctx context.Context, sessionID string, activeOrgID *string) error {
	res := r.ctx(ctx).Model(&Session{}).Where("id = ?", sessionID).
		Update("active_org_id", activeOrgID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return yautherr.ErrNotFound
	}
	return nil
}

// --- Password ---

func (r *Repo) UpsertPassword(ctx context.Context, input domain.NewPassword) error {
	m := passwordFromDomain(input)
	return r.ctx(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"password_hash"}),
	}).Create(&m).Error
}

func (r *Repo) GetPasswordByUserID(ctx context.Context, userID string) (*domain.Password, error) {
	var m Password
	if err := r.ctx(ctx).Where("user_id = ?", userID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, yautherr.ErrNotFound
		}
		return nil, err
	}
	d := m.toDomain()
	return &d, nil
}

// --- PasswordHistory ---

func (r *Repo) AppendPasswordHistory(ctx context.Context, input domain.NewPasswordHistory) error {
	m := passwordHistoryFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) GetPasswordHistory(ctx context.Context, userID string, n int) ([]*domain.PasswordHistory, error) {
	if n <= 0 {
		return nil, nil
	}
	var rows []PasswordHistory
	if err := r.ctx(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(n).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.PasswordHistory, 0, len(rows))
	for i := range rows {
		d := rows[i].toDomain()
		out = append(out, &d)
	}
	return out, nil
}

func (r *Repo) TrimPasswordHistory(ctx context.Context, userID string, keep int) (int64, error) {
	if keep <= 0 {
		res := r.ctx(ctx).Where("user_id = ?", userID).Delete(&PasswordHistory{})
		return res.RowsAffected, res.Error
	}
	// Find IDs of the rows to keep, then delete everything else.
	var keepIDs []string
	if err := r.ctx(ctx).
		Model(&PasswordHistory{}).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(keep).
		Pluck("id", &keepIDs).Error; err != nil {
		return 0, err
	}
	q := r.ctx(ctx).Where("user_id = ?", userID)
	if len(keepIDs) > 0 {
		q = q.Where("id NOT IN ?", keepIDs)
	}
	res := q.Delete(&PasswordHistory{})
	return res.RowsAffected, res.Error
}

// --- EmailVerification ---

func (r *Repo) CreateEmailVerification(ctx context.Context, input domain.NewEmailVerification) error {
	m := emailVerificationFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) ConsumeEmailVerification(ctx context.Context, tokenHash string) (*domain.EmailVerification, error) {
	var out *domain.EmailVerification
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m EmailVerification
		q := tx.Where("token_hash = ?", tokenHash)
		switch tx.Dialector.Name() {
		case "postgres", "mysql":
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		if !m.ExpiresAt.UTC().After(time.Now().UTC()) {
			if err := tx.Where("id = ?", m.ID).Delete(&EmailVerification{}).Error; err != nil {
				return err
			}
			return yautherr.ErrNotFound
		}
		if err := tx.Where("id = ?", m.ID).Delete(&EmailVerification{}).Error; err != nil {
			return err
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

// --- PasswordReset ---

func (r *Repo) CreatePasswordReset(ctx context.Context, input domain.NewPasswordReset) error {
	m := passwordResetFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

func (r *Repo) ConsumePasswordReset(ctx context.Context, tokenHash string) (*domain.PasswordReset, error) {
	var out *domain.PasswordReset
	err := r.ctx(ctx).Transaction(func(tx *gorm.DB) error {
		var m PasswordReset
		q := tx.Where("token_hash = ?", tokenHash)
		switch tx.Dialector.Name() {
		case "postgres", "mysql":
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return yautherr.ErrNotFound
			}
			return err
		}
		now := time.Now().UTC()
		if m.UsedAt != nil {
			return yautherr.ErrNotFound
		}
		if !m.ExpiresAt.UTC().After(now) {
			return yautherr.ErrNotFound
		}
		if err := tx.Model(&PasswordReset{}).
			Where("id = ? AND used_at IS NULL", m.ID).
			Update("used_at", now).Error; err != nil {
			return err
		}
		m.UsedAt = &now
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

// --- AuditLog ---

func (r *Repo) LogAuditEvent(ctx context.Context, input domain.NewAuditLog) error {
	m := auditLogFromDomain(input)
	return r.ctx(ctx).Create(&m).Error
}

// isUniqueViolation matches both PG (SQLSTATE 23505) and SQLite UNIQUE
// constraint errors via string sniffing — keeps the package driver-agnostic.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") ||
		strings.Contains(msg, "duplicate") ||
		strings.Contains(msg, "23505")
}
