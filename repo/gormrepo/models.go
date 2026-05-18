package gormrepo

import (
	"time"

	"github.com/yackey-labs/yauth-go/domain"
)

// User mirrors yauth_users.
type User struct {
	ID            string     `gorm:"column:id;primaryKey"`
	Email         string     `gorm:"column:email;not null;uniqueIndex"`
	DisplayName   *string    `gorm:"column:display_name"`
	EmailVerified bool       `gorm:"column:email_verified;not null"`
	Role          string     `gorm:"column:role;not null;default:user"`
	Banned        bool       `gorm:"column:banned;not null"`
	BannedReason  *string    `gorm:"column:banned_reason"`
	BannedUntil   *time.Time `gorm:"column:banned_until"`
	CreatedAt     time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt     time.Time  `gorm:"column:updated_at;not null"`
}

func (User) TableName() string { return "yauth_users" }

func (m *User) toDomain() domain.User {
	return domain.User{
		ID:            m.ID,
		Email:         m.Email,
		DisplayName:   m.DisplayName,
		EmailVerified: m.EmailVerified,
		Role:          m.Role,
		Banned:        m.Banned,
		BannedReason:  m.BannedReason,
		BannedUntil:   ptrUTC(m.BannedUntil),
		CreatedAt:     m.CreatedAt.UTC(),
		UpdatedAt:     m.UpdatedAt.UTC(),
	}
}

func userFromDomain(in domain.NewUser) User {
	return User{
		ID:            in.ID,
		Email:         in.Email,
		DisplayName:   in.DisplayName,
		EmailVerified: in.EmailVerified,
		Role:          in.Role,
		Banned:        in.Banned,
		BannedReason:  in.BannedReason,
		BannedUntil:   ptrUTC(in.BannedUntil),
		CreatedAt:     in.CreatedAt.UTC(),
		UpdatedAt:     in.UpdatedAt.UTC(),
	}
}

// Session mirrors yauth_sessions.
type Session struct {
	ID        string  `gorm:"column:id;primaryKey"`
	UserID    string  `gorm:"column:user_id;not null;index"`
	TokenHash string  `gorm:"column:token_hash;not null;uniqueIndex"`
	IPAddress *string `gorm:"column:ip_address"`
	UserAgent *string `gorm:"column:user_agent"`
	// ActiveOrgID is the org this session is currently operating under.
	// NULL = no active org. yauth Rust #89 / Go #15.
	ActiveOrgID *string   `gorm:"column:active_org_id;index"`
	ExpiresAt   time.Time `gorm:"column:expires_at;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
}

func (Session) TableName() string { return "yauth_sessions" }

func (m *Session) toDomain() domain.Session {
	return domain.Session{
		ID:          m.ID,
		UserID:      m.UserID,
		TokenHash:   m.TokenHash,
		IPAddress:   m.IPAddress,
		UserAgent:   m.UserAgent,
		ActiveOrgID: m.ActiveOrgID,
		ExpiresAt:   m.ExpiresAt.UTC(),
		CreatedAt:   m.CreatedAt.UTC(),
	}
}

func sessionFromDomain(in domain.NewSession) Session {
	return Session{
		ID:          in.ID,
		UserID:      in.UserID,
		TokenHash:   in.TokenHash,
		IPAddress:   in.IPAddress,
		UserAgent:   in.UserAgent,
		ActiveOrgID: in.ActiveOrgID,
		ExpiresAt:   in.ExpiresAt.UTC(),
		CreatedAt:   in.CreatedAt.UTC(),
	}
}

// Password mirrors yauth_passwords.
type Password struct {
	UserID       string `gorm:"column:user_id;primaryKey"`
	PasswordHash string `gorm:"column:password_hash;not null"`
}

func (Password) TableName() string { return "yauth_passwords" }

func (m *Password) toDomain() domain.Password {
	return domain.Password{
		UserID:       m.UserID,
		PasswordHash: m.PasswordHash,
	}
}

func passwordFromDomain(in domain.NewPassword) Password {
	return Password{
		UserID:       in.UserID,
		PasswordHash: in.PasswordHash,
	}
}

// EmailVerification mirrors yauth_email_verifications.
type EmailVerification struct {
	ID        string    `gorm:"column:id;primaryKey"`
	UserID    string    `gorm:"column:user_id;index"`
	TokenHash string    `gorm:"column:token_hash;not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (EmailVerification) TableName() string { return "yauth_email_verifications" }

func (m *EmailVerification) toDomain() domain.EmailVerification {
	return domain.EmailVerification{
		ID:        m.ID,
		UserID:    m.UserID,
		TokenHash: m.TokenHash,
		ExpiresAt: m.ExpiresAt.UTC(),
		CreatedAt: m.CreatedAt.UTC(),
	}
}

func emailVerificationFromDomain(in domain.NewEmailVerification) EmailVerification {
	return EmailVerification{
		ID:        in.ID,
		UserID:    in.UserID,
		TokenHash: in.TokenHash,
		ExpiresAt: in.ExpiresAt.UTC(),
		CreatedAt: in.CreatedAt.UTC(),
	}
}

// PasswordReset mirrors yauth_password_resets.
type PasswordReset struct {
	ID        string     `gorm:"column:id;primaryKey"`
	UserID    string     `gorm:"column:user_id;index"`
	TokenHash string     `gorm:"column:token_hash;not null;uniqueIndex"`
	ExpiresAt time.Time  `gorm:"column:expires_at;not null"`
	UsedAt    *time.Time `gorm:"column:used_at"`
	CreatedAt time.Time  `gorm:"column:created_at;not null"`
}

func (PasswordReset) TableName() string { return "yauth_password_resets" }

func (m *PasswordReset) toDomain() domain.PasswordReset {
	return domain.PasswordReset{
		ID:        m.ID,
		UserID:    m.UserID,
		TokenHash: m.TokenHash,
		ExpiresAt: m.ExpiresAt.UTC(),
		UsedAt:    ptrUTC(m.UsedAt),
		CreatedAt: m.CreatedAt.UTC(),
	}
}

func passwordResetFromDomain(in domain.NewPasswordReset) PasswordReset {
	return PasswordReset{
		ID:        in.ID,
		UserID:    in.UserID,
		TokenHash: in.TokenHash,
		ExpiresAt: in.ExpiresAt.UTC(),
		CreatedAt: in.CreatedAt.UTC(),
	}
}

// PasswordHistory mirrors yauth_password_history.
type PasswordHistory struct {
	ID           string    `gorm:"column:id;primaryKey"`
	UserID       string    `gorm:"column:user_id;index"`
	PasswordHash string    `gorm:"column:password_hash;not null"`
	CreatedAt    time.Time `gorm:"column:created_at;not null;index"`
}

func (PasswordHistory) TableName() string { return "yauth_password_history" }

func (m *PasswordHistory) toDomain() domain.PasswordHistory {
	return domain.PasswordHistory{
		ID:           m.ID,
		UserID:       m.UserID,
		PasswordHash: m.PasswordHash,
		CreatedAt:    m.CreatedAt.UTC(),
	}
}

func passwordHistoryFromDomain(in domain.NewPasswordHistory) PasswordHistory {
	return PasswordHistory{
		ID:           in.ID,
		UserID:       in.UserID,
		PasswordHash: in.PasswordHash,
		CreatedAt:    in.CreatedAt.UTC(),
	}
}

// AuditLog mirrors yauth_audit_log. Metadata is stored as TEXT (JSON string).
type AuditLog struct {
	ID        string    `gorm:"column:id;primaryKey"`
	UserID    *string   `gorm:"column:user_id;index"`
	EventType string    `gorm:"column:event_type;not null"`
	Metadata  *string   `gorm:"column:metadata;type:text"`
	IPAddress *string   `gorm:"column:ip_address"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (AuditLog) TableName() string { return "yauth_audit_log" }

func auditLogFromDomain(in domain.NewAuditLog) AuditLog {
	var meta *string
	if len(in.Metadata) > 0 {
		s := string(in.Metadata)
		meta = &s
	}
	return AuditLog{
		ID:        in.ID,
		UserID:    in.UserID,
		EventType: in.EventType,
		Metadata:  meta,
		IPAddress: in.IPAddress,
		CreatedAt: in.CreatedAt.UTC(),
	}
}

func ptrUTC(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
