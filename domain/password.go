package domain

import "time"

// Password is a user's stored password hash.
type Password struct {
	UserID       string
	PasswordHash string
}

// NewPassword is the input for upserting a password.
type NewPassword struct {
	UserID       string
	PasswordHash string
}

// EmailVerification is a pending email-verification token.
type EmailVerification struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewEmailVerification is the input for creating an email verification.
type NewEmailVerification struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// PasswordReset is a pending password-reset token.
type PasswordReset struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// NewPasswordReset is the input for creating a password reset.
type NewPasswordReset struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}
