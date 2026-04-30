package domain

import "time"

// User is a registered account.
type User struct {
	ID            string
	Email         string
	DisplayName   *string
	EmailVerified bool
	Role          string
	Banned        bool
	BannedReason  *string
	BannedUntil   *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NewUser is the input for creating a user.
type NewUser struct {
	ID            string
	Email         string
	DisplayName   *string
	EmailVerified bool
	Role          string
	Banned        bool
	BannedReason  *string
	BannedUntil   *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// UpdateUser is a partial update payload; nil fields are unchanged.
type UpdateUser struct {
	Email         *string
	DisplayName   **string
	EmailVerified *bool
	Role          *string
	Banned        *bool
	BannedReason  **string
	BannedUntil   **time.Time
	UpdatedAt     *time.Time
}
