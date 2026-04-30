package domain

import "time"

// AccountLock tracks failed-login state and lockout windows for a user.
type AccountLock struct {
	ID           string
	UserID       string
	FailedCount  int
	LockedUntil  *time.Time
	LockCount    int
	LockedReason *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NewAccountLock is the input for inserting an account lock.
type NewAccountLock struct {
	ID           string
	UserID       string
	FailedCount  int
	LockedUntil  *time.Time
	LockCount    int
	LockedReason *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// LockState is the result of a "set locked" mutation, capturing the new
// locked_until / reason / lock_count atomically applied to a lock row.
type LockState struct {
	LockedUntil  *time.Time
	LockedReason *string
	LockCount    int
}

// UnlockToken is a single-use token that lifts an account lock.
type UnlockToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewUnlockToken is the input for creating an unlock token.
type NewUnlockToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}
