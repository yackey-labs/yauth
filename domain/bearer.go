package domain

import "time"

// RefreshToken is a JWT refresh token tracked for rotation and reuse detection.
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	FamilyID  string
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}

// NewRefreshToken is the input for creating a refresh token.
type NewRefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	FamilyID  string
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}
