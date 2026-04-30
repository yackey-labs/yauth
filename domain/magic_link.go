package domain

import "time"

// MagicLink is a single-use, time-limited passwordless login token.
type MagicLink struct {
	ID        string
	Email     string
	TokenHash string
	ExpiresAt time.Time
	Used      bool
	CreatedAt time.Time
}

// NewMagicLink is the input for creating a magic link.
type NewMagicLink struct {
	ID        string
	Email     string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}
