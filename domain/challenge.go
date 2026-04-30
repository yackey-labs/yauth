package domain

import "time"

// Challenge is an ephemeral key/value record (CSRF, WebAuthn, MFA) with TTL.
type Challenge struct {
	Key       string
	Value     string
	ExpiresAt time.Time
}

// NewChallenge is the input for setting a challenge.
type NewChallenge struct {
	Key       string
	Value     string
	ExpiresAt time.Time
}
