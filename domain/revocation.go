package domain

import "time"

// Revocation is a revoked bearer/JWT token id (jti) with an absolute TTL.
type Revocation struct {
	Key       string
	ExpiresAt time.Time
}
