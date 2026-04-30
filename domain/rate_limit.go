package domain

import "time"

// RateLimitResult is the outcome of a rate-limit check.
type RateLimitResult struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}
