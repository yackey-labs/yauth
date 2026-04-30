package yauth

import "time"

// YAuthConfig holds runtime configuration for yauth-go.
type YAuthConfig struct {
	SessionTTL     time.Duration
	CookieName     string
	CookieDomain   string
	CookieSecure   bool
	CookiePath     string
	CookieSameSite string // "Lax" | "Strict" | "None"

	// SessionBinding controls IP and User-Agent hijack detection on
	// cookie-resolved sessions. Disabled by default.
	SessionBinding SessionBindingConfig

	// RateLimit holds per-operation rate-limit windows. Plugins read
	// these via PluginHost.RateLimit when wrapping their handlers.
	RateLimit RateLimitConfig
}

// SessionBindingConfig is the IP/UA binding policy. Action values are
// "warn" (log + audit, allow), "invalidate" (delete session, return
// unauthorized), or "" (treated as warn — only the bind flag enables
// the check).
type SessionBindingConfig struct {
	BindIP           bool
	BindUA           bool
	IPMismatchAction string
	UAMismatchAction string
}

// RateLimitConfig holds per-operation max + window pairs. A zero Max
// disables rate limiting for that operation.
type RateLimitConfig struct {
	Login           RateLimitRule
	Register        RateLimitRule
	ForgotPassword  RateLimitRule
	MagicLinkSend   RateLimitRule
	UnlockRequest   RateLimitRule
	MFAVerify       RateLimitRule
}

// RateLimitRule is one (max, window) pair. Max=0 means "no limit".
type RateLimitRule struct {
	Max    int
	Window time.Duration
}

// NewDefaultConfig returns sensible dev defaults. Production callers should
// set CookieSecure=true and a non-empty CookieDomain.
func NewDefaultConfig() YAuthConfig {
	return YAuthConfig{
		SessionTTL:     30 * 24 * time.Hour,
		CookieName:     "yauth_session",
		CookieDomain:   "",
		CookieSecure:   false,
		CookiePath:     "/",
		CookieSameSite: "Lax",
		RateLimit: RateLimitConfig{
			Login:          RateLimitRule{Max: 10, Window: 60 * time.Second},
			Register:       RateLimitRule{Max: 10, Window: 60 * time.Second},
			ForgotPassword: RateLimitRule{Max: 5, Window: 60 * time.Second},
			MagicLinkSend:  RateLimitRule{Max: 5, Window: 60 * time.Second},
			UnlockRequest:  RateLimitRule{Max: 10, Window: 60 * time.Second},
			MFAVerify:      RateLimitRule{Max: 10, Window: 60 * time.Second},
		},
	}
}
