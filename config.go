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
	}
}
