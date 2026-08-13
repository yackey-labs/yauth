package yauth

import (
	"time"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
)

// YAuthConfig holds runtime configuration for yauth-go.
type YAuthConfig struct {
	SessionTTL     time.Duration
	CookieName     string
	CookieDomain   string
	CookieSecure   bool
	CookiePath     string
	CookieSameSite string // "Lax" | "Strict" | "None"

	// BaseURL is the absolute URL the public API is reachable at,
	// e.g. "https://app.example.com". Plugins read this via
	// PluginHost.BaseURL.
	BaseURL string

	// AllowSignups defaults to true. When false, the email-password
	// /register handler responds 403 SIGNUPS_DISABLED.
	AllowSignups bool

	// AutoAdminFirstUser, when true, promotes the very first registered
	// user to role "admin".
	AutoAdminFirstUser bool

	// CORS holds cross-origin policy. When AllowedOrigins is empty the
	// CORS middleware is not installed.
	CORS CORSConfig

	// SecurityHeaders controls the response-header floor the mounted
	// Router applies (nosniff, Referrer-Policy, X-Frame-Options, CSP).
	//
	// The zero value ENABLES it, which is the whole point: New() stores
	// the config it is handed verbatim with no defaulting pass, so an
	// `Enabled bool` here would be false for every embedder that builds
	// its config in Go and the middleware would ship doing nothing. The
	// switch is therefore SecurityHeadersConfig.Disabled — opt out, never
	// opt in. Strict-Transport-Security stays off until HSTS is set.
	SecurityHeaders middleware.SecurityHeadersConfig

	// SessionBinding controls IP and User-Agent hijack detection on
	// cookie-resolved sessions. Disabled by default.
	SessionBinding SessionBindingConfig

	// AllowAdminMachineCallers controls whether bearer or USER-scoped
	// api-key callers can pass RequireAdmin. False (default) = cookie-only.
	// An ORG-scoped api-key (service account) never passes it, opt-in or
	// not: its authority is the org and role recorded on the key, not the
	// global role of the human who minted it.
	AllowAdminMachineCallers bool

	// RateLimit holds per-operation rate-limit windows. Plugins read
	// these via plugin.RateLimitFor when wrapping their handlers; an
	// unset rule falls back to the plugin's own built-in default.
	RateLimit RateLimitConfig

	// TrustedProxies decides whose X-Forwarded-For / X-Real-IP yauth
	// believes when it resolves a request's client IP — the value written
	// to a session's ip_address, to every audit row and every
	// events.AuthEvent.IPAddress, and the key the per-IP rate limiter
	// buckets on.
	//
	// Entries are literal IPs, CIDRs, or the keywords "private", "all" and
	// "none" (see [middleware.ParseTrustedProxies]). EMPTY — the default —
	// means "private": forwarding headers are honoured only from a
	// loopback/RFC1918/link-local peer, which is where a reverse proxy,
	// ingress controller or sidecar lives. A listener clients reach
	// directly sees a public peer, so its headers are ignored and a caller
	// can no longer forge the address recorded against it.
	//
	// Set it when the hop in front of yauth is NOT on private space (a
	// public-IP load balancer, a CDN edge): add its ranges, or "all" to
	// restore unconditional trust.
	TrustedProxies []string
}

// CORSConfig is the runtime CORS policy. See yauthcfg.CORSConfig for
// per-field semantics. Empty AllowedOrigins disables the middleware.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
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

// RateLimitConfig holds per-operation max + window pairs. Each rule is
// consulted by [plugin.RateLimitFor] when the plugin owning that operation
// wraps its route.
type RateLimitConfig struct {
	Login          RateLimitRule
	Register       RateLimitRule
	ForgotPassword RateLimitRule
	MagicLinkSend  RateLimitRule
	UnlockRequest  RateLimitRule
	MFAVerify      RateLimitRule
}

// Rule returns the rule configured for op, and whether op is one this
// config covers. Unknown ops resolve to the zero rule (fall back to the
// plugin's own defaults).
func (c RateLimitConfig) Rule(op plugin.RateLimitOp) (RateLimitRule, bool) {
	switch op {
	case plugin.RateLimitLogin:
		return c.Login, true
	case plugin.RateLimitRegister:
		return c.Register, true
	case plugin.RateLimitForgotPassword:
		return c.ForgotPassword, true
	case plugin.RateLimitMagicLinkSend:
		return c.MagicLinkSend, true
	case plugin.RateLimitUnlockRequest:
		return c.UnlockRequest, true
	case plugin.RateLimitMFAVerify:
		return c.MFAVerify, true
	}
	return RateLimitRule{}, false
}

// RateLimitRule is one (max, window) pair.
//
// Max is a POINTER so "the operator said nothing" and "the operator said
// zero" stay distinguishable: nil means fall back to the plugin's built-in
// default, and an explicit 0 means no limit — which is what the yaml schema
// has always documented but could not previously express, because a
// zero int was indistinguishable from an omitted key.
type RateLimitRule struct {
	Max    *int
	Window time.Duration
}

// RateLimitMax boxes n for [RateLimitRule.Max]. RateLimitMax(0) is an
// explicit "no limit".
func RateLimitMax(n int) *int { return &n }

// Resolve applies the rule on top of the plugin's built-in defaults,
// returning the (max, window) to enforce. An unset field takes the default;
// max=0 disables the limiter (middleware.RateLimit becomes a passthrough).
func (r RateLimitRule) Resolve(defMax int, defWindow time.Duration) (int, time.Duration) {
	max := defMax
	if r.Max != nil {
		max = *r.Max
	}
	window := defWindow
	if r.Window > 0 {
		window = r.Window
	}
	return max, window
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
		AllowSignups:   true,
		RateLimit: RateLimitConfig{
			Login:          RateLimitRule{Max: RateLimitMax(10), Window: 60 * time.Second},
			Register:       RateLimitRule{Max: RateLimitMax(10), Window: 60 * time.Second},
			ForgotPassword: RateLimitRule{Max: RateLimitMax(5), Window: 60 * time.Second},
			MagicLinkSend:  RateLimitRule{Max: RateLimitMax(5), Window: 60 * time.Second},
			UnlockRequest:  RateLimitRule{Max: RateLimitMax(10), Window: 60 * time.Second},
			MFAVerify:      RateLimitRule{Max: RateLimitMax(10), Window: 60 * time.Second},
		},
	}
}
