// Package emailpassword implements the email + password authentication
// plugin for yauth-go.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/register             create account, set session cookie
//	POST {prefix}/login                verify password, set session cookie
//	POST {prefix}/logout               delete current session, clear cookie
//	GET  {prefix}/session              return current AuthUser  (RequireAuth)
//	POST {prefix}/change-password      rotate password           (RequireAuth)
//	PATCH {prefix}/me                  update profile (display_name) (RequireAuth)
//	POST {prefix}/verify-email         consume verification token
//	POST {prefix}/resend-verification  email a fresh verification link
//	POST {prefix}/forgot-password      email a password-reset link
//	POST {prefix}/reset-password       consume reset token + new password
package emailpassword

import (
	"github.com/danielgtaylor/huma/v2"

	"log/slog"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth/auth/hibp"
	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	"github.com/yackey-labs/yauth/plugin"
)

// Config tunes plugin behaviour. Zero value yields safe defaults.
type Config struct {
	// MinPasswordLength is the minimum password length accepted by
	// /register, /reset-password, and /change-password. If zero,
	// defaults to 12. Superseded by PasswordPolicy.MinLength when the
	// policy is configured with a non-zero value.
	MinPasswordLength int
	// RequireEmailVerification, when true, will reject /login for
	// unverified accounts. MVP leaves this off (false).
	RequireEmailVerification bool
	// RememberMeTTL is the session TTL applied when /login receives
	// remember_me=true. If zero, defaults to 30 days. When the login
	// request has remember_me unset or false, the host's default
	// SessionTTL is used instead.
	RememberMeTTL time.Duration

	// VerificationTokenTTL is the lifetime of email-verification
	// tokens. Defaults to 24h.
	VerificationTokenTTL time.Duration
	// PasswordResetTokenTTL is the lifetime of password-reset tokens.
	// Defaults to 1h.
	PasswordResetTokenTTL time.Duration

	// VerificationLinkBaseURL is prepended to the raw verification
	// token to form the link sent in the verification email. Empty
	// means raw token only.
	VerificationLinkBaseURL string
	// PasswordResetLinkBaseURL is the equivalent for password-reset
	// emails.
	PasswordResetLinkBaseURL string

	// Mailer delivers verification, reset, and "account-exists"
	// notices. Nil = LoggingMailer (stderr).
	Mailer Mailer

	// HIBPCheck enables a HaveIBeenPwned k-anonymity password-breach
	// check on /register and /reset-password. Defaults to true.
	// Network failure is fail-open: the check is skipped, the action
	// is allowed.
	HIBPCheck bool
	// HIBPCheckSet records whether the caller explicitly set
	// HIBPCheck — applyDefaults uses this to honor "false" while
	// still defaulting unset configs to true.
	HIBPCheckSet bool
	// HIBPClient is the *http.Client used for HIBP requests; nil =
	// new client with hibp.DefaultTimeout. Tests override with an
	// httptest server.
	HIBPClient *http.Client
	// HIBPEndpoint overrides the production HIBP API base URL. Empty
	// = hibp.DefaultEndpoint. Used only by tests.
	HIBPEndpoint string

	// PasswordPolicy is the complexity policy enforced by /register,
	// /change-password, and /reset-password. Zero value (default)
	// applies a permissive but sane baseline; populate to require
	// uppercase/lowercase/digit/special, common-password rejection,
	// or password-history checks.
	PasswordPolicy passwordpolicy.Policy
}

const (
	defaultVerificationTokenTTL  = 24 * time.Hour
	defaultPasswordResetTokenTTL = 1 * time.Hour
	defaultRememberMeTTL         = 30 * 24 * time.Hour
)

// emailPasswordPlugin is an unexported implementation of plugin.Plugin.
type emailPasswordPlugin struct {
	cfg     Config
	checker *hibp.Checker
	logger  *slog.Logger
}

// New constructs the email-password plugin.
func New(cfg Config) plugin.Plugin {
	if cfg.MinPasswordLength <= 0 {
		cfg.MinPasswordLength = 12
	}
	if cfg.RememberMeTTL <= 0 {
		cfg.RememberMeTTL = defaultRememberMeTTL
	}
	if cfg.VerificationTokenTTL <= 0 {
		cfg.VerificationTokenTTL = defaultVerificationTokenTTL
	}
	if cfg.PasswordResetTokenTTL <= 0 {
		cfg.PasswordResetTokenTTL = defaultPasswordResetTokenTTL
	}
	if cfg.Mailer == nil {
		cfg.Mailer = &LoggingMailer{}
	}
	if !cfg.HIBPCheckSet {
		cfg.HIBPCheck = true
	}

	checker := &hibp.Checker{
		Endpoint: cfg.HIBPEndpoint,
		Client:   cfg.HIBPClient,
	}
	return &emailPasswordPlugin{cfg: cfg, checker: checker}
}

// Name implements plugin.Plugin.
func (p *emailPasswordPlugin) Name() string { return "email-password" }

// Routes implements plugin.Plugin. Every route is huma-native. The six
// public routes (register/login/verify-email/resend-verification/
// forgot-password/reset-password) carry their original fixed-window rate
// limiter as the OUTERMOST per-operation middleware via RateLimitHuma, then
// StashHTTPHuma so the migrated handlers keep byte-identical body parsing
// (strict decode, the enumeration-safe responses, RequestIP) and the
// register/login Set-Cookie writes. The three authenticated routes
// (logout/change-password/PATCH me) are gated by RequireAuthHuma with
// StashHTTPHuma; /session needs only RequireAuthHuma (it reads the AuthUser
// from ctx — no body, cookie, or IP). The mux is retained in the signature
// for plugins that still register raw net/http routes; email-password no
// longer uses it.
//
// host.RateLimit is a no-op when max<=0, so the same wiring works regardless
// of the operator's config; the RateLimitHuma bridge preserves the plain-text
// 429 and X-RateLimit-* headers on block (NOT problem+json).
func (p *emailPasswordPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	p.logger = host.Logger()
	// If the default console mailer is in use, give it the host logger and
	// warn loudly: it prints verification/reset links (which carry bearer
	// tokens) to the log and sends NO real email — safe for dev, a
	// credential-leak in prod. Configure a real Mailer / mailer.provider=smtp.
	if lm, ok := p.cfg.Mailer.(*LoggingMailer); ok {
		lm.logger = p.logger
		p.logger.Warn("email-password: using the console LoggingMailer — verification & password-reset links (bearer tokens) are written to logs and NO email is sent; set Config.Mailer or mailer.provider=smtp for production")
	}

	mw := host.Middleware()

	registerRL := host.RateLimit("emailpassword.register", 10, 60*time.Second)
	loginRL := host.RateLimit("emailpassword.login", 10, 60*time.Second)
	verifyEmailRL := host.RateLimit("emailpassword.verify_email", 10, 60*time.Second)
	resendVerifyRL := host.RateLimit("emailpassword.resend_verification", 5, 60*time.Second)
	forgotRL := host.RateLimit("emailpassword.forgot_password", 5, 60*time.Second)
	resetRL := host.RateLimit("emailpassword.reset_password", 5, 60*time.Second)

	p.registerRegister(host, api, prefix, registerRL)
	p.registerLogin(host, api, prefix, loginRL)
	p.registerLogout(host, api, mw, prefix)
	p.registerSession(host, api, mw, prefix)
	p.registerChangePassword(host, api, mw, prefix)
	p.registerPatchMe(host, api, mw, prefix)
	p.registerVerifyEmail(host, api, prefix, verifyEmailRL)
	p.registerResendVerification(host, api, prefix, resendVerifyRL)
	p.registerForgotPassword(host, api, prefix, forgotRL)
	p.registerResetPassword(host, api, prefix, resetRL)
}
