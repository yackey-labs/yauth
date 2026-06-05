// Package lockout implements account-lockout-on-repeated-failure as a
// pluggable yauth-go plugin. It listens to login.attempt / login.failed /
// login.succeeded events emitted by the email-password plugin, tracks
// per-user failure counts, and blocks logins for a configurable cooldown
// when the failure threshold is hit. Repeat offenders are escalated by
// stepping through Config.LockoutDurations.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/account/unlock                — exchange a single-use unlock token
//	POST {prefix}/account/request-unlock        — email a fresh unlock token
//	POST {prefix}/admin/users/{id}/unlock       — admin: force-unlock a user
//	GET  {prefix}/lockout/state                 — admin: list currently locked accounts
package lockout

import (
	"github.com/danielgtaylor/huma/v2"

	"context"
	"log/slog"
	"time"

	"github.com/yackey-labs/yauth/plugin"
)

// Mailer delivers an unlock token to a user. The plugin uses its own
// interface (rather than reusing magiclink's) so operators can route the
// two channels independently.
type Mailer interface {
	SendUnlockToken(ctx context.Context, email, link string) error
}

// LoggingMailer is the default Mailer used when Config.Mailer is nil. It
// logs the generated unlock link (via the host's structured logger),
// matching magic-link's dev behaviour.
//
// It sends NO real email and writes a single-use unlock token to the log —
// dev/test only. The lockout plugin emits a one-time WARN at startup when
// this mailer is active so a production misconfiguration is visible.
type LoggingMailer struct {
	// logger is injected by the plugin at Routes time (from
	// PluginHost.Logger()). Nil falls back to slog.Default().
	logger *slog.Logger
}

// SendUnlockToken logs the unlock link (email + link) at WARN.
func (m *LoggingMailer) SendUnlockToken(ctx context.Context, email, link string) error {
	l := m.logger
	if l == nil {
		l = slog.Default()
	}
	l.WarnContext(ctx, "lockout: [console mailer] unlock link (would be emailed)", "email", email, "link", link)
	return nil
}

// Config tunes plugin behaviour. Zero value yields safe defaults.
type Config struct {
	// MaxAttempts is the number of consecutive failed logins before the
	// account is locked. Defaults to 5.
	MaxAttempts int

	// LockoutDurations is the escalation ladder for repeated lockouts:
	// the first lockout uses LockoutDurations[0], the second
	// LockoutDurations[1], etc. The last entry is the cap. Defaults to
	// [1m, 5m, 15m, 1h] when nil.
	LockoutDurations []time.Duration

	// UnlockTokenTTL is the lifetime of a token issued via /unlock/request.
	// Defaults to 1 hour.
	UnlockTokenTTL time.Duration

	// Mailer delivers unlock tokens. nil disables the mail delivery (the
	// /unlock/request endpoint still issues tokens but only operators with
	// database access will see them).
	Mailer Mailer

	// LinkBaseURL is prepended to the raw token to form the link sent in
	// the unlock email. Example: "https://app.example.com/unlock". The
	// plugin appends "?token=<raw>".
	LinkBaseURL string

	// MaxLockoutDuration caps the per-step value picked off
	// LockoutDurations. A LockoutDurations entry larger than this is
	// truncated to MaxLockoutDuration when applied. Zero means
	// "no cap"; the default applied below is 1h, the same as the last
	// rung of the default ladder, so the default cap is effectively
	// no-op until an operator extends the ladder.
	MaxLockoutDuration time.Duration

	// AutoUnlock controls whether expired locks are cleared lazily by a
	// subsequent login attempt. When false the cooldown timer is
	// ignored and an admin must POST /unlock to clear the lock; this
	// is the safer mode for high-value workflows where a noisy
	// attacker should not be able to "wait out" a lock. nil = true.
	AutoUnlock *bool
}

func (c *Config) applyDefaults() {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	if len(c.LockoutDurations) == 0 {
		c.LockoutDurations = []time.Duration{
			1 * time.Minute,
			5 * time.Minute,
			15 * time.Minute,
			1 * time.Hour,
		}
	}
	if c.UnlockTokenTTL <= 0 {
		c.UnlockTokenTTL = 1 * time.Hour
	}
	if c.MaxLockoutDuration <= 0 {
		c.MaxLockoutDuration = 1 * time.Hour
	}
	if c.Mailer == nil {
		c.Mailer = &LoggingMailer{}
	}
}

// autoUnlock reports the effective AutoUnlock value, defaulting to true
// when the caller left the pointer nil.
func (c *Config) autoUnlock() bool {
	if c.AutoUnlock == nil {
		return true
	}
	return *c.AutoUnlock
}

type lockoutPlugin struct {
	cfg    Config
	logger *slog.Logger
}

// New constructs the lockout plugin.
func New(cfg Config) plugin.Plugin {
	cfg.applyDefaults()
	return &lockoutPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *lockoutPlugin) Name() string { return "lockout" }

// Routes implements plugin.Plugin. Registers the events.Handler with the
// host (so login attempts are intercepted) and mounts the unlock routes as
// huma-native typed operations.
//
// The two public POST routes (account/unlock, account/request-unlock) take a
// native huma typed Body, so huma parses + validates the JSON and the request
// schema auto-derives (unknown fields / malformed body → 422); they carry
// Security:[] (public). The two admin routes (force-unlock, lockout/state) are
// gated by RequireAdminHuma — force-unlock recovers its {id} via a typed path
// input, and lockout/state takes no input.
//
// The mux is retained in the signature for plugins that still register raw
// net/http routes; lockout no longer uses it.
func (p *lockoutPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	p.logger = host.Logger()
	if lm, ok := p.cfg.Mailer.(*LoggingMailer); ok {
		lm.logger = p.logger
		p.logger.Warn("lockout: using the console LoggingMailer — unlock links (single-use tokens) are written to logs and NO email is sent; set Config.Mailer for production")
	}

	host.RegisterEventHandler(&loginEventHandler{cfg: p.cfg, host: host})

	mw := host.Middleware()
	p.registerUnlock(host, api, prefix)
	p.registerUnlockRequest(host, api, prefix)
	p.registerAdminUnlock(host, api, mw, prefix)
	p.registerLockoutState(host, api, mw, prefix)
}
