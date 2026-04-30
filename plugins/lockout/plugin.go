// Package lockout implements account-lockout-on-repeated-failure as a
// pluggable yauth-go plugin. It listens to login.attempt / login.failed /
// login.succeeded events emitted by the email-password plugin, tracks
// per-user failure counts, and blocks logins for a configurable cooldown
// when the failure threshold is hit. Repeat offenders are escalated by
// stepping through Config.LockoutDurations.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/unlock          — exchange a single-use unlock token
//	POST {prefix}/unlock/request  — email a fresh unlock token
//	GET  {prefix}/lockout/state   — admin: list currently locked accounts
package lockout

import (
	"context"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Mailer delivers an unlock token to a user. The plugin uses its own
// interface (rather than reusing magiclink's) so operators can route the
// two channels independently.
type Mailer interface {
	SendUnlockToken(ctx context.Context, email, link string) error
}

// LoggingMailer is the default Mailer used when Config.Mailer is nil. It
// prints the generated unlock link to stderr, matching magic-link's dev
// behaviour.
type LoggingMailer struct{}

// SendUnlockToken writes a single line to stderr.
func (LoggingMailer) SendUnlockToken(_ context.Context, email, link string) error {
	logf("yauth: unlock-token for %s: %s", email, link)
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
		c.Mailer = LoggingMailer{}
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
	cfg Config
}

// New constructs the lockout plugin.
func New(cfg Config) plugin.Plugin {
	cfg.applyDefaults()
	return &lockoutPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *lockoutPlugin) Name() string { return "lockout" }

// Routes implements plugin.Plugin. Registers the events.Handler with the
// host (so login attempts are intercepted) and mounts the unlock routes.
func (p *lockoutPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	host.RegisterEventHandler(&loginEventHandler{cfg: p.cfg, host: host})

	mw := host.Middleware()
	mux.Handle("POST "+prefix+"/unlock", http.HandlerFunc(p.handleUnlock(host)))
	mux.Handle("POST "+prefix+"/unlock/request", http.HandlerFunc(p.handleUnlockRequest(host)))
	mux.Handle("GET "+prefix+"/lockout/state", mw.RequireAdmin(http.HandlerFunc(p.handleLockoutState(host))))
}
