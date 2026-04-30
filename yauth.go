// Package yauth is the root entry point for yauth-go. It composes a
// repository, a tri-mode authentication middleware, and a slice of
// plugins into a single mountable http.Handler.
//
// Typical usage:
//
//	repo := gormrepo.New(db)
//	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
//	    WithPlugin(emailpassword.New(emailpassword.Config{})).
//	    Build()
//	if err != nil { /* handle */ }
//	http.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
package yauth

import (
	"context"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/telemetry"
)

// YAuth is a fully-built authentication stack. Construct it via the
// builder returned by New().
type YAuth struct {
	cfg              YAuthConfig
	repo             repo.Repository
	plugins          []plugin.Plugin
	mux              *http.ServeMux
	mw               *middleware.Middleware
	telemetryEnabled bool
	telemetryShut    func(context.Context) error

	eventHandlers []events.Handler
	authResolvers []plugin.AuthResolver
	jwtSigner     plugin.JWTSigner
	jwtSecret     []byte
}

// YAuthBuilder accumulates plugins before producing a YAuth via Build.
type YAuthBuilder struct {
	cfg           YAuthConfig
	repo          repo.Repository
	plugins       []plugin.Plugin
	telemetryCfg  *telemetry.Config
	telemetryShut func(context.Context) error
	jwtSecret     []byte
}

// New starts a new builder bound to the supplied repository and config.
func New(r repo.Repository, cfg YAuthConfig) *YAuthBuilder {
	return &YAuthBuilder{cfg: cfg, repo: r}
}

// WithPlugin appends a plugin to the builder. Order is preserved; plugins
// register routes in the order they were added.
func (b *YAuthBuilder) WithPlugin(p plugin.Plugin) *YAuthBuilder {
	b.plugins = append(b.plugins, p)
	return b
}

// WithTelemetry enables OpenTelemetry tracing on the built YAuth. Build
// will wrap the returned router with middleware.TraceMiddleware so every
// request opens a server span. Pass telemetry.DefaultConfig() for the
// common case, or telemetry.Config{Enabled: false} to register the no-op
// provider (useful in tests).
func (b *YAuthBuilder) WithTelemetry(cfg telemetry.Config) *YAuthBuilder {
	b.telemetryCfg = &cfg
	return b
}

// WithTelemetryShutdown registers a shutdown function returned by
// telemetry.Init so the resulting YAuth can flush spans via
// YAuth.TelemetryShutdown. Optional — callers that own the shutdown
// lifecycle directly do not need to use this.
func (b *YAuthBuilder) WithTelemetryShutdown(shutdown func(context.Context) error) *YAuthBuilder {
	b.telemetryShut = shutdown
	return b
}

// WithJWTSecret seeds the HS256 secret exposed to plugins via
// PluginHost.JWTSecret. The bearer plugin reads this when it lacks its
// own secret configuration; setting it at builder time keeps wiring
// simple in the common case.
func (b *YAuthBuilder) WithJWTSecret(secret []byte) *YAuthBuilder {
	b.jwtSecret = secret
	return b
}

// Build produces a YAuth ready to be mounted. It instantiates the
// middleware, asks each plugin to register its routes onto an internal
// ServeMux, and returns the assembled object.
func (b *YAuthBuilder) Build() (*YAuth, error) {
	mw := middleware.New(b.repo, middleware.Config{CookieName: b.cfg.CookieName})
	mux := http.NewServeMux()

	ya := &YAuth{
		cfg:              b.cfg,
		repo:             b.repo,
		plugins:          b.plugins,
		mux:              mux,
		mw:               mw,
		telemetryEnabled: b.telemetryCfg != nil && b.telemetryCfg.Enabled,
		telemetryShut:    b.telemetryShut,
		jwtSecret:        b.jwtSecret,
	}

	for _, p := range b.plugins {
		p.Routes(ya, mux, "")
	}

	return ya, nil
}

// Router returns the configured ServeMux, optionally wrapped with the
// OpenTelemetry trace middleware when WithTelemetry was called on the
// builder. Mount it under any prefix:
//
//	http.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
func (y *YAuth) Router() http.Handler {
	if y.telemetryEnabled {
		return middleware.TraceMiddleware(y.mux)
	}
	return y.mux
}

// TelemetryShutdown flushes any pending OpenTelemetry spans by invoking
// the shutdown function registered via YAuthBuilder.WithTelemetryShutdown.
// Safe to call when no shutdown was registered (returns nil).
func (y *YAuth) TelemetryShutdown(ctx context.Context) error {
	if y.telemetryShut == nil {
		return nil
	}
	return y.telemetryShut(ctx)
}

// Middleware returns the auth middleware so callers can guard their own
// routes outside the YAuth router.
func (y *YAuth) Middleware() *middleware.Middleware { return y.mw }

// Repo returns the repository plugin handlers persist against.
func (y *YAuth) Repo() repo.Repository { return y.repo }

// Config returns the YAuthConfig the instance was built with.
func (y *YAuth) Config() YAuthConfig { return y.cfg }

// Emit fans event through every registered events.Handler in registration
// order. The first non-Continue decision short-circuits the chain and is
// returned to the caller. If every handler returns Continue (or no
// handlers are registered), Emit returns events.Continue() and a nil
// error. Handler errors are surfaced immediately along with the decision
// returned by that handler.
func (y *YAuth) Emit(ctx context.Context, event events.AuthEvent) (events.Decision, error) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	for _, h := range y.eventHandlers {
		dec, err := h.Handle(ctx, event)
		if err != nil {
			return dec, err
		}
		if dec.Kind != events.DecisionKindContinue {
			return dec, nil
		}
	}
	return events.Continue(), nil
}

// --- plugin.PluginHost implementation -------------------------------------

// SessionTTL implements plugin.PluginHost.
func (y *YAuth) SessionTTL() time.Duration { return y.cfg.SessionTTL }

// CookieName implements plugin.PluginHost.
func (y *YAuth) CookieName() string { return y.cfg.CookieName }

// CookieDomain implements plugin.PluginHost.
func (y *YAuth) CookieDomain() string { return y.cfg.CookieDomain }

// CookieSecure implements plugin.PluginHost.
func (y *YAuth) CookieSecure() bool { return y.cfg.CookieSecure }

// CookiePath implements plugin.PluginHost.
func (y *YAuth) CookiePath() string { return y.cfg.CookiePath }

// CookieSameSite implements plugin.PluginHost. Maps the string form on
// YAuthConfig onto an http.SameSite value via the same rules used in
// auth/cookie.go.
func (y *YAuth) CookieSameSite() http.SameSite {
	switch y.cfg.CookieSameSite {
	case "Strict", "strict":
		return http.SameSiteStrictMode
	case "None", "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// RegisterEventHandler implements plugin.PluginHost.
func (y *YAuth) RegisterEventHandler(h events.Handler) {
	y.eventHandlers = append(y.eventHandlers, h)
}

// RegisterAuthResolver implements plugin.PluginHost.
func (y *YAuth) RegisterAuthResolver(r plugin.AuthResolver) {
	y.authResolvers = append(y.authResolvers, r)
	y.mw.AddResolver(r)
}

// PluginNames implements plugin.PluginHost.
func (y *YAuth) PluginNames() []string {
	names := make([]string, len(y.plugins))
	for i, p := range y.plugins {
		names[i] = p.Name()
	}
	return names
}

// JWTSigner implements plugin.PluginHost.
func (y *YAuth) JWTSigner() plugin.JWTSigner { return y.jwtSigner }

// JWTSecret implements plugin.PluginHost.
func (y *YAuth) JWTSecret() []byte { return y.jwtSecret }

// SetJWTSigner is invoked by the asymmetric-jwt plugin from its Routes
// hook to publish its signer to the rest of the host. Plugins should not
// invoke this directly outside of asymjwt — the contract is "first
// signer wins", subsequent calls are ignored.
func (y *YAuth) SetJWTSigner(s plugin.JWTSigner) {
	if y.jwtSigner == nil {
		y.jwtSigner = s
	}
}

// Compile-time check that *YAuth satisfies plugin.PluginHost.
var _ plugin.PluginHost = (*YAuth)(nil)
