// Package yauth is the root entry point for yauth. It composes a
// repository, a tri-mode authentication middleware, and a slice of
// plugins into a single mountable http.Handler.
//
// Typical usage:
//
//	repo := memrepo.New() // or pgxrepo.New(pool) for Postgres
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

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/telemetry"
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
	traceMiddleware  bool
	telemetryShut    func(context.Context) error

	eventHandlers []events.Handler
	authResolvers []plugin.AuthResolver
	jwtSigner     plugin.JWTSigner
	jwtSecret     []byte

	// humaAPI is the huma API every plugin registered its routes on. Its
	// auto-derived OpenAPI is exposed via OpenAPI() — the published spec source.
	humaAPI huma.API
}

// YAuthBuilder accumulates plugins before producing a YAuth via Build.
type YAuthBuilder struct {
	cfg             YAuthConfig
	repo            repo.Repository
	plugins         []plugin.Plugin
	telemetryCfg    *telemetry.Config
	traceMiddleware *bool
	telemetryShut   func(context.Context) error
	jwtSecret       []byte
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

// WithTelemetry enables OpenTelemetry tracing on the built YAuth. yauth's
// internal instrumentation (StartSpan/WithSpan/RecordError/SetAttribute and
// the `user.id` tag on authenticated requests) records against the global
// tracer provider — yauth never calls otel.SetTracerProvider on this path, so
// a consumer's already-installed SDK is respected. By default Build also wraps
// the returned router with middleware.TraceMiddleware so every request opens a
// server span; consumers who already run their own HTTP instrumentation (e.g.
// otelhttp) can drop that with WithTraceMiddleware(false) to avoid
// double-tracing. Pass telemetry.DefaultConfig() for the common case, or
// telemetry.Config{Enabled: false} to register the no-op provider (useful in
// tests).
func (b *YAuthBuilder) WithTelemetry(cfg telemetry.Config) *YAuthBuilder {
	b.telemetryCfg = &cfg
	return b
}

// WithTraceMiddleware controls whether Build wraps the router in yauth's own
// HTTP server-span middleware (middleware.TraceMiddleware). It only has an
// effect when telemetry is enabled via WithTelemetry; the default is true for
// backwards compatibility.
//
// Set it to false when the consuming application already wraps its handler
// tree in an HTTP instrumentation (otelhttp or equivalent): yauth then
// participates in the consumer's traces — DB spans, internal spans, and the
// `user.id` attribute all attach to the consumer's server span — without
// emitting a second, redundant server span per request.
func (b *YAuthBuilder) WithTraceMiddleware(enabled bool) *YAuthBuilder {
	b.traceMiddleware = &enabled
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
	// yauth #89 / Go #15: enable active-org hydration on the
	// middleware iff the organizations plugin is registered. Without
	// the plugin the AuthUser stays in legacy single-user shape with
	// ActiveOrgID=nil.
	enableOrgHydration := false
	for _, p := range b.plugins {
		if p.Name() == "organizations" {
			enableOrgHydration = true
			break
		}
	}
	mw := middleware.New(b.repo, middleware.Config{
		CookieName:               b.cfg.CookieName,
		BindIP:                   b.cfg.SessionBinding.BindIP,
		BindUA:                   b.cfg.SessionBinding.BindUA,
		IPMismatchAction:         b.cfg.SessionBinding.IPMismatchAction,
		UAMismatchAction:         b.cfg.SessionBinding.UAMismatchAction,
		AllowAdminMachineCallers: b.cfg.AllowAdminMachineCallers,
		EnableOrgHydration:       enableOrgHydration,
	})
	mux := http.NewServeMux()

	// The HTTP server-span middleware defaults to on when telemetry is
	// enabled, but consumers running their own HTTP instrumentation can
	// opt out via WithTraceMiddleware(false) to avoid double-tracing.
	traceMiddleware := b.traceMiddleware == nil || *b.traceMiddleware

	ya := &YAuth{
		cfg:              b.cfg,
		repo:             b.repo,
		plugins:          b.plugins,
		mux:              mux,
		mw:               mw,
		telemetryEnabled: b.telemetryCfg != nil && b.telemetryCfg.Enabled,
		traceMiddleware:  traceMiddleware,
		telemetryShut:    b.telemetryShut,
		jwtSecret:        b.jwtSecret,
	}

	// Every plugin is huma-native: the huma.API is built over the bare mux
	// (humago.Mux needs only HandleFunc + ServeHTTP, both of which *http.ServeMux
	// provides), and plugins register their operations on it via huma.Register.
	// huma's auto-derived OpenAPI (exposed via OpenAPI()) is therefore the single
	// source of truth — serving and spec are derived from the same registrations,
	// so route-level drift is structurally impossible.
	api := humaapi.New(mux)
	ya.humaAPI = api
	for _, p := range b.plugins {
		p.Routes(ya, mux, api, "")
	}

	return ya, nil
}

// OpenAPI returns the huma-derived OpenAPI document for every route the plugins
// registered. Plugins carry explicit request/response schemas on their
// operations, so this is the published spec source — see openapi.json at the
// repo root, generated from this document.
func (y *YAuth) OpenAPI() *huma.OpenAPI { return y.humaAPI.OpenAPI() }

// Router returns the configured ServeMux, optionally wrapped with the
// OpenTelemetry trace middleware when WithTelemetry was called on the
// builder (unless suppressed via WithTraceMiddleware(false)), and with the
// CORS middleware when CORS.AllowedOrigins is non-empty. Mount it under any
// prefix:
//
//	http.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
func (y *YAuth) Router() http.Handler {
	var h http.Handler = y.mux
	if len(y.cfg.CORS.AllowedOrigins) > 0 {
		h = middleware.CORS(middleware.CORSConfig{
			AllowedOrigins:   y.cfg.CORS.AllowedOrigins,
			AllowedMethods:   y.cfg.CORS.AllowedMethods,
			AllowedHeaders:   y.cfg.CORS.AllowedHeaders,
			AllowCredentials: y.cfg.CORS.AllowCredentials,
			MaxAge:           y.cfg.CORS.MaxAge,
		})(h)
	}
	if y.telemetryEnabled && y.traceMiddleware {
		h = middleware.TraceMiddleware(h)
	}
	return h
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

// BaseURL implements plugin.PluginHost.
func (y *YAuth) BaseURL() string { return y.cfg.BaseURL }

// AllowSignups implements plugin.PluginHost.
func (y *YAuth) AllowSignups() bool { return y.cfg.AllowSignups }

// AutoAdminFirstUser implements plugin.PluginHost.
func (y *YAuth) AutoAdminFirstUser() bool { return y.cfg.AutoAdminFirstUser }

// CookieDomain implements plugin.PluginHost.
func (y *YAuth) CookieDomain() string { return y.cfg.CookieDomain }

// CookieSecure implements plugin.PluginHost.
func (y *YAuth) CookieSecure() bool { return y.cfg.CookieSecure }

// CookiePath implements plugin.PluginHost.
func (y *YAuth) CookiePath() string { return y.cfg.CookiePath }

// SessionBinding implements plugin.PluginHost. Returns the deployment-
// global session-binding flags so plugins (e.g. organizations'
// per-org policy resolver, yauth #92 / yauth-go #21) can merge them
// with per-tenant overrides.
func (y *YAuth) SessionBinding() (bindIP, bindUserAgent bool) {
	return y.cfg.SessionBinding.BindIP, y.cfg.SessionBinding.BindUA
}

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

// RateLimit implements plugin.PluginHost. It binds middleware.RateLimit
// to the host's repository so plugins can wrap their handlers without
// reaching into the repo themselves.
func (y *YAuth) RateLimit(name string, max int, window time.Duration) func(http.Handler) http.Handler {
	return middleware.RateLimit(y.repo, name, max, window)
}

// Compile-time check that *YAuth satisfies plugin.PluginHost.
var _ plugin.PluginHost = (*YAuth)(nil)
