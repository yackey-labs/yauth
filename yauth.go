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
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/telemetry"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// YAuth is a fully-built authentication stack. Construct it via the
// builder returned by New().
type YAuth struct {
	cfg     YAuthConfig
	repo    repo.Repository
	plugins []plugin.Plugin
	mux     *http.ServeMux
	mw      *middleware.Middleware
	// trusted is the parsed cfg.TrustedProxies policy. Parsed and validated
	// once in Build so Router does not re-derive it per call and a
	// malformed list can never reach a request.
	trusted          middleware.TrustedProxies
	telemetryEnabled bool
	traceMiddleware  bool
	telemetryShut    func(context.Context) error

	eventGates     []events.Handler
	eventHandlers  []events.Handler
	auditRecorders []plugin.AuditRecorder
	authResolvers  []plugin.AuthResolver
	jwtSigner      plugin.JWTSigner
	jwtSecret      []byte
	mfaVerifier    plugin.MFAVerifier
	logger         *slog.Logger

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
	logger          *slog.Logger
	// deferredErr carries a validation failure from a With* setter, which
	// cannot return one, through to Build().
	deferredErr error
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
//
// The secret must be at least [yauthcfg.MinJWTSecretBytes] bytes. This used to
// accept anything, including a single byte, and every bearer access token,
// refresh binding and machine credential in the deployment was signed with it —
// recoverable offline from one captured token. RFC 7518 §3.2 requires a key at
// least as long as the hash output for HS256.
//
// The builder cannot return an error here, so a short secret is recorded and
// surfaced by [YAuthBuilder.Build] rather than swallowed. Generate one with
// `yauth gen-secrets`.
func (b *YAuthBuilder) WithJWTSecret(secret []byte) *YAuthBuilder {
	if n := len(secret); n > 0 && n < yauthcfg.MinJWTSecretBytes {
		b.deferredErr = fmt.Errorf("yauth: WithJWTSecret was given a %d-byte HS256 secret; at least %d bytes are required (RFC 7518 §3.2) — generate one with `yauth gen-secrets`", n, yauthcfg.MinJWTSecretBytes)
		return b
	}
	b.jwtSecret = secret
	return b
}

// WithLogger sets the structured logger yauth uses for ALL of its internal
// logging — middleware warnings, plugin error logs, the console mailer's
// dev output, and config advisories. Pass your application's *slog.Logger
// so yauth's output shares the app's handler (level, JSON/text format,
// trace correlation, redaction). If never called, yauth uses
// slog.Default(). The logger is exposed to plugins via PluginHost.Logger().
func (b *YAuthBuilder) WithLogger(l *slog.Logger) *YAuthBuilder {
	b.logger = l
	return b
}

// Build produces a YAuth ready to be mounted. It instantiates the
// middleware, asks each plugin to register its routes onto an internal
// ServeMux, and returns the assembled object.
func (b *YAuthBuilder) Build() (*YAuth, error) {
	if b.deferredErr != nil {
		return nil, b.deferredErr
	}
	// Reject duplicate plugins up front with a clear error rather than letting
	// huma panic on colliding route registrations. This is the guard for the
	// mix-and-match footgun: the same plugin wired via both NewBuilderFromConfig
	// (yaml) and WithPlugin (builder). One plugin name = one registration.
	seen := make(map[string]bool, len(b.plugins))
	for _, p := range b.plugins {
		name := p.Name()
		if seen[name] {
			return nil, fmt.Errorf("yauth: duplicate plugin %q — it is registered twice (likely enabled in yaml AND added via WithPlugin); remove one", name)
		}
		seen[name] = true
	}

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
	// Resolve the logger once: the consumer's via WithLogger, else the
	// process default. Every yauth subsystem (middleware, plugins, the
	// console mailer) logs through this one logger.
	logger := b.logger
	if logger == nil {
		logger = slog.Default()
	}

	// Rejected here rather than at first request: a typo'd CIDR must not
	// silently degrade to "trust nobody" (which would break the audit
	// trail) or to "trust everybody" (which would restore the forgery).
	trusted, err := middleware.ParseTrustedProxies(b.cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("yauth: %w", err)
	}

	// The cross-site-write allow-list defaults to the CORS allow-list: a
	// cross-domain SPA authenticating with cookies must already be listed
	// there (a credentialed XHR cannot read its response otherwise), so the
	// inheritance carries that whole population with ZERO new config. Which
	// SOURCE the list came from is recorded, because it decides whether a
	// literal "*" counts as consent to cross-site credentialed WRITES —
	// yauthcfg rejects "*" together with allow_credentials, so a "*"
	// inherited from CORS means the operator DECLINED credentialed
	// cross-origin access. See middleware.crossSiteOriginAllowed.
	xsOrigins := b.cfg.CrossSiteWrites.Origins
	xsFromCORS := len(xsOrigins) == 0
	if xsFromCORS {
		xsOrigins = b.cfg.CORS.AllowedOrigins
	}

	mw := middleware.New(b.repo, middleware.Config{
		CookieName:               b.cfg.CookieName,
		BindIP:                   b.cfg.SessionBinding.BindIP,
		BindUA:                   b.cfg.SessionBinding.BindUA,
		IPMismatchAction:         b.cfg.SessionBinding.IPMismatchAction,
		UAMismatchAction:         b.cfg.SessionBinding.UAMismatchAction,
		TrustedProxies:           trusted,
		AllowAdminMachineCallers: b.cfg.AllowAdminMachineCallers,
		EnableOrgHydration:       enableOrgHydration,
		Logger:                   logger,

		AllowCrossSiteWrites:          b.cfg.CrossSiteWrites.Allow,
		CrossSiteWriteOrigins:         xsOrigins,
		CrossSiteWriteOriginsFromCORS: xsFromCORS,
		CORSAllowCredentials:          b.cfg.CORS.AllowCredentials,
		// The deployment's own origin, so a Host-rewriting proxy or an
		// SSR/BFF that forwards the browser's Origin verbatim is still
		// recognised as first-party.
		SelfOrigin: b.cfg.BaseURL,
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
		logger:           logger,
		trusted:          trusted,
	}

	// The middleware writes one audit row of its own (the session-binding
	// mismatch) and cannot reach the recorder list by itself — package
	// plugin imports middleware, so middleware cannot import plugin and
	// cannot call plugin.WriteAudit. Hand it the fan-out now that ya
	// exists; middleware.New has to run first because the plugins take the
	// middleware handle from the host.
	mw.SetAuditFanout(ya.FanoutAudit)

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

// Router returns the configured ServeMux, wrapped with the security-header
// middleware (unless SecurityHeaders.Disabled), optionally wrapped with the
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
	// Outermost: every handler below resolves the client IP under the
	// deployment's trusted-proxy policy, so what a plugin writes to a
	// session/audit row and what the rate limiter buckets on are the same
	// value the session-binding check will later compare against.
	h = middleware.TrustedProxiesMiddleware(y.trusted)(h)
	// Outermost of all: until this existed every response yauth emitted —
	// JSON, problem+json and the text/html end_session page alike — went
	// out with no CSP, no X-Frame-Options, no nosniff and no
	// Referrer-Policy, so a browser-facing state-changing route like
	// /oauth/end_session was framable. It wraps LAST so that responses from
	// middleware that short-circuits also carry the headers — in particular
	// the bare 204 middleware.CORS answers a preflight with, which never
	// reaches the mux. It only fills in headers that are still unset, so an
	// embedding application that wraps this router with its own policy wins.
	h = middleware.SecurityHeaders(y.cfg.SecurityHeaders)(h)
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

// Logger implements plugin.PluginHost. It returns the resolved structured
// logger (WithLogger's value, or slog.Default()). Never nil.
func (y *YAuth) Logger() *slog.Logger { return y.logger }

// Repo returns the repository plugin handlers persist against.
func (y *YAuth) Repo() repo.Repository { return y.repo }

// Config returns the YAuthConfig the instance was built with.
func (y *YAuth) Config() YAuthConfig { return y.cfg }

// Emit fans event through the auth-event pipeline: first every gate
// registered with RegisterEventGate, then every handler registered with
// RegisterEventHandler, each stage in its own registration order. The
// first non-Continue decision short-circuits the chain and is returned to
// the caller. If every handler returns Continue (or none are registered),
// Emit returns events.Continue() and a nil error. Handler errors are
// surfaced immediately along with the decision returned by that handler.
//
// The two stages exist so a gate's veto (mfa's RequireMfa) always lands
// before observers act on the event; see PluginHost.RegisterEventGate.
//
// Emit also writes the event's audit-log row — see audit_events.go. That
// happens AFTER the pipeline and whatever the decision, so a login a gate
// refused is recorded as refused rather than not at all, and so every
// credential plugin is covered by the single choke point they all already
// pass through.
func (y *YAuth) Emit(ctx context.Context, event events.AuthEvent) (events.Decision, error) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	dec, err := y.dispatchEvent(ctx, event)
	y.recordAuthAudit(ctx, event, dec, err)
	return dec, err
}

// dispatchEvent runs the gate stage then the handler stage, short-circuiting
// on the first non-Continue decision or the first handler error.
func (y *YAuth) dispatchEvent(ctx context.Context, event events.AuthEvent) (events.Decision, error) {
	for _, h := range y.eventGates {
		dec, err := h.Handle(ctx, event)
		if err != nil {
			return dec, err
		}
		if dec.Kind != events.DecisionKindContinue {
			return dec, nil
		}
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

// RegisterEventGate implements plugin.PluginHost. Gates run before every
// RegisterEventHandler handler, independent of plugin registration order.
func (y *YAuth) RegisterEventGate(h events.Handler) {
	y.eventGates = append(y.eventGates, h)
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

// MFAVerifier implements plugin.PluginHost. Returns nil when no MFA
// plugin registered a verifier.
func (y *YAuth) MFAVerifier() plugin.MFAVerifier { return y.mfaVerifier }

// RegisterMFAVerifier implements plugin.PluginHost. It is invoked by the
// mfa plugin from its Routes hook to publish its challenge verifier to
// plugins that complete a login without a cookie session (bearer). First
// verifier wins, matching SetJWTSigner.
func (y *YAuth) RegisterMFAVerifier(v plugin.MFAVerifier) {
	if y.mfaVerifier == nil {
		y.mfaVerifier = v
	}
}

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

// RateLimitForOp implements plugin.RateLimitConfigurer: it resolves the
// operator's rate_limit.<op> rule over the plugin's own defaults and binds
// the limiter to the host repository. This is what makes the rate_limit
// section of yauth.yaml load-bearing — before it, every plugin passed
// literal numbers and the whole section was read by nothing.
func (y *YAuth) RateLimitForOp(op plugin.RateLimitOp, defMax int, defWindow time.Duration) func(http.Handler) http.Handler {
	rule, _ := y.cfg.RateLimit.Rule(op)
	max, window := rule.Resolve(defMax, defWindow)
	return middleware.RateLimit(y.repo, string(op), max, window)
}

// TrustedProxies returns the deployment's client-IP policy, parsed and
// validated at Build. Consumers that guard their OWN routes with
// Middleware().RequireAuth and run a non-default policy should wrap those
// routes with middleware.TrustedProxiesMiddleware(ya.TrustedProxies()) so
// the address they record matches the one yauth recorded at login.
func (y *YAuth) TrustedProxies() middleware.TrustedProxies { return y.trusted }

// Compile-time checks that *YAuth satisfies the host contracts.
var (
	_ plugin.PluginHost          = (*YAuth)(nil)
	_ plugin.RateLimitConfigurer = (*YAuth)(nil)
	_ plugin.AuditFanout         = (*YAuth)(nil)
)
