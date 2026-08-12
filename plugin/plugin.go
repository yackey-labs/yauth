// Package plugin defines the contract a yauth-go plugin must satisfy and the
// PluginHost interface that is passed to plugins when their routes are
// registered. The host gives a plugin access to the repository, the
// authentication middleware, and a small slice of configuration values
// without forcing plugins to depend on the root yauth package (which would
// create an import cycle, since root depends on plugin/).
package plugin

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/repo"
)

// AuthResolver is an alternative identity-resolution path that plugins can
// register with the host. It is a type alias of middleware.AuthResolver so
// that plugins can refer to it as plugin.AuthResolver without taking on a
// direct dependency on the middleware package's other surface area.
//
// See middleware.AuthResolver for the recognized/error contract.
type AuthResolver = middleware.AuthResolver

// PluginHost is the surface plugins use to integrate with the running
// YAuth instance. The root yauth.YAuth implements this interface.
//
// Config values are exposed as individual getters rather than as a config
// struct to avoid an import cycle: yauth root imports plugin/, so plugin/
// cannot import yauth root. Each method below corresponds 1-1 with a field
// on yauth.YAuthConfig.
type PluginHost interface {
	Repo() repo.Repository
	Middleware() *middleware.Middleware

	// Logger returns the host's structured logger — the one the consumer
	// injected via Builder.WithLogger (or slog.Default() if none was set).
	// Plugins MUST log through this rather than the standard log package,
	// slog package-level functions, or os.Stderr, so all yauth output
	// routes through the app's configured handler (level, format, trace
	// correlation). Never nil.
	Logger() *slog.Logger

	SessionTTL() time.Duration
	CookieName() string
	CookieDomain() string
	CookieSecure() bool
	CookiePath() string
	CookieSameSite() http.SameSite

	// SessionBinding returns the deployment-global session-binding
	// flags (BindIP, BindUserAgent). Plugins read these as the
	// inherit-global fallback when resolving an effective per-org
	// auth policy (yauth #92 / yauth-go #21). The mismatch-action
	// knobs are intentionally not exposed — they are middleware
	// implementation detail.
	SessionBinding() (bindIP, bindUserAgent bool)

	// BaseURL returns the absolute URL the API is reachable at, e.g.
	// "https://app.example.com". Empty when not configured. Plugins use
	// it to build outbound links (verification emails, OIDC issuer)
	// when they have no local override.
	BaseURL() string

	// AllowSignups reports whether public registration is enabled.
	// /register returns 403 SIGNUPS_DISABLED when this is false.
	AllowSignups() bool

	// AutoAdminFirstUser reports whether the very first user registered
	// should be promoted to role "admin" automatically.
	AutoAdminFirstUser() bool

	// RegisterEventHandler appends h to the host's auth-event pipeline.
	// Handlers fire in registration order; the first non-Continue decision
	// short-circuits the chain.
	RegisterEventHandler(h events.Handler)

	// RegisterEventGate appends h to the pipeline's GATE stage, which runs
	// to completion before any RegisterEventHandler handler, whatever
	// order the plugins were registered in. Gates fire in their own
	// registration order and short-circuit the same way.
	//
	// Reserved for handlers that decide whether a login may proceed —
	// today only mfa's step-up. The distinction is not cosmetic: a gate
	// answering login.succeeded with RequireMfa is saying "this login has
	// NOT completed", so observers that mutate per-login state (lockout
	// clearing its failure counter) must not already have run. Which of
	// the two happened first used to depend on plugin registration order:
	// mfa before lockout meant an MFA user's counter was never cleared and
	// they were eventually locked out despite always authenticating
	// correctly; lockout before mfa meant wrong TOTP codes were forgiven
	// by the next password login, so MFA brute force went unthrottled.
	RegisterEventGate(h events.Handler)

	// RegisterAuthResolver appends r to the list of alternative identity
	// resolvers consulted by the middleware after the cookie path.
	RegisterAuthResolver(r AuthResolver)

	// PluginNames returns the Name() of every plugin registered on the
	// host, in registration order. Used by the status plugin.
	PluginNames() []string

	// JWTSigner returns the registered JWTSigner, or nil if no asymmetric-
	// JWT plugin is loaded. Plugins that need RS256/ES256 signing (oidc,
	// oauth2-server) should check for nil and refuse to start when absent.
	JWTSigner() JWTSigner

	// JWTSecret returns the HS256 secret used by the bearer plugin, or nil
	// if no bearer plugin is loaded.
	JWTSecret() []byte

	// RegisterMFAVerifier publishes v as the host's second-factor
	// verifier. The mfa plugin calls this from its Routes hook; the
	// contract is "first verifier wins", like SetJWTSigner.
	RegisterMFAVerifier(v MFAVerifier)

	// MFAVerifier returns the registered MFAVerifier, or nil if no MFA
	// plugin is loaded. Plugins that complete a login outside the cookie
	// flow (bearer) must look it up lazily inside their handlers —
	// plugin registration order is not guaranteed.
	MFAVerifier() MFAVerifier

	// Emit fans an AuthEvent through every registered events.Handler in
	// registration order. The first non-Continue decision short-circuits
	// and is returned to the caller; the caller is responsible for
	// honoring the decision (writing a Block response, branching to MFA,
	// etc.).
	Emit(ctx context.Context, event events.AuthEvent) (events.Decision, error)

	// RateLimit returns a middleware that enforces a fixed-window rate
	// limit on the wrapped handler. Plugins call this to wrap their
	// public-facing routes (login, register, forgot-password, etc.).
	// max<=0 or window<=0 disables the limiter — callers can pass the
	// configured rule without branching.
	RateLimit(name string, max int, window time.Duration) func(http.Handler) http.Handler
}

// MFAVerifier completes a second-factor challenge that an events.Handler
// opened with an events.RequireMfa decision. The mfa plugin registers an
// implementation via PluginHost.RegisterMFAVerifier; plugins that finish a
// login without a cookie session (bearer's /token) retrieve it via
// PluginHost.MFAVerifier and MUST refuse the exchange when it is nil, so a
// challenge can never be waved through by a deployment that dropped the mfa
// plugin.
//
// This mirrors the JWTSigner brokering pattern: one plugin supplies a
// capability, another consumes it, and neither imports the other.
type MFAVerifier interface {
	// VerifyPendingChallenge consumes the pending session identified by
	// pendingSessionID and validates code against the user's second
	// factor (TOTP or a backup code). It returns the authenticated user's
	// id with ok=true only when both succeed.
	//
	// ok=false covers every credential-level failure — unknown, expired
	// or already-consumed pending session, wrong code — and callers MUST
	// answer with a single opaque 401 so the cases stay
	// indistinguishable. A non-nil error means a backend failure (500),
	// never a failed verification.
	//
	// The pending session is single-use and is consumed even when the
	// code turns out to be wrong, so a challenge cannot be brute-forced.
	VerifyPendingChallenge(ctx context.Context, pendingSessionID, code string) (userID string, ok bool, err error)
}

// RunFederatedLogin runs the login half of the auth-event pipeline for a
// login completed by an EXTERNAL identity provider — the oauth client, the
// SSO OIDC relying party and the SSO SAML service provider — and reports
// whether the login may proceed. A nil error means "issue the session"; a
// non-nil error is a huma error the caller must return unchanged.
//
// Those three flows end in a browser redirect (or a bodyless 302), so
// unlike the cookie password login they cannot hand the caller a
// {require_mfa, pending_session_id} challenge to answer — there is no
// response body to put it in, and no redirect contract for carrying it.
// Both decisions are still honoured, they just have fewer shapes to land in:
//
//   - Block → the mapped status, no session. This is unconditional: a
//     locked account must not obtain a session by any route, and before
//     this the decision was discarded and the cookie was set anyway.
//   - RequireMfa → 403, no session, when satisfiesMFA is false. Failing
//     closed is the only honest option on a flow that cannot carry the
//     challenge.
//
// satisfiesMFA=true (each plugin's default, preserving today's behaviour)
// declares the IdP's own authentication to BE the second factor. It is
// asserted in the event via events.MFACompleted() rather than by dropping
// the decision: the marker stands mfa's gate down instead of minting a
// challenge no one will answer, and lets observers such as lockout see a
// COMPLETED login, which is what clears the failure counter. Dropping the
// decision — the old behaviour — did neither, so an MFA-enrolled user's
// lockout counter was never cleared by a federated login.
func RunFederatedLogin(
	ctx context.Context,
	host PluginHost,
	satisfiesMFA bool,
	userID, email string,
	ip *string,
	method string,
) error {
	uid := userID
	em := email
	m := method

	attempt := events.AuthEvent{
		Type:      events.EventLoginAttempt,
		UserID:    &uid,
		IPAddress: ip,
		Method:    &m,
	}
	if em != "" {
		attempt.Email = &em
	}
	// login.attempt is what lockout answers with Block; its onSucceeded
	// only ever clears state. Without this event a locked account could
	// still open a session through an external IdP.
	if dec, _ := host.Emit(ctx, attempt); dec.Kind == events.DecisionKindBlock {
		return huma.NewError(decisionStatus(dec), decisionMessage(dec))
	}

	succeeded := attempt
	succeeded.Type = events.EventLoginSucceeded
	if satisfiesMFA {
		succeeded.Metadata = events.MFACompleted()
	}
	dec, _ := host.Emit(ctx, succeeded)
	switch dec.Kind {
	case events.DecisionKindBlock:
		return huma.NewError(decisionStatus(dec), decisionMessage(dec))
	case events.DecisionKindRequireMfa:
		return huma.Error403Forbidden("multi-factor authentication is required and cannot be completed on this login method")
	}
	return nil
}

// decisionStatus / decisionMessage map a Block decision onto an HTTP
// response the same way the email-password, bearer and mfa login paths do,
// so a lockout 429 reads identically wherever a login is finished.
func decisionStatus(d events.Decision) int {
	if d.BlockStatus == 0 {
		return http.StatusForbidden
	}
	return d.BlockStatus
}

func decisionMessage(d events.Decision) string {
	if d.BlockMessage == "" {
		return "request blocked"
	}
	return d.BlockMessage
}

// JWTSigner is the abstraction asymmetric-JWT and OIDC plugins use to
// produce and validate signed tokens. The asymjwt plugin registers an
// implementation via PluginHost; other plugins (oidc, oauth2-server)
// retrieve it via PluginHost.JWTSigner.
//
// Algo returns the JWS alg header ("HS256", "RS256", "ES256"). KID is the
// key ID embedded in headers and JWKS entries. PublicJWKS returns the
// JSON-encoded JWKS document for the public verification key (HS256
// signers may return an empty JWKS).
type JWTSigner interface {
	Sign(claims map[string]any) (string, error)
	Verify(token string) (map[string]any, error)
	Algo() string
	KID() string
	PublicJWKS() ([]byte, error)
}

// Router is the subset of *http.ServeMux that plugins use to register their
// handlers inside Routes. It is an interface (rather than the concrete
// *http.ServeMux) so the root yauth package retains the freedom to wrap the mux
// without touching plugins. The real *http.ServeMux satisfies this interface.
//
// The two methods are exactly the ones plugins call (Handle / HandleFunc with
// the Go 1.22 "METHOD /path" pattern syntax). If a future plugin needs another
// ServeMux method inside Routes, add it here.
type Router interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// Plugin extends yauth with new routes mounted under a prefix.
// Implementations should register handlers via the Go 1.22 ServeMux pattern API.
//
// Routes is called once during YAuth.Build(). The plugin should register
// every handler it owns onto mux using prefix as the path root (typically
// the empty string when the YAuth router is later mounted under a parent
// prefix via http.StripPrefix).
//
// api is the huma.API used by huma-native (typed) operations. Plugins
// migrated to huma serving call huma.Register(api, ...); plugins still on
// net/http ignore it and register onto mux as before. Both register against
// the same underlying mux, so the two styles coexist during the migration.
type Plugin interface {
	Name() string
	Routes(host PluginHost, mux Router, api huma.API, prefix string)
}

// ShutdownAware is an optional interface plugins implement when they own
// background goroutines, network clients, or other resources that need to
// drain on process exit. YAuth.Shutdown invokes Shutdown(ctx) on every
// registered plugin that satisfies this interface, in registration order,
// and returns the first non-nil error.
//
// Implementations must honor ctx — if ctx is cancelled before the
// background work drains, Shutdown should return ctx.Err() so callers
// know the drain was incomplete.
type ShutdownAware interface {
	Shutdown(ctx context.Context) error
}
