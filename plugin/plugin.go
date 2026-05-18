// Package plugin defines the contract a yauth-go plugin must satisfy and the
// PluginHost interface that is passed to plugins when their routes are
// registered. The host gives a plugin access to the repository, the
// authentication middleware, and a small slice of configuration values
// without forcing plugins to depend on the root yauth package (which would
// create an import cycle, since root depends on plugin/).
package plugin

import (
	"context"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/repo"
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

// Plugin extends yauth with new routes mounted under a prefix.
// Implementations should register handlers via the Go 1.22 ServeMux pattern API.
//
// Routes is called once during YAuth.Build(). The plugin should register
// every handler it owns onto mux using prefix as the path root (typically
// the empty string when the YAuth router is later mounted under a parent
// prefix via http.StripPrefix).
type Plugin interface {
	Name() string
	Routes(host PluginHost, mux *http.ServeMux, prefix string)
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
