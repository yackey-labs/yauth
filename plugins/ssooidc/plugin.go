// Package sso_oidc implements yauth-go as an OIDC Relying Party — the
// "OIDC client" role complementing the existing oauth (Google/GitHub
// client) and oidc (yauth-as-Provider) plugins.
//
// Port of yauth Rust #93 / yauth-go #23. The plugin is plugin-flag
// gated: it only mounts when the organizations plugin (yauth-go #11)
// is registered, because every SsoConnection is organization-scoped.
// Single-user / anonymous deployments that never register sso_oidc
// see none of these routes.
//
// Routes registered (relative to the prefix passed in):
//
//	# Admin (per-org)
//	POST   {prefix}/organizations/{id}/sso/connections                 — create
//	GET    {prefix}/organizations/{id}/sso/connections                 — list
//	GET    {prefix}/organizations/{id}/sso/connections/{cid}           — get
//	PATCH  {prefix}/organizations/{id}/sso/connections/{cid}           — update
//	DELETE {prefix}/organizations/{id}/sso/connections/{cid}           — delete
//	POST   {prefix}/organizations/{id}/sso/connections/{cid}/test      — discovery round-trip
//
//	# User-facing (commit B — full login)
//	GET    {prefix}/sso/login                                          — begin SSO (org= or domain= HRD)
//	GET    {prefix}/sso/callback                                       — IdP returns here
//
// At-rest encryption: SsoConnection.Config carries the IdP client
// secret. The plugin AES-256-GCM-encrypts the secret with cfg.EncryptionKey
// before storage and decrypts on read. The 32-byte key is supplied
// by the caller; the zero value is rejected by New.
package ssooidc

import (
	"github.com/danielgtaylor/huma/v2"

	"errors"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/yackey-labs/yauth/plugin"
)

// Config tunes the sso_oidc plugin.
type Config struct {
	// EncryptionKey is the 32-byte AES-256-GCM key used to encrypt
	// each SsoConnection's IdP client_secret at rest. The zero value
	// is rejected by New — callers MUST supply a real key.
	//
	// The key shape matches the oauth plugin's EncryptionKey so a
	// deployment using both can reuse the same key material (it is
	// not required — they are namespaced by the JSON payload format).
	EncryptionKey [32]byte

	// StateTTL bounds how long an outbound /sso/login -> /sso/callback
	// round-trip may take. Defaults to 10 minutes (the OIDC spec
	// recommendation). State rows are single-use regardless.
	StateTTL time.Duration

	// AllowedRedirectURLs is the allow-list of post-login redirect
	// targets honored by the redirect_url query parameter. Empty
	// slice means "redirect_url is ignored entirely" — the safest
	// default. Matches the oauth plugin's option of the same name.
	AllowedRedirectURLs []string

	// JWKSCacheTTL caps the JWKS document cache lifetime when an IdP
	// does not surface a Cache-Control: max-age on its JWKS response.
	// Defaults to 1h, matching the OIDC spec recommendation. The
	// cache also refreshes on a kid-miss (rate-limited).
	JWKSCacheTTL time.Duration

	// JWKSRefreshCooldown is the minimum interval between forced
	// JWKS refetches triggered by a kid-miss. Prevents a flood of
	// id_tokens with unknown kids from hammering the IdP's JWKS
	// endpoint. Defaults to 1 minute.
	JWKSRefreshCooldown time.Duration

	// HTTPClient is the optional HTTP client used for outbound calls
	// to the IdP (discovery, JWKS, token exchange). nil uses
	// http.DefaultClient with a 10s timeout applied per-call.
	HTTPClient *http.Client

	// SelfIssuer is this app's OWN OIDC issuer URL (e.g.
	// "https://app/api/auth"). When set and an asymmetric signer is registered
	// (asymjwt), the runtime federate endpoint signs a software_statement so the
	// app self-registers at a trusted upstream IdP with NO admin key. Optional.
	SelfIssuer string
}

const (
	defaultStateTTL            = 10 * time.Minute
	defaultJWKSCacheTTL        = time.Hour
	defaultJWKSRefreshCooldown = time.Minute
	defaultHTTPTimeout         = 10 * time.Second
)

// ssoOIDCPlugin implements plugin.Plugin.
type ssoOIDCPlugin struct {
	cfg Config

	// jwksCacheOnce guards lazy initialization of the per-process
	// JWKS cache. The cache is shared across every connection in
	// the process — entries are keyed by JWKS URL so multi-IdP
	// deployments do not collide.
	jwksCacheOnce sync.Once
	jwksCacheRef  *jwksCache

	// bclJTIOnce guards lazy init of the Back-Channel Logout jti replay cache.
	bclJTIOnce sync.Once
	bclJTIRef  *bclJTICache
}

// New constructs the sso_oidc plugin. Returns a non-nil error when the
// config is invalid (zero key).
func New(cfg Config) (plugin.Plugin, error) {
	if cfg.EncryptionKey == ([32]byte{}) {
		return nil, errors.New("ssooidc: Config.EncryptionKey is required (zero value rejected)")
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = defaultStateTTL
	}
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = defaultJWKSCacheTTL
	}
	if cfg.JWKSRefreshCooldown <= 0 {
		cfg.JWKSRefreshCooldown = defaultJWKSRefreshCooldown
	}
	return &ssoOIDCPlugin{cfg: cfg}, nil
}

// MustNew is the panic-on-error variant of New.
func MustNew(cfg Config) plugin.Plugin {
	p, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return p
}

// Name implements plugin.Plugin.
func (p *ssoOIDCPlugin) Name() string { return "sso_oidc" }

// Routes implements plugin.Plugin. The plugin mounts admin CRUD
// unconditionally — the organizations plugin owns the membership/admin
// gates and the SsoConnection rows cascade with the org delete, so
// mounting these routes in a deployment without the organizations
// plugin is harmless (every route 403s on the membership lookup).
//
// User-facing login/callback routes are gated on the same hosting
// invariant. Phase A (this commit) ships the admin surface only.
// Routes implements plugin.Plugin. Every route is huma-native: a typed
// operation that threads the underlying *http.Request / http.ResponseWriter
// onto the operation context via middleware.StashHTTPHuma so the ported
// handlers keep byte-identical request parsing (custom query precedence,
// strict body decode, RequestIP, form_post handling) and response-side cookie
// writes / 302 redirects.
//
// Two route families:
//
//   - org-scoped admin CRUD under /organizations/{id}/sso/connections... —
//     gated by RequireAuthHuma plus the inline requireOrgAdmin membership
//     check (org-admin, NOT global-admin), clean typed JSON.
//   - the public SSO login flow (/sso/login, /sso/callback GET+POST,
//     /sso/backchannel-logout) — browser redirects, Set-Cookie, state/nonce/
//     CSRF, all written through the stashed raw request/writer.
//
// The mux is retained in the signature for plugins that still register raw
// net/http routes; ssooidc no longer uses it.
func (p *ssoOIDCPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	// Admin CRUD (org-scoped).
	p.registerCreateConnection(host, api, mw, prefix)
	p.registerListConnections(host, api, mw, prefix)
	p.registerGetConnection(host, api, mw, prefix)
	p.registerUpdateConnection(host, api, mw, prefix)
	p.registerDeleteConnection(host, api, mw, prefix)
	p.registerTestConnection(host, api, mw, prefix)
	p.registerFederate(host, api, mw, prefix)
	p.registerFederateStart(host, api, prefix)
	p.registerFederateReturn(host, api, prefix)
	p.registerGlobalConnectionRoutes(host, api, mw, prefix)

	// User-facing login flow. The route bodies live in handlers_login.go.
	p.registerSsoLogin(host, api, prefix)
	// GET and POST share one callback handler but need distinct OperationIDs
	// (huma requires operation-id uniqueness).
	p.registerSsoCallback(host, api, prefix, http.MethodGet, "ssooidc-callback-get")
	p.registerSsoCallback(host, api, prefix, http.MethodPost, "ssooidc-callback-post")

	// OIDC Back-Channel Logout 1.0 receiver: the upstream IdP POSTs a
	// logout_token here when a user is logged out/offboarded, and we terminate
	// the matching local sessions. Public (verified by logout_token signature).
	p.registerBackchannelLogout(host, api, prefix)
}

// httpClient returns the configured HTTP client or a 10s-timeout
// default. The helper exists so tests can swap in an httptest server.
//
// The default client's transport is wrapped with otelhttp so the outbound
// OIDC discovery / JWKS / token-exchange calls emit CLIENT spans and inject
// the W3C traceparent + baggage (so the IdP-side trace, if any, joins ours).
// A caller-supplied HTTPClient is used verbatim — instrumenting it is the
// caller's choice.
func (p *ssoOIDCPlugin) httpClient() *http.Client {
	if p.cfg.HTTPClient != nil {
		return p.cfg.HTTPClient
	}
	return &http.Client{
		Timeout:   defaultHTTPTimeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}

// jwksCache returns the lazily-initialized process-wide JWKS cache.
func (p *ssoOIDCPlugin) jwksCache() *jwksCache {
	p.jwksCacheOnce.Do(func() {
		p.jwksCacheRef = newJWKSCache(p.cfg.JWKSCacheTTL, p.cfg.JWKSRefreshCooldown, p.httpClient())
	})
	return p.jwksCacheRef
}
