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
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/yackey-labs/yauth-go/plugin"
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
func (p *ssoOIDCPlugin) Routes(host plugin.PluginHost, mux plugin.Router, prefix string) {
	mw := host.Middleware()

	mux.Handle("POST "+prefix+"/organizations/{id}/sso/connections", mw.RequireAuth(http.HandlerFunc(p.handleCreateConnection(host))))
	mux.Handle("GET "+prefix+"/organizations/{id}/sso/connections", mw.RequireAuth(http.HandlerFunc(p.handleListConnections(host))))
	mux.Handle("GET "+prefix+"/organizations/{id}/sso/connections/{cid}", mw.RequireAuth(http.HandlerFunc(p.handleGetConnection(host))))
	mux.Handle("PATCH "+prefix+"/organizations/{id}/sso/connections/{cid}", mw.RequireAuth(http.HandlerFunc(p.handleUpdateConnection(host))))
	mux.Handle("DELETE "+prefix+"/organizations/{id}/sso/connections/{cid}", mw.RequireAuth(http.HandlerFunc(p.handleDeleteConnection(host))))
	mux.Handle("POST "+prefix+"/organizations/{id}/sso/connections/{cid}/test", mw.RequireAuth(http.HandlerFunc(p.handleTestConnection(host))))

	// User-facing routes (begin SSO + callback). Wired here so the
	// admin CRUD and the login surface live in the same plugin. The
	// route bodies live in login.go and callback.go.
	mux.Handle("GET "+prefix+"/sso/login", http.HandlerFunc(p.handleSsoLogin(host)))
	mux.Handle("GET "+prefix+"/sso/callback", http.HandlerFunc(p.handleSsoCallback(host)))
	mux.Handle("POST "+prefix+"/sso/callback", http.HandlerFunc(p.handleSsoCallback(host)))

	// OIDC Back-Channel Logout 1.0 receiver: the upstream IdP POSTs a
	// logout_token here when a user is logged out/offboarded, and we terminate
	// the matching local sessions. Public (verified by logout_token signature).
	mux.Handle("POST "+prefix+"/sso/backchannel-logout", http.HandlerFunc(p.handleBackchannelLogout(host)))
}

// httpClient returns the configured HTTP client or a 10s-timeout
// default. The helper exists so tests can swap in an httptest server.
func (p *ssoOIDCPlugin) httpClient() *http.Client {
	if p.cfg.HTTPClient != nil {
		return p.cfg.HTTPClient
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

// jwksCache returns the lazily-initialized process-wide JWKS cache.
func (p *ssoOIDCPlugin) jwksCache() *jwksCache {
	p.jwksCacheOnce.Do(func() {
		p.jwksCacheRef = newJWKSCache(p.cfg.JWKSCacheTTL, p.cfg.JWKSRefreshCooldown, p.httpClient())
	})
	return p.jwksCacheRef
}
