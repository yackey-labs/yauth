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
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/auth/safehttp"
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
	// to the IdP (discovery, JWKS, token exchange). nil builds the
	// egress-guarded default client — see httpClient(). A client supplied
	// here is used verbatim, guard and all: it is the caller's own
	// transport and the caller owns its policy.
	HTTPClient *http.Client

	// AllowPrivateNetworkIDP opts this plugin's outbound IdP calls into
	// loopback / RFC 1918 destinations.
	//
	// A connection's discovery_url is chosen by an ORG admin (org creation is
	// open to any signed-up user in most deployments), and the server then
	// dials it: on /test, on every /sso/login, on every /sso/callback, and on
	// back-channel logout. That makes the server's network position a
	// primitive the caller aims — at a database bound to loopback, at
	// anything inside the VPC, at the cloud metadata service. So the default
	// is FALSE and auth/safehttp refuses the dial.
	//
	// Set true when the IdP genuinely lives inside the perimeter — an
	// in-cluster Keycloak at http://keycloak.identity.svc:8080 is a
	// first-class deployment shape. Even then 169.254.0.0/16 stays refused;
	// see safehttp.IsAlwaysDeniedIP.
	AllowPrivateNetworkIDP bool

	// SelfIssuer is this app's OWN OIDC issuer URL (e.g.
	// "https://app/api/auth"). When set and an asymmetric signer is registered
	// (asymjwt), the runtime federate endpoint signs a software_statement so the
	// app self-registers at a trusted upstream IdP with NO admin key. Optional.
	SelfIssuer string

	// SatisfiesMFA declares whether the upstream IdP's own authentication
	// counts as the second factor. nil (the default) means TRUE, which is
	// both what /sso/callback has always done and the usual enterprise
	// arrangement: an org buys SSO precisely so the IdP owns
	// authentication policy, MFA included. The difference is that it is
	// now asserted in the login event instead of being the side effect of
	// a discarded step-up decision, so mfa's gate stands down and lockout
	// sees a completed login.
	//
	// Set a pointer to false where local TOTP must be enforced regardless
	// of the IdP. The callback is a browser redirect and cannot carry a
	// {require_mfa, pending_session_id} challenge, so a step-up decision
	// then FAILS CLOSED with 403 and no session. See
	// plugin.RunFederatedLogin.
	SatisfiesMFA *bool

	// LoginStateBinding controls whether /sso/login ties the login state to
	// the browser that started the flow — see auth/login_binding.go for the
	// attack this closes (a finished-but-undelivered /sso/callback URL was a
	// portable credential for "become whoever authenticated at the IdP").
	//
	// "" / "auto" binds iff the deployment issues Secure cookies, "required"
	// always binds, "off" never does. Validated by New; the knob is named
	// verbatim in the 400 body.
	LoginStateBinding string
}

// satisfiesMFA reports the effective SatisfiesMFA value, defaulting to
// true when the caller left the pointer nil.
func (c *Config) satisfiesMFA() bool {
	if c.SatisfiesMFA == nil {
		return true
	}
	return *c.SatisfiesMFA
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
	// Loud on an unknown mode: "off" mistyped would otherwise silently become
	// "auto" and refuse every login on a deployment that cannot carry the
	// binding cookie.
	mode, err := auth.NormalizeLoginStateBinding(cfg.LoginStateBinding)
	if err != nil {
		return nil, fmt.Errorf("ssooidc: %w", err)
	}
	cfg.LoginStateBinding = mode
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

// httpClient returns the configured HTTP client or the egress-guarded
// default. The helper exists so tests can swap in an httptest server.
//
// EVERY outbound call this plugin makes goes through here — discovery, JWKS,
// the token exchange, the DCR registration POST, the federation-grant
// redemption — and every one of them is aimed by a destination an admin
// typed into a connection row. Until this returned a bare
// &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}, so
// the only thing standing between "org admin" and "read anything the server
// can reach" was config.go's "must start with http(s)://" prefix check. An
// admin set discovery_url = http://127.0.0.1:6379 (or 169.254.169.254) and
// POSTed .../test, and the route dialled it and echoed the document back.
//
// safehttp.Client is yauth's single answer to that shape (the same one the
// webhook, audit-export and oauth2server jwks_uri fetches use): it resolves
// the host itself and dials the address it checked, so a DNS-rebinding
// answer cannot flip between the two, and it caps redirects at 3 — a
// redirect is otherwise how a public IdP hands the fetch to a private one.
// safehttp.Client already wraps its transport in otelhttp, so the outbound
// CLIENT spans and W3C traceparent propagation are unchanged.
//
// A caller-supplied HTTPClient is still used VERBATIM. That is the documented
// escape hatch (see Config.HTTPClient) for a deployment that wants its own
// transport — proxy, mTLS to the IdP, a test's httptest client — and it is
// deliberately not second-guessed here; a caller handing us a client has
// already made the policy decision.
func (p *ssoOIDCPlugin) httpClient() *http.Client {
	if p.cfg.HTTPClient != nil {
		return p.cfg.HTTPClient
	}
	return safehttp.Client(p.cfg.AllowPrivateNetworkIDP, defaultHTTPTimeout, 3)
}

// jwksCache returns the lazily-initialized process-wide JWKS cache.
func (p *ssoOIDCPlugin) jwksCache() *jwksCache {
	p.jwksCacheOnce.Do(func() {
		p.jwksCacheRef = newJWKSCache(p.cfg.JWKSCacheTTL, p.cfg.JWKSRefreshCooldown, p.httpClient())
	})
	return p.jwksCacheRef
}
