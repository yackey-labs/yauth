// Package oauth2server implements an OAuth2 authorization server plugin
// for yauth-go (RFC 6749 + 7636 PKCE + 8628 device + 7009 revoke +
// 7662 introspect).
//
// Supported grant types in this round:
//
//   - authorization_code (with PKCE S256, optional OIDC nonce)
//   - refresh_token
//   - client_credentials
//   - urn:ietf:params:oauth:grant-type:device_code
//
// Skipped (returns unsupported_grant_type / invalid_client):
//
//   - urn:ietf:params:oauth:grant-type:jwt-bearer (RFC 7523)
//   - private_key_jwt client auth — gated behind asymjwt being loaded
//
// Token issuance prefers host.JWTSigner() (asymjwt) when available; it
// falls back to HS256 with host.JWTSecret() otherwise. Refresh tokens
// are opaque 32-byte hex strings persisted hashed via the bearer
// plugin's RefreshTokenRepository (same table, same family-id rotation).
//
// Routes (relative to prefix):
//
//	GET    {prefix}/oauth2/clients                — admin: list clients (Go-only admin namespace)
//	POST   {prefix}/oauth2/clients                — admin: register a client (Go-only)
//	GET    {prefix}/oauth2/clients/{id}           — admin: fetch a client (Go-only)
//	PATCH  {prefix}/oauth2/clients/{id}           — admin: ban/rotate-key (Go-only)
//	DELETE {prefix}/oauth2/clients/{id}           — admin: ban (soft delete) (Go-only)
//	POST   {prefix}/oauth2/clients/{id}/ban       — admin: ban with reason (Go-only)
//	POST   {prefix}/oauth2/clients/{id}/unban     — admin: clear ban (Go-only)
//	POST   {prefix}/oauth2/clients/{id}/rotate-public-key — admin: replace PKJWT key (Go-only)
//	GET    {prefix}/oauth/authorize               — return JSON consent payload
//	POST   {prefix}/oauth2/consent                — approve/deny a pending request (Go-specific split; Rust merges into authorize)
//	POST   {prefix}/oauth/token                   — token endpoint (dispatch)
//	POST   {prefix}/oauth/revoke                  — RFC 7009
//	POST   {prefix}/oauth/introspect              — RFC 7662
//	POST   {prefix}/oauth/device/code             — RFC 8628 (device init)
//	POST   {prefix}/oauth/device                  — user enters user_code
//	GET    {prefix}/.well-known/oauth-authorization-server — RFC 8414 metadata
//	POST   {prefix}/oauth/register                — RFC 7591 dynamic client registration (opt-in: Config.DCREnabled)
package oauth2server

import (
	"github.com/danielgtaylor/huma/v2"

	"sync"
	"time"

	"github.com/yackey-labs/yauth/plugin"
)

// Config tunes the oauth2-server plugin. Zero values resolve to safe
// defaults during Routes(): AccessTTL=15m, RefreshTTL=720h, AuthCodeTTL=
// 10m, DeviceCodeTTL=5m, DevicePollInterval=5s, Issuer="yauth",
// VerificationURI="/oauth2/device".
type Config struct {
	// Issuer is the JWT "iss" claim and the "iss" returned by introspect.
	Issuer string
	// BasePath is the external URL prefix the YAuth router is mounted
	// under. It is concatenated with the runtime host in metadata
	// responses; the device flow uses VerificationURI directly.
	BasePath string
	// AccessTTL is the lifetime of issued access tokens. Default: 15m.
	AccessTTL time.Duration
	// RefreshTTL is the lifetime of issued refresh tokens. Default: 720h
	// (30 days).
	RefreshTTL time.Duration
	// AuthCodeTTL is the lifetime of single-use authorization codes.
	// Default: 10m.
	AuthCodeTTL time.Duration
	// DeviceCodeTTL is the lifetime of issued device codes. Default: 5m.
	DeviceCodeTTL time.Duration
	// DevicePollInterval is the polling interval (seconds) returned to
	// clients in the device-authorization response. Default: 5.
	DevicePollInterval int
	// VerificationURI is the URL displayed to users in the device flow.
	// Default: "/oauth/device".
	VerificationURI string
	// ConsentRequired forces the consent payload to be returned even if
	// a prior matching Consent record exists. Set true while developing
	// or for clients with sensitive scopes.
	ConsentRequired bool
	// DCREnabled enables the RFC 7591 dynamic client registration
	// endpoint at POST /oauth/register. Default: false.
	//
	// When enabled, the registration policy is split by risk:
	//   - A public client (token_endpoint_auth_method=none) whose
	//     redirect_uris are ALL loopback (localhost / 127.0.0.1 / ::1) may
	//     register ANONYMOUSLY. This is the safe subset — a loopback
	//     redirect can only deliver the authorization code to the caller's
	//     own machine, so it closes the redirect-phishing vector — and it
	//     is exactly what local MCP / native-app clients (e.g. Claude Code)
	//     need to self-register with an ephemeral callback port.
	//   - Any registration with a non-loopback redirect, or a confidential
	//     client, requires an authenticated administrator (same rule as
	//     RequireAdmin: a cookie-resolved admin session unless
	//     AllowAdminMachineCallers is set).
	//
	// SECURITY / BEHAVIOR-CHANGE NOTE: anonymous loopback registration is
	// the default when DCREnabled is true. The exploitable token-theft
	// vector is closed by the loopback restriction, but the endpoint then
	// accepts unauthenticated POSTs that create public client rows — apply
	// rate limiting at your edge (gateway/CDN) as you would for any other
	// unauthenticated endpoint (yauth-go does not rate-limit /oauth/token,
	// /oauth/introspect, or /oauth/device/code either). Operators who want
	// the prior behaviour — every registration gated behind an admin —
	// set DCRRequireAdminForLoopback.
	DCREnabled bool
	// DCRRequireAdminForLoopback restores the strict pre-loopback-anonymous
	// behaviour: when true, EVERY POST /oauth/register requires an
	// authenticated administrator, including public loopback-only clients.
	// Default: false (loopback-only public clients may self-register
	// anonymously per DCREnabled). Set true on a multi-tenant or public
	// deployment where you cannot rate-limit anonymous registration at the
	// edge and prefer to provision all clients via an admin.
	DCRRequireAdminForLoopback bool
	// DCRAllowConfidentialClients controls whether POST /oauth/register may
	// create confidential clients (those with a secret / private_key_jwt).
	// Default: false — self-registered clients are public (PKCE,
	// token_endpoint_auth_method=none) only. This blocks the escalation where
	// an anonymous registrant obtains a confidential client and uses
	// client_credentials to mint a no-user token. Provision confidential/M2M
	// clients via the authenticated admin endpoint instead. Set true only if
	// you trust the DCR path (e.g. gated registration).
	DCRAllowConfidentialClients bool
	// AllowPrivateNetworkJWKSURI permits private_key_jwt clients to supply a
	// jwks_uri pointing at a loopback or RFC 1918 address. Default: false
	// (SSRF protection). Set true only in development/test environments where
	// local JWKS endpoints are needed.
	AllowPrivateNetworkJWKSURI bool
	// BackchannelLogoutTimeout bounds each OIDC Back-Channel Logout delivery
	// (the OP→RP logout_token POST). Default: 5s. Delivery is best-effort and
	// asynchronous; this only caps how long a single attempt may hang.
	BackchannelLogoutTimeout time.Duration
	// DCRStaleClientTTL enables the background sweep of stale dynamically-
	// registered clients: a DCR client unused (no token-endpoint use) for longer
	// than this is purged along with its dependent consents/codes. 0 (default)
	// disables the sweep entirely. Admin-provisioned clients are never touched.
	// A sensible value is the refresh-token TTL — past it, any token the client
	// minted is already expired, so the client provably can't grant access.
	DCRStaleClientTTL time.Duration
	// DCRStaleSweepInterval is how often the sweep runs when DCRStaleClientTTL
	// is set. Default: 24h.
	DCRStaleSweepInterval time.Duration
}

// oauth2Plugin is the unexported plugin.Plugin implementation.
type oauth2Plugin struct {
	cfg Config

	// pendingMu guards in-memory pending /authorize requests. The
	// payload is held here for the consent POST to consume; storing it
	// in memory mirrors the Rust source and avoids a new repo table.
	pendingMu sync.Mutex
	pending   map[string]*pendingRequest

	// jwksMu guards the per-client JWKS cache used by private_key_jwt.
	jwksMu sync.Mutex
	jwks   map[string]*jwksEntry

	// sweepOnce guards one-time start of the stale-DCR-client sweep goroutine.
	sweepOnce sync.Once
}

// New constructs the oauth2-server plugin.
func New(cfg Config) plugin.Plugin {
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.AuthCodeTTL <= 0 {
		cfg.AuthCodeTTL = 10 * time.Minute
	}
	if cfg.DeviceCodeTTL <= 0 {
		cfg.DeviceCodeTTL = 5 * time.Minute
	}
	if cfg.DevicePollInterval <= 0 {
		cfg.DevicePollInterval = 5
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "yauth"
	}
	if cfg.VerificationURI == "" {
		cfg.VerificationURI = "/oauth/device"
	}
	if cfg.BackchannelLogoutTimeout <= 0 {
		cfg.BackchannelLogoutTimeout = 5 * time.Second
	}
	if cfg.DCRStaleClientTTL > 0 && cfg.DCRStaleSweepInterval <= 0 {
		cfg.DCRStaleSweepInterval = 24 * time.Hour
	}
	return &oauth2Plugin{
		cfg:     cfg,
		pending: map[string]*pendingRequest{},
		jwks:    map[string]*jwksEntry{},
	}
}

// Name implements plugin.Plugin.
func (p *oauth2Plugin) Name() string { return "oauth2-server" }

// Routes implements plugin.Plugin. It mounts the admin client CRUD,
// authorize/consent, token, introspect, revoke, and device-flow
// endpoints described in the package doc.
func (p *oauth2Plugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	// OIDC Back-Channel Logout: react to logout/suspend/ban events by notifying
	// the user's RPs that registered a backchannel_logout_uri.
	host.RegisterEventHandler(&bclEventHandler{p: p, host: host})

	// Opt-in background sweep of stale dynamically-registered clients.
	if p.cfg.DCRStaleClientTTL > 0 {
		p.startStaleClientSweep(host)
	}

	// Every route is huma-native (see routes_huma.go). The migration is
	// transport-only: the ported handlers keep writing byte-identical RFC
	// 6749 / 7662 / 8628 / 7591 responses (including the OAuth2 error shape,
	// Cache-Control: no-store, WWW-Authenticate, redirects, and the
	// end_session HTML) via a func(huma.Context) stream body, so huma never
	// problem+json-wraps or re-marshals the OAuth2 wire bytes.
	//
	// Path note: /oauth/authorize, /oauth/token, etc. are literal patterns
	// that take precedence over the wildcard /oauth/{provider}/* registered
	// by the oauth client plugin (Go 1.22+ ServeMux specificity rules); the
	// huma adapter registers the same literal patterns, so the precedence is
	// preserved.
	//
	// The mux is retained in the Routes signature for plugins that still
	// register raw net/http routes; oauth2server no longer uses it.
	p.registerRoutes(host, api, mw, prefix)
}
