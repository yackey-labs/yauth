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
//	GET    {prefix}/oauth2/clients                — admin: list clients
//	POST   {prefix}/oauth2/clients                — admin: register a client
//	GET    {prefix}/oauth2/clients/{id}           — admin: fetch a client
//	PATCH  {prefix}/oauth2/clients/{id}           — admin: ban/rotate-key
//	DELETE {prefix}/oauth2/clients/{id}           — admin: ban (soft delete)
//	POST   {prefix}/oauth2/clients/{id}/ban       — admin: ban with reason
//	POST   {prefix}/oauth2/clients/{id}/unban     — admin: clear ban
//	POST   {prefix}/oauth2/clients/{id}/rotate-public-key — admin: replace PKJWT key
//	GET    {prefix}/oauth2/authorize              — return JSON consent payload
//	POST   {prefix}/oauth2/consent                — approve/deny a pending request
//	POST   {prefix}/oauth2/token                  — token endpoint (dispatch)
//	POST   {prefix}/oauth2/revoke                 — RFC 7009
//	POST   {prefix}/oauth2/introspect             — RFC 7662
//	POST   {prefix}/oauth2/device_authorization   — RFC 8628 (device init)
//	POST   {prefix}/oauth2/device                 — user enters user_code
//	GET    {prefix}/.well-known/oauth-authorization-server — RFC 8414 metadata
package oauth2server

import (
	"net/http"
	"sync"
	"time"

	"github.com/yackey-labs/yauth-go/plugin"
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
	// Default: "/oauth2/device".
	VerificationURI string
	// ConsentRequired forces the consent payload to be returned even if
	// a prior matching Consent record exists. Set true while developing
	// or for clients with sensitive scopes.
	ConsentRequired bool
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
		cfg.VerificationURI = "/oauth2/device"
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
func (p *oauth2Plugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	mw := host.Middleware()

	// --- admin client CRUD ---
	mux.Handle("GET "+prefix+"/oauth2/clients", mw.RequireAdmin(http.HandlerFunc(p.handleListClients(host))))
	mux.Handle("POST "+prefix+"/oauth2/clients", mw.RequireAdmin(http.HandlerFunc(p.handleCreateClient(host))))
	mux.Handle("GET "+prefix+"/oauth2/clients/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleGetClient(host))))
	mux.Handle("PATCH "+prefix+"/oauth2/clients/{id}", mw.RequireAdmin(http.HandlerFunc(p.handlePatchClient(host))))
	mux.Handle("DELETE "+prefix+"/oauth2/clients/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleDeleteClient(host))))
	mux.Handle("POST "+prefix+"/oauth2/clients/{id}/ban", mw.RequireAdmin(http.HandlerFunc(p.handleBanClient(host))))
	mux.Handle("POST "+prefix+"/oauth2/clients/{id}/unban", mw.RequireAdmin(http.HandlerFunc(p.handleUnbanClient(host))))
	mux.Handle("POST "+prefix+"/oauth2/clients/{id}/rotate-public-key", mw.RequireAdmin(http.HandlerFunc(p.handleRotatePublicKey(host))))

	// --- RFC 8414 authorization server metadata ---
	mux.Handle("GET "+prefix+"/.well-known/oauth-authorization-server", http.HandlerFunc(p.handleAuthServerMetadata(host)))

	// --- authorization-code + consent ---
	// /authorize is a session-protected endpoint: the caller must be a
	// logged-in user before consent makes sense.
	mux.Handle("GET "+prefix+"/oauth2/authorize", mw.RequireAuth(http.HandlerFunc(p.handleAuthorize(host))))
	mux.Handle("POST "+prefix+"/oauth2/consent", mw.RequireAuth(http.HandlerFunc(p.handleConsent(host))))

	// --- token / introspect / revoke ---
	mux.Handle("POST "+prefix+"/oauth2/token", http.HandlerFunc(p.handleToken(host)))
	mux.Handle("POST "+prefix+"/oauth2/introspect", http.HandlerFunc(p.handleIntrospect(host)))
	mux.Handle("POST "+prefix+"/oauth2/revoke", http.HandlerFunc(p.handleRevoke(host)))

	// --- device flow ---
	mux.Handle("POST "+prefix+"/oauth2/device_authorization", http.HandlerFunc(p.handleDeviceAuth(host)))
	mux.Handle("POST "+prefix+"/oauth2/device", mw.RequireAuth(http.HandlerFunc(p.handleDeviceVerify(host))))
}
