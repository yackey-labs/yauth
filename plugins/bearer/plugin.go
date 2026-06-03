// Package bearer implements the JWT bearer-token authentication plugin
// for yauth-go.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/token          email+password → access_token + refresh_token
//	POST {prefix}/token/refresh  rotate refresh; family-revokes on reuse
//	POST {prefix}/token/revoke   (auth) revoke a refresh token
//
// In addition to its routes, Routes registers an AuthResolver with the
// host so that requests carrying an "Authorization: Bearer <jwt>" header
// are resolved by the tri-mode middleware.
//
// JWT secret resolution order:
//
//  1. Config.JWTSecret (set by the caller).
//  2. host.JWTSecret() (set globally on the builder via WithJWTSecret).
//
// If both are empty the plugin panics at construction time — bearer
// without a signing secret is non-functional.
package bearer

import (
	"github.com/danielgtaylor/huma/v2"

	"time"

	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes the bearer plugin. Zero values resolve to safe defaults
// during Routes(): AccessTTL=15m, RefreshTTL=720h (30d), Issuer="yauth".
type Config struct {
	// JWTSecret is the HS256 signing secret. If empty, the plugin falls
	// back to host.JWTSecret() during Routes().
	JWTSecret []byte
	// AccessTTL is the lifetime of issued access tokens. Default: 15m.
	AccessTTL time.Duration
	// RefreshTTL is the lifetime of issued refresh tokens. Default: 720h
	// (30 days).
	RefreshTTL time.Duration
	// Issuer is the JWT "iss" claim. Default: "yauth".
	Issuer string
	// Audience, when non-empty, is set as the JWT "aud" claim and
	// enforced on verification.
	Audience string
}

// bearerPlugin is the unexported plugin.Plugin implementation.
type bearerPlugin struct {
	cfg Config
}

// New constructs the bearer plugin. The returned plugin defers JWT
// secret resolution to Routes() so callers can rely on host-level
// configuration via Builder.WithJWTSecret.
func New(cfg Config) plugin.Plugin {
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "yauth"
	}
	return &bearerPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *bearerPlugin) Name() string { return "bearer" }

// Routes implements plugin.Plugin. It resolves the JWT secret, registers
// a Bearer AuthResolver with the host, and wires the /token endpoints as
// huma-native typed operations on the shared huma.API.
//
// Every route uses StashHTTPHuma so the migrated handlers keep byte-identical
// request parsing: the input structs carry NO huma Body field, so huma never
// consumes the body and bearer's strict decodeJSON (DisallowUnknownFields,
// 1 MiB cap, INVALID_REQUEST error semantics) stays authoritative. /token and
// /token/refresh are public (Security: none); /token/revoke is gated by
// RequireAuthHuma — the same identity logic as the legacy mw.RequireAuth
// wrapper. The mux is retained in the signature for plugins that still register
// raw net/http routes; bearer no longer uses it.
//
// Panics if no JWT secret is available (neither Config.JWTSecret nor
// host.JWTSecret()) — bearer cannot operate without one.
func (p *bearerPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	if len(p.cfg.JWTSecret) == 0 {
		p.cfg.JWTSecret = host.JWTSecret()
	}
	if len(p.cfg.JWTSecret) == 0 {
		panic("bearer plugin: JWT secret is required (set Config.JWTSecret or use yauth.Builder.WithJWTSecret)")
	}

	host.RegisterAuthResolver(newResolver(host, p.cfg))

	mw := host.Middleware()
	p.registerToken(host, api, prefix)
	p.registerRefresh(host, api, prefix)
	p.registerRevoke(host, api, mw, prefix)
}

// stashOnly is the per-operation middleware chain for the public token
// endpoints: stash the raw request/writer so the migrated handlers reuse
// bearer's strict net/http body decoder.
func stashOnly(api huma.API) huma.Middlewares {
	return huma.Middlewares{middleware.StashHTTPHuma(api)}
}
