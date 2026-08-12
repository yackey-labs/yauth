// Package bearer implements the JWT bearer-token authentication plugin
// for yauth-go.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/token          email+password → access_token + refresh_token
//	POST {prefix}/token/mfa      pending_session_id + code → token pair
//	POST {prefix}/token/refresh  rotate refresh; family-revokes on reuse
//	POST {prefix}/token/revoke   (auth) revoke a refresh token
//
// /token runs the same auth-event pipeline as the cookie /login
// (login.attempt / login.failed / login.succeeded), so account lockout,
// audit export and webhooks see native logins too. When a handler answers
// login.succeeded with a RequireMfa decision, /token returns
// {require_mfa, pending_session_id} and issues nothing; the caller finishes
// at /token/mfa, which completes the challenge through the host's
// plugin.MFAVerifier and returns the ordinary token pair.
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

	"github.com/yackey-labs/yauth/plugin"
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

	// ResourceIdentifiers lists the `aud` values that identify THIS
	// deployment's own API. It decides whether an OAuth2 access token —
	// one carrying `token_use: "access"`, minted by the oauth2-server
	// plugin — is the user acting in their own right or a relying party
	// acting on their behalf.
	//
	// An OAuth2 access token whose `aud` matches an entry here is
	// FIRST-PARTY: it keeps the full authority a session has. Every other
	// OAuth2 access token is DELEGATED — it still authenticates the user,
	// so /userinfo and ordinary application routes work exactly as before,
	// but it is refused on the routes that mint a lasting credential or
	// change an authentication factor: personal API keys, MFA
	// enrolment/reset, passkey enrolment, password and email changes,
	// OAuth2 consent.
	//
	// EMPTY (the default) means the deployment has declared no audience of
	// its own, so no OAuth2 access token is first-party. That is
	// deliberate: it closes the escalation without configuration, and it
	// rejects nothing that used to work — first-party credentials
	// (cookies, the token pair from POST /token, API keys) carry no
	// `token_use` claim and are untouched.
	//
	// Set it when this deployment genuinely issues access tokens FOR
	// itself — e.g. its own SPA is a registered OAuth client whose tokens
	// should behave like a session:
	//
	//	bearer.Config{ResourceIdentifiers: []string{"my-first-party-spa"}}
	//
	// Entries are compared for exact equality against each `aud` value.
	ResourceIdentifiers []string
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
// Each route declares a native huma typed Body, so huma parses + validates the
// JSON request directly (additionalProperties:false → 422 on unknown/malformed
// bodies). /token and /token/refresh are public (Security: none); /token/revoke
// is gated by RequireAuthHuma — the same identity logic as the legacy
// mw.RequireAuth wrapper. The mux is retained in the signature for plugins that
// still register raw net/http routes; bearer no longer uses it.
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

	// POST /token is a password login: it verifies email+password exactly
	// as the cookie POST /login does. It carried no per-IP throttle at
	// all, so an attacker spraying a couple of guesses each across many
	// accounts — which never trips per-account lockout — ran at line rate
	// on the route /login would have metered. It buckets on the SAME key
	// as /login so alternating the two cannot double that budget;
	// /token/mfa likewise shares the mfa_verify bucket with /mfa/verify.
	tokenRL := plugin.RateLimitFor(host, plugin.RateLimitLogin, 10, 60*time.Second)
	tokenMFARL := plugin.RateLimitFor(host, plugin.RateLimitMFAVerify, 10, 60*time.Second)

	p.registerToken(host, api, prefix, tokenRL)
	p.registerTokenMFA(host, api, prefix, tokenMFARL)
	p.registerRefresh(host, api, prefix)
	p.registerRevoke(host, api, mw, prefix)
}
