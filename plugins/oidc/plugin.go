// Package oidc implements a minimal OpenID Connect Provider surface
// that sits on top of yauth-go's authentication primitives.
//
// MVP scope (this revision):
//   - GET {prefix}/.well-known/openid-configuration — discovery doc.
//   - GET {prefix}/userinfo                          — Bearer-protected
//     UserInfo response.
//
// id_token issuance is intentionally NOT wired here. It belongs in the
// oauth2-server plugin (task #19) where the authorization-code →
// id_token mint happens. The discovery doc still advertises the alg(s)
// supported by the loaded JWTSigner so that relying parties can
// pre-validate tokens against the JWKS.
//
// Issuer is the only required configuration value. The plugin reads
// host.JWTSigner() and host.PluginNames() lazily inside its handlers so
// it does not constrain plugin registration order.
package oidc

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes the oidc plugin.
type Config struct {
	// Issuer is the OIDC "iss" value. It is also used as the host
	// portion of the absolute URLs in the discovery document. Required,
	// e.g., "http://localhost:3000".
	Issuer string
	// BasePath is the external URL prefix the YAuth router is mounted
	// under (e.g., "/api/auth"). It is concatenated with Issuer when
	// building the absolute URLs returned in the discovery doc. Empty
	// means the router is mounted at the root.
	BasePath string

	// IDTokenTTL is the lifetime stamped onto id_tokens minted in the
	// authorization-code → id_token flow. Defaults to 1h when zero.
	// The mint itself happens in oauth2-server today; this config is
	// surfaced here so the discovery doc and a future revision of
	// oauth2-server can both read it from one place.
	IDTokenTTL time.Duration

	// ClaimsSupported populates the discovery doc "claims_supported"
	// array. Defaults to the OIDC core baseline (sub, email,
	// email_verified, name, aud, exp, iat, iss).
	ClaimsSupported []string
}

// defaultClaimsSupported is the baseline list advertised when
// Config.ClaimsSupported is nil. It mirrors the OIDC Core 1.0 standard
// claims yauth's UserInfo response actually populates.
var defaultClaimsSupported = []string{
	"sub", "email", "email_verified", "name", "aud", "exp", "iat", "iss",
}

// claimsSupported returns the configured claim list, falling back to
// defaultClaimsSupported when nil.
func (c *Config) claimsSupported() []string {
	if len(c.ClaimsSupported) == 0 {
		return defaultClaimsSupported
	}
	return c.ClaimsSupported
}

// EffectiveIDTokenTTL returns the configured id_token TTL, defaulting
// to 1h when zero. Exported so a future oauth2-server revision can read
// it without reimplementing the default rule.
func (c *Config) EffectiveIDTokenTTL() time.Duration {
	if c.IDTokenTTL <= 0 {
		return time.Hour
	}
	return c.IDTokenTTL
}

// oidcPlugin is the unexported plugin.Plugin implementation.
type oidcPlugin struct {
	cfg Config
}

// New constructs the oidc plugin.
func New(cfg Config) plugin.Plugin {
	return &oidcPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *oidcPlugin) Name() string { return "oidc" }

// Routes implements plugin.Plugin. Both routes are huma-native typed
// operations registered on the shared huma.API:
//
//	GET {prefix}/.well-known/openid-configuration   public discovery doc.
//	GET {prefix}/userinfo                           RequireAuth-gated UserInfo.
//
// The mux is retained in the signature for plugins that still register raw
// net/http routes; oidc no longer uses it. Neither route needs StashHTTPHuma:
// discovery ignores the request entirely, and userinfo recovers the resolved
// AuthUser from the operation context (injected by RequireAuthHuma) — no raw
// *http.Request/ResponseWriter access is required.
func (p *oidcPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	// Discovery is unauthenticated (Security: none), mirroring the public
	// net/http route it replaces.
	huma.Register(api, huma.Operation{
		OperationID: "oidc-discovery",
		Method:      http.MethodGet,
		Path:        prefix + "/.well-known/openid-configuration",
		Summary:     "OpenID Provider discovery document",
		Description: "OIDC Discovery 1.0 §3 provider metadata. Unauthenticated.",
		Tags:        []string{"oidc"},
		Security:    []map[string][]string{}, // explicitly public
	}, func(_ context.Context, _ *discoveryInput) (*discoveryOutput, error) {
		return p.discovery(host), nil
	})

	// UserInfo is auth-gated: RequireAuthHuma resolves cookie-or-bearer
	// identity (the same logic as the legacy mw.RequireAuth wrapper) and
	// injects the AuthUser onto the operation context.
	huma.Register(api, huma.Operation{
		OperationID: "oidc-userinfo",
		Method:      http.MethodGet,
		Path:        prefix + "/userinfo",
		Summary:     "OIDC UserInfo",
		Description: "OIDC Core 1.0 §5.3 standard claims for the authenticated caller.",
		Tags:        []string{"oidc"},
		Security: []map[string][]string{
			{"sessionCookie": {}},
			{"bearer": {}},
			{"apiKey": {}},
		},
		Middlewares: huma.Middlewares{middleware.RequireAuthHuma(api, mw)},
	}, func(ctx context.Context, _ *userInfoInput) (*userInfoOutput, error) {
		return p.userInfo(ctx, host)
	})
}
