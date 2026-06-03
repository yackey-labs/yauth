// Package humaapi constructs the huma.API that yauth-go plugins register
// huma-native operations onto. During the net/http → huma migration the
// published OpenAPI spec is still produced by the openapi/ package; this API
// exists so migrated routes can use huma.Register (typed handlers, derived
// schemas) while the legacy spec stays authoritative. Once every route is
// migrated this API becomes the spec source and openapi/ is retired.
//
// The config is built bare on purpose — NOT via huma.DefaultConfig:
//
//   - No SchemaLinkTransformer: DefaultConfig injects a "$schema" field into
//     every JSON response body, which would change the bytes migrated
//     handlers emit and break wire-compat with the legacy handlers.
//   - No OpenAPIPath/DocsPath/SchemasPath: DefaultConfig auto-registers
//     /openapi.json, /docs, and /schemas/* onto the mux. We leave those empty
//     so huma serves no spec routes — openapi/ owns /openapi.json this phase.
package humaapi

import (
	"sync"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/yackey-labs/yauth-go/humaerr"
)

// overrideOnce guards the single process-global write of huma.NewError. It
// is installed the first time New runs so parallel test builds don't race on
// the package-level variable.
var overrideOnce sync.Once

// New builds the huma.API bound to mux. It also installs humaerr.Override as
// huma's global error constructor (once), so huma's own built-in errors
// marshal to yauth-go's {"error":{code,message}} envelope.
//
// The OpenAPI metadata mirrors openapi/spec.go: title "yauth-go", the three
// security schemes (sessionCookie / bearer / apiKey), and the same tag set,
// so that if/when this API replaces the legacy spec the document is
// consistent.
func New(mux humago.Mux) huma.API {
	overrideOnce.Do(func() {
		huma.NewError = humaerr.Override
	})

	config := huma.Config{
		OpenAPI: &huma.OpenAPI{
			OpenAPI: "3.1.0",
			Info: &huma.Info{
				Title:   "yauth-go",
				Version: "0.0.1",
				License: &huma.License{Name: "MIT"},
			},
			Components: &huma.Components{
				SecuritySchemes: map[string]*huma.SecurityScheme{
					"sessionCookie": {
						Type: "apiKey",
						In:   "cookie",
						Name: "yauth_session",
					},
					"bearer": {
						Type:         "http",
						Scheme:       "bearer",
						BearerFormat: "JWT",
					},
					"apiKey": {
						Type: "apiKey",
						In:   "header",
						Name: "X-Api-Key",
					},
				},
			},
			Tags: tags(),
		},
		// Provide JSON marshaling but no transformers (no $schema field) and
		// no built-in spec/docs routes.
		Formats: huma.DefaultFormats,
	}

	return humago.NewWithPrefix(mux, "", config)
}

// tags mirrors the Tags slice in openapi/spec.go so the two documents agree.
func tags() []*huma.Tag {
	return []*huma.Tag{
		{Name: "email-password", Description: "Username/password sessions."},
		{Name: "bearer", Description: "JWT access + refresh tokens with family rotation."},
		{Name: "api-key", Description: "Long-lived prefix+secret API keys."},
		{Name: "magic-link", Description: "Passwordless email-link login."},
		{Name: "lockout", Description: "Account lockout-on-repeated-failure."},
		{Name: "status", Description: "Diagnostics — list registered plugins."},
		{Name: "admin", Description: "Admin user management + audit."},
		{Name: "mfa", Description: "TOTP + backup codes."},
		{Name: "passkey", Description: "WebAuthn / passkey credentials."},
		{Name: "oauth", Description: "OAuth client (Google / GitHub / generic OIDC)."},
		{Name: "webhooks", Description: "Outbound HMAC-signed event delivery."},
		{Name: "asymmetric-jwt", Description: "RS256 / ES256 JWKS publication."},
		{Name: "oidc", Description: "OpenID Connect discovery + UserInfo."},
		{Name: "oauth2-server", Description: "RFC 6749 / 7636 / 7009 / 7662 / 8628 authorization server."},
		{Name: "organizations", Description: "Multi-tenancy primitive — org CRUD, membership, invitations, and RBAC."},
		{Name: "audit-export", Description: "Audit log SIEM/syslog export destinations and replay."},
	}
}
