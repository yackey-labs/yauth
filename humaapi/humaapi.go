// Package humaapi constructs the huma.API that yauth-go plugins register their
// huma-native operations onto. Its auto-derived OpenAPI document (exposed via
// YAuth.OpenAPI()) is the single source of truth for the published spec — the
// committed openapi.json at the repo root is generated from it.
//
// The config is built bare on purpose — NOT via huma.DefaultConfig:
//
//   - No SchemaLinkTransformer: DefaultConfig injects a "$schema" field into
//     every JSON response body, which would change the bytes handlers emit and
//     break wire-compat with the handlers' hand-authored responses.
//   - No OpenAPIPath/DocsPath/SchemasPath: DefaultConfig auto-registers
//     /openapi.json, /docs, and /schemas/* onto the mux. We leave those empty so
//     huma serves no spec routes — yauth-go publishes the spec as a generated,
//     checked-in openapi.json rather than serving it live.
package humaapi

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// New builds the huma.API bound to mux. huma's global error constructor
// (huma.NewError) is left at its default, so huma's own built-in errors —
// request validation (422), content negotiation (406), and any 401/403/404/500
// returned via huma.Error*/huma.WriteErr — marshal as native RFC 9457
// problem+json ({type,title,status,detail}) with an application/problem+json
// content type. (yauth#129's shared TS client normalizes problem+json.)
//
// The OpenAPI metadata sets title "yauth-go", the three security schemes
// (sessionCookie / bearer / apiKey), and the tag set carried into the published
// openapi.json.
func New(mux humago.Mux) huma.API {
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
