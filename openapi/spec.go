package openapi

import (
	"reflect"

	"github.com/danielgtaylor/huma/v2"
)

// Build returns the fully-populated OpenAPI 3.1 spec for every yauth-go
// route. The returned *huma.OpenAPI marshals to JSON via its
// MarshalJSON method (used by /openapi.json and the go:generate target).
func Build() *huma.OpenAPI {
	registry := huma.NewMapRegistry("#/components/schemas/", huma.DefaultSchemaNamer)
	declareSchemas(registry)

	api := &huma.OpenAPI{
		OpenAPI: "3.1.0",
		Info: &huma.Info{
			Title:       "yauth-go",
			Description: "OpenAPI 3.1 specification for the yauth-go authentication library. Routes are mounted by each plugin under whatever prefix the embedder chooses (commonly `/api/auth`).",
			Version:     "0.0.1",
			License:     &huma.License{Name: "MIT"},
		},
		Components: &huma.Components{
			Schemas: registry,
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
		Tags: []*huma.Tag{
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
		},
	}

	addEmailPassword(api)
	addBearer(api)
	addAPIKey(api)
	addMagicLink(api)
	addLockout(api)
	addStatus(api)
	addAdmin(api)
	addMFA(api)
	addPasskey(api)
	addOAuth(api)
	addWebhooks(api)
	addAsymJWT(api)
	addOIDC(api)
	addOAuth2Server(api)

	return api
}

// declareSchemas walks every request/response Go struct through the
// huma registry so they appear under #/components/schemas. Operations
// emitted later refer to them via $ref. Order does not matter.
func declareSchemas(r huma.Registry) {
	for _, t := range []reflect.Type{
		reflect.TypeOf(errorBody{}),
		reflect.TypeOf(errorPayload{}),
		reflect.TypeOf(userJSON{}),
		reflect.TypeOf(adminUserJSON{}),

		reflect.TypeOf(sessionUserJSON{}),
		reflect.TypeOf(emailPasswordRegisterRequest{}),
		reflect.TypeOf(emailPasswordRegisterResponse{}),
		reflect.TypeOf(emailPasswordLoginRequest{}),
		reflect.TypeOf(emailPasswordLoginResponse{}),
		reflect.TypeOf(emailPasswordLoginMfaResponse{}),
		reflect.TypeOf(emailPasswordSessionResponse{}),
		reflect.TypeOf(emailPasswordChangePasswordRequest{}),
		reflect.TypeOf(emailPasswordChangePasswordResponse{}),
		reflect.TypeOf(emailPasswordPatchMeRequest{}),
		reflect.TypeOf(emailPasswordPatchMeResponse{}),
		reflect.TypeOf(emailVerifyRequest{}),
		reflect.TypeOf(emailVerifyResponse{}),
		reflect.TypeOf(emailResendVerificationRequest{}),
		reflect.TypeOf(emailResendVerificationResponse{}),
		reflect.TypeOf(emailForgotPasswordRequest{}),
		reflect.TypeOf(emailForgotPasswordResponse{}),
		reflect.TypeOf(emailResetPasswordRequest{}),
		reflect.TypeOf(emailResetPasswordResponse{}),

		reflect.TypeOf(bearerTokenRequest{}),
		reflect.TypeOf(bearerTokenResponse{}),
		reflect.TypeOf(bearerRefreshRequest{}),
		reflect.TypeOf(bearerRevokeRequest{}),

		reflect.TypeOf(apiKeyJSON{}),
		reflect.TypeOf(apiKeyListResponse{}),
		reflect.TypeOf(apiKeyCreateRequest{}),
		reflect.TypeOf(apiKeyCreateResponse{}),

		reflect.TypeOf(magicLinkSendRequest{}),
		reflect.TypeOf(magicLinkSendResponse{}),
		reflect.TypeOf(magicLinkVerifyRequest{}),
		reflect.TypeOf(magicLinkVerifyResponse{}),

		reflect.TypeOf(lockoutUnlockRequest{}),
		reflect.TypeOf(lockoutUnlockResponse{}),
		reflect.TypeOf(lockoutUnlockReqRequest{}),
		reflect.TypeOf(lockoutUnlockReqResponse{}),
		reflect.TypeOf(lockoutLockedAccountJSON{}),
		reflect.TypeOf(lockoutStateResponse{}),

		reflect.TypeOf(statusResponse{}),
		reflect.TypeOf(configResponse{}),

		reflect.TypeOf(adminListUsersResponse{}),
		reflect.TypeOf(adminPatchUserRequest{}),
		reflect.TypeOf(adminBanRequest{}),
		reflect.TypeOf(adminImpersonateResponse{}),
		reflect.TypeOf(adminDeleteSessionsResponse{}),
		reflect.TypeOf(adminAuditEntryJSON{}),
		reflect.TypeOf(adminListAuditResponse{}),
		reflect.TypeOf(adminSessionJSON{}),
		reflect.TypeOf(adminListSessionsResponse{}),

		reflect.TypeOf(mfaSetupResponse{}),
		reflect.TypeOf(mfaConfirmRequest{}),
		reflect.TypeOf(mfaMessageResponse{}),
		reflect.TypeOf(mfaBackupCodesCountResponse{}),
		reflect.TypeOf(mfaRegenerateResponse{}),
		reflect.TypeOf(mfaVerifyRequest{}),
		reflect.TypeOf(mfaVerifyResponse{}),

		reflect.TypeOf(passkeyRegisterBeginResponse{}),
		reflect.TypeOf(passkeyRegisterFinishRequest{}),
		reflect.TypeOf(passkeyRegisterFinishResponse{}),
		reflect.TypeOf(passkeyLoginBeginRequest{}),
		reflect.TypeOf(passkeyLoginBeginResponse{}),
		reflect.TypeOf(passkeyLoginFinishRequest{}),
		reflect.TypeOf(passkeyLoginFinishResponse{}),
		reflect.TypeOf(passkeyJSON{}),
		reflect.TypeOf(passkeyListResponse{}),

		reflect.TypeOf(oauthCallbackResponse{}),
		reflect.TypeOf(oauthCallbackBody{}),
		reflect.TypeOf(oauthAccountJSON{}),
		reflect.TypeOf(oauthListAccountsResponse{}),
		reflect.TypeOf(oauthLinkResponse{}),

		reflect.TypeOf(webhookJSON{}),
		reflect.TypeOf(webhookCreateRequest{}),
		reflect.TypeOf(webhookUpdateRequest{}),
		reflect.TypeOf(webhookDeliveryJSON{}),
		reflect.TypeOf(webhookListResponse{}),
		reflect.TypeOf(webhookListDeliveriesResponse{}),
		reflect.TypeOf(webhookShowResponse{}),
		reflect.TypeOf(webhookTestResponse{}),

		reflect.TypeOf(jwksKey{}),
		reflect.TypeOf(jwksDocument{}),

		reflect.TypeOf(oidcDiscoveryDoc{}),
		reflect.TypeOf(oidcUserInfoResponse{}),

		reflect.TypeOf(oauth2RegisterRequest{}),
		reflect.TypeOf(oauth2RegisterResponse{}),
		reflect.TypeOf(oauth2ConsentClient{}),
		reflect.TypeOf(oauth2ConsentPayload{}),
		reflect.TypeOf(oauth2AuthorizeRedirect{}),
		reflect.TypeOf(oauth2ConsentRequest{}),
		reflect.TypeOf(oauth2TokenResponse{}),
		reflect.TypeOf(oauth2IntrospectResponse{}),
		reflect.TypeOf(oauth2ClientJSON{}),
		reflect.TypeOf(oauth2CreateClientRequest{}),
		reflect.TypeOf(oauth2CreateClientResponse{}),
		reflect.TypeOf(oauth2PatchClientRequest{}),
		reflect.TypeOf(oauth2BannedClientsResponse{}),
		reflect.TypeOf(oauth2DeviceAuthResponse{}),
		reflect.TypeOf(oauth2DeviceVerifyRequest{}),
		reflect.TypeOf(oauth2DeviceVerifyResponse{}),
	} {
		_ = r.Schema(t, true, t.Name())
	}
}

// --- helpers used by per-plugin operation builders --------------------

// schemaRef returns a Schema with $ref pointing at the registered
// schema for typ in the components/schemas registry. The name MUST
// match what huma's DefaultSchemaNamer produced when the schema was
// registered (initial-cap), so callers don't have to know that detail.
func schemaRef(typ any) *huma.Schema {
	t := reflect.TypeOf(typ)
	return &huma.Schema{Ref: "#/components/schemas/" + huma.DefaultSchemaNamer(t, t.Name())}
}

// jsonContent returns the application/json content map for either a
// request or response body, referring to typ.
func jsonContent(typ any) map[string]*huma.MediaType {
	return map[string]*huma.MediaType{
		"application/json": {Schema: schemaRef(typ)},
	}
}

// jsonRequestBody constructs a required JSON request body keyed off typ.
func jsonRequestBody(typ any, description string) *huma.RequestBody {
	return &huma.RequestBody{
		Description: description,
		Required:    true,
		Content:     jsonContent(typ),
	}
}

// jsonResponse constructs a 200/201/etc response with a single
// application/json body referencing typ.
func jsonResponse(description string, typ any) *huma.Response {
	return &huma.Response{
		Description: description,
		Content:     jsonContent(typ),
	}
}

// emptyResponse returns a description-only Response (used for 204).
func emptyResponse(description string) *huma.Response {
	return &huma.Response{Description: description}
}

// errorResponse returns a Response whose body is the canonical
// {"error": {...}} envelope.
func errorResponse(description string) *huma.Response {
	return &huma.Response{
		Description: description,
		Content:     jsonContent(errorBody{}),
	}
}

// pathParam declares a required string path parameter.
func pathParam(name, description string) *huma.Param {
	return &huma.Param{
		Name:        name,
		In:          "path",
		Description: description,
		Required:    true,
		Schema:      &huma.Schema{Type: "string"},
	}
}

// queryStringParam declares an optional string query parameter.
func queryStringParam(name, description string) *huma.Param {
	return &huma.Param{
		Name:        name,
		In:          "query",
		Description: description,
		Schema:      &huma.Schema{Type: "string"},
	}
}

// queryIntParam declares an optional integer query parameter.
func queryIntParam(name, description string) *huma.Param {
	return &huma.Param{
		Name:        name,
		In:          "query",
		Description: description,
		Schema:      &huma.Schema{Type: "integer"},
	}
}

// secNone explicitly clears top-level security on an unauthenticated
// operation. Returning an empty slice (not nil) ensures the spec emits
// `security: []` to override any document-level requirement.
func secNone() []map[string][]string { return []map[string][]string{} }

// secCookie marks an operation as requiring the session cookie.
func secCookie() []map[string][]string {
	return []map[string][]string{{"sessionCookie": {}}}
}

// secAny marks an operation as accepting any of: cookie, bearer JWT, or
// X-Api-Key. The middleware tries them in that order.
func secAny() []map[string][]string {
	return []map[string][]string{
		{"sessionCookie": {}},
		{"bearer": {}},
		{"apiKey": {}},
	}
}
