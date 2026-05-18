package openapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// addSaml declares the SAML 2.0 Service Provider routes introduced in yauth (Rust) #94.
//
// SP endpoints (public — processed before the auth middleware):
//
//	GET  /sso/saml/login               — initiate SP-initiated SSO (redirect binding)
//	POST /sso/saml/acs                 — Assertion Consumer Service (receive IdP response)
//	GET  /sso/saml/metadata/{cid}      — SP metadata XML for IdP registration
//	GET  /sso/saml/logout              — SP-initiated SLO redirect
//	POST /sso/saml/slo                 — receive IdP-initiated SLO
//
// Admin CRUD for SAML connections is shared with OIDC via addSsoOidc
// (/organizations/{id}/sso/connections).
func addSaml(api *huma.OpenAPI) {
	cidParam := pathParam("cid", "SSO connection id (UUID).")

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/sso/saml/login",
		Tags: []string{"organizations"}, OperationID: "samlLogin",
		Summary:  "Initiate SP-initiated SAML SSO (redirect binding)",
		Security: secNone(),
		Parameters: []*huma.Param{
			queryStringParam("connection_id", "SSO connection UUID to authenticate against."),
			queryStringParam("next", "Post-login redirect URL."),
		},
		Responses: map[string]*huma.Response{
			"302": emptyResponse("Redirect to IdP SSO URL."),
			"400": errorResponse("Missing or invalid connection_id."),
			"404": errorResponse("Connection not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/sso/saml/acs",
		Tags: []string{"organizations"}, OperationID: "samlAcs",
		Summary:  "SAML Assertion Consumer Service — receive IdP response",
		Security: secNone(),
		Responses: map[string]*huma.Response{
			"302": emptyResponse("Redirect to application after successful assertion."),
			"400": errorResponse("Invalid or expired SAMLResponse."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/sso/saml/metadata/{cid}",
		Tags: []string{"organizations"}, OperationID: "samlMetadata",
		Summary:    "SP metadata XML for IdP registration",
		Security:   secNone(),
		Parameters: []*huma.Param{cidParam},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "SAML metadata XML.",
				Content: map[string]*huma.MediaType{
					"application/xml": {},
				},
			},
			"404": errorResponse("Connection not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/sso/saml/logout",
		Tags: []string{"organizations"}, OperationID: "samlLogout",
		Summary:  "SP-initiated SAML Single Logout redirect",
		Security: secAny(),
		Responses: map[string]*huma.Response{
			"302": emptyResponse("Redirect to IdP SLO endpoint."),
			"400": errorResponse("No active SAML session."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/sso/saml/slo",
		Tags: []string{"organizations"}, OperationID: "samlSlo",
		Summary:  "Receive IdP-initiated SAML Single Logout",
		Security: secNone(),
		Responses: map[string]*huma.Response{
			"302": emptyResponse("SLO complete, redirect to login."),
			"400": errorResponse("Invalid LogoutRequest."),
		},
	})
}
