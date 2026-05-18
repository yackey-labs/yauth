package openapi

import (
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// ── SSO connection types ──────────────────────────────────────────────────

type ssoConnectionJSON struct {
	ID                     string    `json:"id"`
	OrganizationID         string    `json:"organization_id"`
	Kind                   string    `json:"kind"`
	Name                   string    `json:"name"`
	Status                 string    `json:"status"`
	JitProvisioningEnabled bool      `json:"jit_provisioning_enabled"`
	DefaultRoleOnJit       string    `json:"default_role_on_jit"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type ssoConnectionListResponse struct {
	Connections []ssoConnectionJSON `json:"connections"`
}

type createSsoConnectionRequest struct {
	Kind                   string `json:"kind"`
	Name                   string `json:"name"`
	Status                 string `json:"status,omitempty"`
	Config                 any    `json:"config"`
	JitProvisioningEnabled *bool  `json:"jit_provisioning_enabled,omitempty"`
	DefaultRoleOnJit       string `json:"default_role_on_jit,omitempty"`
}

type createSsoConnectionResponse struct {
	Connection ssoConnectionJSON `json:"connection"`
}

type updateSsoConnectionRequest struct {
	Name                   *string `json:"name,omitempty"`
	Status                 *string `json:"status,omitempty"`
	Config                 any     `json:"config,omitempty"`
	JitProvisioningEnabled *bool   `json:"jit_provisioning_enabled,omitempty"`
	DefaultRoleOnJit       *string `json:"default_role_on_jit,omitempty"`
}

type ssoTestResponse struct {
	Ok      bool   `json:"ok"`
	Message string `json:"message"`
}

// addSsoOidc declares the OIDC SSO routes introduced in yauth (Rust) #93
// (issue #93 — federated sign-in from external IdP).
//
// Admin CRUD (protected, org-admin gated):
//
//	GET  /organizations/{id}/sso/connections
//	POST /organizations/{id}/sso/connections
//	PATCH  /organizations/{id}/sso/connections/{cid}
//	DELETE /organizations/{id}/sso/connections/{cid}
//	POST   /organizations/{id}/sso/connections/{cid}/test
//
// Note: /sso/login and /sso/callback are app-level redirect handlers,
// not declared in the shared OpenAPI spec.
func addSsoOidc(api *huma.OpenAPI) {
	orgIDParam := pathParam("id", "Organization id (UUID).")
	cidParam := pathParam("cid", "SSO connection id (UUID).")

	// List SSO connections
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/organizations/{id}/sso/connections",
		Tags: []string{"organizations"}, OperationID: "organizationsListSsoConnections",
		Summary:    "List SSO connections for an organization",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("SSO connection list.", ssoConnectionListResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Organization not found."),
		},
	})

	// Create SSO connection
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/organizations/{id}/sso/connections",
		Tags: []string{"organizations"}, OperationID: "organizationsCreateSsoConnection",
		Summary:     "Create an SSO connection for an organization",
		Security:    secAny(),
		Parameters:  []*huma.Param{orgIDParam},
		RequestBody: jsonRequestBody(createSsoConnectionRequest{}, "SSO connection to create."),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Created SSO connection.", createSsoConnectionResponse{}),
			"400": errorResponse("Invalid connection configuration."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Organization not found."),
		},
	})

	// Update SSO connection
	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/organizations/{id}/sso/connections/{cid}",
		Tags: []string{"organizations"}, OperationID: "organizationsUpdateSsoConnection",
		Summary:     "Update an SSO connection",
		Security:    secAny(),
		Parameters:  []*huma.Param{orgIDParam, cidParam},
		RequestBody: jsonRequestBody(updateSsoConnectionRequest{}, "Fields to update; omit to leave unchanged."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated SSO connection.", createSsoConnectionResponse{}),
			"400": errorResponse("Invalid field value."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("SSO connection not found."),
		},
	})

	// Delete SSO connection
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/organizations/{id}/sso/connections/{cid}",
		Tags: []string{"organizations"}, OperationID: "organizationsDeleteSsoConnection",
		Summary:    "Delete an SSO connection",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam, cidParam},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Connection deleted."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("SSO connection not found."),
		},
	})

	// Test SSO connection
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/organizations/{id}/sso/connections/{cid}/test",
		Tags: []string{"organizations"}, OperationID: "organizationsTestSsoConnection",
		Summary:    "Test an SSO connection (validates discovery doc + client credentials)",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam, cidParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Test result.", ssoTestResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("SSO connection not found."),
		},
	})
}
