package openapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// addOrganizations declares the routes mounted by
// plugins/organizations/plugin.go for the org primitive (yauth #87 port).
// Routes are emitted at their canonical unprefixed paths; embedders
// mount under whatever prefix they choose.
//
// Org-scoped RBAC handlers (POST /organizations/{id}/members/{user_id}/role,
// POST /organizations/{id}/transfer-ownership, GET
// /organizations/{id}/permissions) exist as code in plugins/organizations
// but are intentionally NOT advertised here while yauth (Rust)'s spec
// also omits them — the strict openapi-conformance gate treats Go-only
// routes as blocking, so the canonical OpenAPI surface stays in lockstep
// with Rust and the RBAC endpoints remain callable but undocumented.
func addOrganizations(api *huma.OpenAPI) {
	orgIDParam := pathParam("id", "Organization id (UUID).")

	// --- Org CRUD + listing ---
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/organizations",
		Tags: []string{"organizations"}, OperationID: "organizationsList",
		Summary:  "List organizations the caller is a member of",
		Security: secAny(),
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Caller's organizations.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: &huma.Schema{
						Type:  "array",
						Items: schemaRef(organizationJSON{}),
					}},
				},
			},
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/organizations",
		Tags: []string{"organizations"}, OperationID: "organizationsCreate",
		Summary:     "Create an organization; caller becomes owner+admin",
		Security:    secAny(),
		RequestBody: jsonRequestBody(createOrgRequest{}, "Org name, slug, and optional display name."),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Organization created.", organizationJSON{}),
			"400": errorResponse("Invalid name or slug."),
			"401": errorResponse("Not authenticated."),
			"409": errorResponse("Slug already in use."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/organizations/{id}",
		Tags: []string{"organizations"}, OperationID: "organizationsGet",
		Summary:    "Fetch a single organization (membership-gated)",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Organization.", organizationJSON{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not a member of this organization."),
			"404": errorResponse("Organization not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/organizations/{id}",
		Tags: []string{"organizations"}, OperationID: "organizationsUpdate",
		Summary:     "Update an organization (admin-gated)",
		Security:    secAny(),
		Parameters:  []*huma.Param{orgIDParam},
		RequestBody: jsonRequestBody(updateOrgRequest{}, "Fields to update; omit fields to leave unchanged."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated organization.", organizationJSON{}),
			"400": errorResponse("Invalid field value."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Organization not found."),
			"409": errorResponse("Slug already in use."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/organizations/{id}",
		Tags: []string{"organizations"}, OperationID: "organizationsDelete",
		Summary:    "Delete an organization and cascade members + invitations (admin-gated)",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Organization deleted."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Organization not found."),
		},
	})

	// --- Members ---
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/organizations/{id}/members",
		Tags: []string{"organizations"}, OperationID: "organizationsListMembers",
		Summary:    "List members of an organization (membership-gated)",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Members.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: &huma.Schema{
						Type:  "array",
						Items: schemaRef(membershipJSON{}),
					}},
				},
			},
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not a member of this organization."),
			"404": errorResponse("Organization not found."),
		},
	})

	// --- Invitations ---
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/organizations/{id}/invitations",
		Tags: []string{"organizations"}, OperationID: "organizationsCreateInvitation",
		Summary:     "Create an invitation for an email (admin-gated)",
		Security:    secAny(),
		Parameters:  []*huma.Param{orgIDParam},
		RequestBody: jsonRequestBody(createInvitationRequest{}, "Email + optional role (defaults to member)."),
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Invitation + one-time plaintext token.", createInvitationResponse{}),
			"400": errorResponse("Invalid email or role."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Organization not found."),
			"409": errorResponse("Active invitation already exists for that email."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/invitations/accept",
		Tags: []string{"organizations"}, OperationID: "organizationsAcceptInvitation",
		Summary:     "Accept an invitation by token (idempotent — second call yields 404)",
		Security:    secAny(),
		RequestBody: jsonRequestBody(acceptInvitationRequest{}, "Invitation token from the email."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Membership created.", membershipJSON{}),
			"400": errorResponse("Missing or malformed token."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("Token invalid, already consumed, or expired."),
			"409": errorResponse("Caller is already a member of the organization."),
		},
	})

}
