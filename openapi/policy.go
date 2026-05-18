package openapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// addPolicy declares the per-org auth policy routes (yauth (Rust) #103
// port — issue #92).
//
//	GET   /organizations/{id}/policy — read effective policy
//	PATCH /organizations/{id}/policy — update policy (admin-gated)
//
// Runtime handlers ship in yauth-go #22 (per-org auth policy). This
// file is the spec-side companion so the strict openapi-conformance
// gate accepts yauth main once #103 lands.
func addPolicy(api *huma.OpenAPI) {
	orgIDParam := pathParam("id", "Organization id (UUID).")

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/organizations/{id}/policy",
		Tags: []string{"organizations"}, OperationID: "organizationsGetPolicy",
		Summary:    "Read the effective auth policy for this organization",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Effective policy.", policyResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not a member of this organization."),
			"404": errorResponse("Organization not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/organizations/{id}/policy",
		Tags: []string{"organizations"}, OperationID: "organizationsUpdatePolicy",
		Summary:     "Update the auth policy for this organization (admin-gated)",
		Security:    secAny(),
		Parameters:  []*huma.Param{orgIDParam},
		RequestBody: jsonRequestBody(updatePolicyRequest{}, "Fields to update; omit to leave unchanged."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated policy.", policyResponse{}),
			"400": errorResponse("Invalid field value."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Organization not found."),
		},
	})
}
