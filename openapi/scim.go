package openapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// ── SCIM 2.0 types ───────────────────────────────────────────────────────

type scimUserResponse struct {
	ID       string `json:"id"`
	UserName string `json:"userName"`
	Active   bool   `json:"active"`
}

type scimGroupResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type scimListResponse struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
}

type scimServiceProviderConfig struct {
	Schemas []string `json:"schemas"`
}

// addScim declares the SCIM 2.0 provisioning endpoints introduced in yauth (Rust) #95.
//
// All endpoints are mounted under /api/scim/v2/organizations/{org_id}
// and authenticated via a Bearer org-scoped API key.
//
//	POST/GET   /api/scim/v2/organizations/{org_id}/Users
//	GET/PUT/PATCH/DELETE /api/scim/v2/organizations/{org_id}/Users/{user_id}
//	POST/GET   /api/scim/v2/organizations/{org_id}/Groups
//	GET/PUT/PATCH/DELETE /api/scim/v2/organizations/{org_id}/Groups/{group_id}
//	GET        /api/scim/v2/organizations/{org_id}/ServiceProviderConfig
//	GET        /api/scim/v2/organizations/{org_id}/Schemas
//	GET        /api/scim/v2/organizations/{org_id}/ResourceTypes
func addScim(api *huma.OpenAPI) {
	orgParam := pathParam("org_id", "Organization id (UUID).")
	userParam := pathParam("user_id", "SCIM user id.")
	groupParam := pathParam("group_id", "SCIM group id.")

	// ── Users ───────────────────────────────────────────────────────────

	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/api/scim/v2/organizations/{org_id}/Users",
		Tags: []string{"organizations"}, OperationID: "scimCreateUser",
		Summary:    "SCIM: provision a user",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam},
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Created SCIM user.", scimUserResponse{}),
			"400": errorResponse("Invalid SCIM request."),
			"401": errorResponse("Not authenticated."),
			"409": errorResponse("User already exists."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/api/scim/v2/organizations/{org_id}/Users",
		Tags: []string{"organizations"}, OperationID: "scimListUsers",
		Summary:    "SCIM: list users",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("SCIM user list.", scimListResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/api/scim/v2/organizations/{org_id}/Users/{user_id}",
		Tags: []string{"organizations"}, OperationID: "scimGetUser",
		Summary:    "SCIM: get a user",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam, userParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("SCIM user.", scimUserResponse{}),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("User not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodPut, Path: "/api/scim/v2/organizations/{org_id}/Users/{user_id}",
		Tags: []string{"organizations"}, OperationID: "scimReplaceUser",
		Summary:    "SCIM: replace a user (full PUT)",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam, userParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated SCIM user.", scimUserResponse{}),
			"400": errorResponse("Invalid SCIM request."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("User not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/api/scim/v2/organizations/{org_id}/Users/{user_id}",
		Tags: []string{"organizations"}, OperationID: "scimPatchUser",
		Summary:    "SCIM: patch a user",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam, userParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Patched SCIM user.", scimUserResponse{}),
			"400": errorResponse("Invalid SCIM PatchOp."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("User not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/api/scim/v2/organizations/{org_id}/Users/{user_id}",
		Tags: []string{"organizations"}, OperationID: "scimDeleteUser",
		Summary:    "SCIM: deprovision a user",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam, userParam},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("User deprovisioned."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("User not found."),
		},
	})

	// ── Groups ──────────────────────────────────────────────────────────

	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/api/scim/v2/organizations/{org_id}/Groups",
		Tags: []string{"organizations"}, OperationID: "scimCreateGroup",
		Summary:    "SCIM: create a group",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam},
		Responses: map[string]*huma.Response{
			"201": jsonResponse("Created SCIM group.", scimGroupResponse{}),
			"400": errorResponse("Invalid SCIM request."),
			"401": errorResponse("Not authenticated."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/api/scim/v2/organizations/{org_id}/Groups",
		Tags: []string{"organizations"}, OperationID: "scimListGroups",
		Summary:    "SCIM: list groups",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("SCIM group list.", scimListResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/api/scim/v2/organizations/{org_id}/Groups/{group_id}",
		Tags: []string{"organizations"}, OperationID: "scimGetGroup",
		Summary:    "SCIM: get a group",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam, groupParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("SCIM group.", scimGroupResponse{}),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("Group not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodPut, Path: "/api/scim/v2/organizations/{org_id}/Groups/{group_id}",
		Tags: []string{"organizations"}, OperationID: "scimReplaceGroup",
		Summary:    "SCIM: replace a group (full PUT)",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam, groupParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated SCIM group.", scimGroupResponse{}),
			"400": errorResponse("Invalid SCIM request."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("Group not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/api/scim/v2/organizations/{org_id}/Groups/{group_id}",
		Tags: []string{"organizations"}, OperationID: "scimPatchGroup",
		Summary:    "SCIM: patch a group",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam, groupParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Patched SCIM group.", scimGroupResponse{}),
			"400": errorResponse("Invalid SCIM PatchOp."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("Group not found."),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/api/scim/v2/organizations/{org_id}/Groups/{group_id}",
		Tags: []string{"organizations"}, OperationID: "scimDeleteGroup",
		Summary:    "SCIM: delete a group",
		Security:   secAny(),
		Parameters: []*huma.Param{orgParam, groupParam},
		Responses: map[string]*huma.Response{
			"204": emptyResponse("Group deleted."),
			"401": errorResponse("Not authenticated."),
			"404": errorResponse("Group not found."),
		},
	})

	// ── Discovery ───────────────────────────────────────────────────────

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/api/scim/v2/organizations/{org_id}/ServiceProviderConfig",
		Tags: []string{"organizations"}, OperationID: "scimServiceProviderConfig",
		Summary:    "SCIM: ServiceProviderConfig discovery",
		Security:   secNone(),
		Parameters: []*huma.Param{orgParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("ServiceProviderConfig.", scimServiceProviderConfig{}),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/api/scim/v2/organizations/{org_id}/Schemas",
		Tags: []string{"organizations"}, OperationID: "scimSchemas",
		Summary:    "SCIM: Schemas discovery",
		Security:   secNone(),
		Parameters: []*huma.Param{orgParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("SCIM schemas.", scimListResponse{}),
		},
	})

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/api/scim/v2/organizations/{org_id}/ResourceTypes",
		Tags: []string{"organizations"}, OperationID: "scimResourceTypes",
		Summary:    "SCIM: ResourceTypes discovery",
		Security:   secNone(),
		Parameters: []*huma.Param{orgParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("SCIM resource types.", scimListResponse{}),
		},
	})
}
