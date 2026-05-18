package openapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// addActiveOrg declares the active-org switcher routes (yauth #89 port).
//
// Three routes hang off /sessions/active-org:
//
//	GET    — read the caller's current active org + their full membership
//	POST   — switch active org (request body: { organization_id })
//	DELETE — clear the active-org claim (back to single-tenant default)
//
// All three respond with ActiveOrgResponse. Cookie callers update the
// session row server-side; bearer callers receive a freshly-issued JWT
// in `bearer_access_token` so their next request carries the new `org`
// / `role` / `orgs` claims. The role for the active org is derived from
// the matching `orgs[].role` entry — there is no top-level `role` field.
//
// As of yauth (Rust) PR #100, the Rust spec exposes these routes; the
// strict openapi-conformance gate compares paths bidirectionally, so the
// three routes had to land in both specs simultaneously. yauth-go's
// runtime handlers ship in PR #32.
func addActiveOrg(api *huma.OpenAPI) {
	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/sessions/active-org",
		Tags: []string{"organizations"}, OperationID: "organizationsGetActiveOrg",
		Summary:  "Read the caller's current active organization",
		Security: secAny(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Active org + full membership list.", activeOrgResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/sessions/active-org",
		Tags: []string{"organizations"}, OperationID: "organizationsSetActiveOrg",
		Summary:     "Switch the caller's active organization",
		Security:    secAny(),
		RequestBody: jsonRequestBody(setActiveOrgRequest{}, "Target organization id (UUID)."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Active org updated.", activeOrgResponse{}),
			"400": errorResponse("Missing organization_id."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not a member of the target organization."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/sessions/active-org",
		Tags: []string{"organizations"}, OperationID: "organizationsClearActiveOrg",
		Summary:  "Clear the caller's active-org claim",
		Security: secAny(),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Active org cleared.", activeOrgResponse{}),
			"401": errorResponse("Not authenticated."),
		},
	})
}
