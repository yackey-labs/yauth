package openapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// addDomains declares the verified-domains + JIT-membership routes
// (yauth (Rust) #101 port).
//
// Five operations hang off /organizations/{id}/domains:
//
//	GET    /organizations/{id}/domains            — list claimed domains
//	POST   /organizations/{id}/domains            — claim a new domain
//	                                                (returns one-time
//	                                                verification token)
//	PATCH  /organizations/{id}/domains/{did}      — update auto-join flags
//	DELETE /organizations/{id}/domains/{did}      — un-claim
//	POST   /organizations/{id}/domains/{did}/verify
//	                                              — run DNS/.well-known
//	                                                check and flip status
//
// Runtime handlers ship in yauth-go #18 (verified-domains + JIT
// membership). This file is the spec-side companion so the strict
// openapi-conformance gate (which compares paths + top-level field
// sets bidirectionally) accepts yauth main once #101 lands.
func addDomains(api *huma.OpenAPI) {
	orgIDParam := pathParam("id", "Organization id (UUID).")
	domainIDParam := pathParam("did", "Domain claim id (UUID).")

	api.AddOperation(&huma.Operation{
		Method: http.MethodGet, Path: "/organizations/{id}/domains",
		Tags: []string{"organizations"}, OperationID: "organizationsListDomains",
		Summary:    "List domains claimed by this organization",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Domain claims for this org.", domainListResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not a member of this organization."),
			"404": errorResponse("Organization not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/organizations/{id}/domains",
		Tags: []string{"organizations"}, OperationID: "organizationsCreateDomain",
		Summary:     "Claim a domain for this organization (admin-gated)",
		Security:    secAny(),
		Parameters:  []*huma.Param{orgIDParam},
		RequestBody: jsonRequestBody(createDomainRequest{}, "Domain + initial auto-join policy."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Domain claimed; verification token returned once.", createDomainResponse{}),
			"400": errorResponse("Invalid domain."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Organization not found."),
			"409": errorResponse("Domain already claimed."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPatch, Path: "/organizations/{id}/domains/{did}",
		Tags: []string{"organizations"}, OperationID: "organizationsUpdateDomain",
		Summary:     "Update auto-join policy on a claimed domain (admin-gated)",
		Security:    secAny(),
		Parameters:  []*huma.Param{orgIDParam, domainIDParam},
		RequestBody: jsonRequestBody(updateDomainRequest{}, "Fields to update; omit to leave unchanged."),
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Updated domain claim.", domainResponse{}),
			"400": errorResponse("Invalid field value."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Domain claim not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodDelete, Path: "/organizations/{id}/domains/{did}",
		Tags: []string{"organizations"}, OperationID: "organizationsDeleteDomain",
		Summary:    "Un-claim a domain (admin-gated)",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam, domainIDParam},
		Responses: map[string]*huma.Response{
			"200": emptyResponse("Domain claim removed."),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Domain claim not found."),
		},
	})
	api.AddOperation(&huma.Operation{
		Method: http.MethodPost, Path: "/organizations/{id}/domains/{did}/verify",
		Tags: []string{"organizations"}, OperationID: "organizationsVerifyDomain",
		Summary:    "Run DNS / .well-known verification on a claimed domain",
		Security:   secAny(),
		Parameters: []*huma.Param{orgIDParam, domainIDParam},
		Responses: map[string]*huma.Response{
			"200": jsonResponse("Verification result.", verifyDomainResponse{}),
			"401": errorResponse("Not authenticated."),
			"403": errorResponse("Caller is not an admin of this organization."),
			"404": errorResponse("Domain claim not found."),
		},
	})
}
