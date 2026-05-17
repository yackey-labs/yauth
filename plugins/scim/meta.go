package scim

import (
	"net/http"
)

// meta.go — SCIM discovery endpoints (ServiceProviderConfig, Schemas,
// ResourceTypes). These tell an IdP what the server supports.
//
// In the spec these are unauthenticated (RFC 7644 §4) — some IdPs hit
// them before the admin has finished pasting the bearer key. yauth-go
// still requires authentication for parity with the Rust side and
// uniform logging; Okta, Entra, and OneLogin all retry after the admin
// completes the setup.

// serviceProviderConfig describes the server capabilities.
func serviceProviderConfig() map[string]any {
	bearerAuth := map[string]any{
		"name":             "OAuth Bearer Token",
		"description":      "Org-scoped API key (RFC 6750 §2.1)",
		"specUri":          "https://tools.ietf.org/html/rfc6750",
		"documentationUri": "https://github.com/yackey-labs/yauth-go/blob/main/docs/scim/README.md",
		"type":             "oauthbearertoken",
		"primary":          true,
	}
	return map[string]any{
		"schemas":          []string{ServiceProviderConfigSchema},
		"documentationUri": "https://github.com/yackey-labs/yauth-go/blob/main/docs/scim/README.md",
		"patch":            map[string]any{"supported": true},
		"bulk": map[string]any{
			"supported":      false,
			"maxOperations":  0,
			"maxPayloadSize": 0,
		},
		"filter": map[string]any{
			"supported":  true,
			"maxResults": 500,
		},
		"changePassword":        map[string]any{"supported": false},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{bearerAuth},
	}
}

func schemasResponse() []map[string]any {
	user := map[string]any{
		"id":          CoreUserSchema,
		"name":        "User",
		"description": "Core User schema (RFC 7643 §4.1)",
		"attributes": []map[string]any{
			attr("userName", "string", "server"),
			attr("displayName", "string", "none"),
			attr("externalId", "string", "none"),
			attr("active", "boolean", "none"),
			complexAttr("name", []string{"formatted", "familyName", "givenName"}),
			multiComplexAttr("emails", []string{"value", "type", "primary"}),
			multiComplexAttr("groups", []string{"value", "display"}),
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/" + CoreUserSchema,
		},
	}
	group := map[string]any{
		"id":          CoreGroupSchema,
		"name":        "Group",
		"description": "Core Group schema (RFC 7643 §4.2)",
		"attributes": []map[string]any{
			attr("displayName", "string", "none"),
			attr("externalId", "string", "none"),
			multiComplexAttr("members", []string{"value", "display"}),
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/" + CoreGroupSchema,
		},
	}
	return []map[string]any{user, group}
}

func resourceTypesResponse() []map[string]any {
	user := map[string]any{
		"schemas":     []string{ResourceTypeSchema},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "User Account",
		"schema":      CoreUserSchema,
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     "/ResourceTypes/User",
		},
	}
	group := map[string]any{
		"schemas":     []string{ResourceTypeSchema},
		"id":          "Group",
		"name":        "Group",
		"endpoint":    "/Groups",
		"description": "Group resource",
		"schema":      CoreGroupSchema,
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     "/ResourceTypes/Group",
		},
	}
	return []map[string]any{user, group}
}

func attr(name, t, mutability string) map[string]any {
	uniqueness := "none"
	if name == "userName" {
		uniqueness = "server"
	}
	return map[string]any{
		"name":        name,
		"type":        t,
		"multiValued": false,
		"required":    false,
		"caseExact":   false,
		"mutability":  mutability,
		"returned":    "default",
		"uniqueness":  uniqueness,
	}
}

func complexAttr(name string, sub []string) map[string]any {
	subAttrs := make([]map[string]any, 0, len(sub))
	for _, s := range sub {
		subAttrs = append(subAttrs, map[string]any{"name": s, "type": "string"})
	}
	return map[string]any{
		"name":          name,
		"type":          "complex",
		"multiValued":   false,
		"required":      false,
		"mutability":    "readWrite",
		"returned":      "default",
		"subAttributes": subAttrs,
	}
}

func multiComplexAttr(name string, sub []string) map[string]any {
	subAttrs := make([]map[string]any, 0, len(sub))
	for _, s := range sub {
		subAttrs = append(subAttrs, map[string]any{"name": s, "type": "string"})
	}
	return map[string]any{
		"name":          name,
		"type":          "complex",
		"multiValued":   true,
		"required":      false,
		"mutability":    "readWrite",
		"returned":      "default",
		"subAttributes": subAttrs,
	}
}

// Silence unused warning for http import — pulled in so handler files
// can use http.* types via this package without the linter ratcheting.
var _ = http.MethodGet
