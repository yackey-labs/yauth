package openapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
)

// TestBuildMarshal verifies the spec marshals to non-empty JSON and the
// resulting bytes are syntactically valid. Acts as a smoke test for the
// declarative wiring in spec.go / operations.go.
func TestBuildMarshal(t *testing.T) {
	body, err := json.Marshal(Build())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(body) < 4096 {
		t.Fatalf("spec is suspiciously small (%d bytes)", len(body))
	}
	var any map[string]any
	if err := json.Unmarshal(body, &any); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if any["openapi"] != "3.1.0" {
		t.Fatalf("unexpected openapi version: %v", any["openapi"])
	}
}

// TestEveryPluginHasOperation asserts at least one operation exists for
// every plugin's tag. New plugins must surface here so we notice if
// someone forgets to wire spec entries.
func TestEveryPluginHasOperation(t *testing.T) {
	want := []string{
		"email-password",
		"bearer",
		"api-key",
		"magic-link",
		"lockout",
		"status",
		"admin",
		"mfa",
		"passkey",
		"oauth",
		"webhooks",
		"asymmetric-jwt",
		"oidc",
		"oauth2-server",
	}

	api := Build()
	seen := map[string]bool{}
	for _, item := range api.Paths {
		for _, op := range []*huma.Operation{
			item.Get, item.Post, item.Put, item.Patch, item.Delete,
		} {
			if op == nil {
				continue
			}
			for _, tag := range op.Tags {
				seen[tag] = true
			}
		}
	}
	missing := []string{}
	for _, w := range want {
		if !seen[w] {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("missing operations for tags: %s", strings.Join(missing, ", "))
	}
}

// TestNoDuplicateOperations is a drift guard. net/http's ServeMux exposes no
// public API to enumerate the patterns the plugins register (true on Go 1.22+),
// so a direct mux-vs-spec route diff isn't possible from this package; the
// authoritative cross-implementation guard is scripts/openapi-conformance.py,
// run in CI against the Rust spec. What we CAN cheaply assert here is internal
// self-consistency of openapi.Build(): every operation must have a unique
// (method, path) and a unique operationId. A duplicate is the usual symptom of
// a copy-paste drift when someone adds a new route declaration, and it also
// catches a path silently shadowing another. Combined with the conformance
// gate and TestRequiredOperationsPresent below, this makes spec drift a build
// failure rather than a silent client breakage.
func TestNoDuplicateOperations(t *testing.T) {
	api := Build()
	type key struct{ method, path string }
	seenRoute := map[key]bool{}
	seenOpID := map[string]string{} // opID -> "METHOD path"
	for path, item := range api.Paths {
		for method, op := range map[string]*huma.Operation{
			"GET":    item.Get,
			"POST":   item.Post,
			"PUT":    item.Put,
			"PATCH":  item.Patch,
			"DELETE": item.Delete,
		} {
			if op == nil {
				continue
			}
			k := key{method, path}
			if seenRoute[k] {
				t.Errorf("duplicate operation for %s %s", method, path)
			}
			seenRoute[k] = true

			if op.OperationID == "" {
				t.Errorf("missing operationId for %s %s", method, path)
				continue
			}
			if prev, ok := seenOpID[op.OperationID]; ok {
				t.Errorf("duplicate operationId %q on %s %s (also on %s)",
					op.OperationID, method, path, prev)
			}
			seenOpID[op.OperationID] = method + " " + path
		}
	}
}

// TestRequiredOperationsPresent pins a representative subset of (method, path)
// pairs that the handlers serve but that historically drifted out of the spec
// (lifecycle, BCL/logout, org-list wrappers). If a future refactor drops one of
// these spec declarations, this test fails before the conformance gate even
// runs, giving a clearer signal.
func TestRequiredOperationsPresent(t *testing.T) {
	api := Build()

	has := func(method, path string) bool {
		item, ok := api.Paths[path]
		if !ok {
			return false
		}
		switch method {
		case "GET":
			return item.Get != nil
		case "POST":
			return item.Post != nil
		case "PUT":
			return item.Put != nil
		case "PATCH":
			return item.Patch != nil
		case "DELETE":
			return item.Delete != nil
		}
		return false
	}

	required := []struct{ method, path string }{
		{"POST", "/admin/users/{id}/suspend"},
		{"POST", "/admin/users/{id}/unsuspend"},
		{"POST", "/admin/users/{id}/schedule-start"},
		{"GET", "/organizations"},
		{"GET", "/organizations/{id}/members"},
		{"GET", "/organizations/{id}/domains"},
		{"GET", "/oauth2/clients/{id}"},
		{"PATCH", "/oauth2/clients/{id}"},
	}
	for _, r := range required {
		if !has(r.method, r.path) {
			t.Errorf("required operation %s %s missing from spec", r.method, r.path)
		}
	}
}

// TestSchemasRegistered asserts the components.schemas map has every
// declared type. Catches a typo in declareSchemas.
func TestSchemasRegistered(t *testing.T) {
	api := Build()
	if api.Components == nil || api.Components.Schemas == nil {
		t.Fatal("components.schemas missing")
	}
	for _, want := range []string{
		"ErrorBody",
		"UserJSON",
		"EmailPasswordRegisterRequest",
		"BearerTokenResponse",
		"WebhookJSON",
		"Oauth2TokenResponse",
		"JwksDocument",
	} {
		if api.Components.Schemas.SchemaFromRef("#/components/schemas/"+want) == nil {
			t.Errorf("schema %s not registered", want)
		}
	}
}
