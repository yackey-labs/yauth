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
