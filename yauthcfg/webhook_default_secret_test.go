// webhook_default_secret_test.go — regression suite for "the schema advertises
// a global webhook secret that does nothing".
//
// plugins.webhooks.default_secret_env is documented in config.go as accepted
// for backward compatibility and IGNORED: webhook signing secrets are issued
// per endpoint by POST /webhooks and sealed at rest, so there is no global
// secret to name. Until this commit `yauth gen-secrets` nonetheless minted a
// WEBHOOK_DEFAULT_SECRET for it, so operators kept populating the field and
// kept believing their webhooks were signed with the value they had set — a
// knob that reads as security configuration, gets committed, stored in a
// secret manager, rotated on a schedule and audited, and is wired to nothing.
// gen-secrets no longer emits it (cmd/yauth/gen_secrets.go), which is the half
// of the problem that actually misled anyone.
//
// The FIELD itself stays, deliberately, and these cases pin that decision so a
// later cleanup does not quietly reverse it. Deleting it would buy nothing —
// it changes no key, weakens no crypto and misroutes no secret — while costing
// two real breakages: yauthcfg is a public package, so a Go caller setting
// Plugins.Webhooks.DefaultSecretEnv would stop compiling; and because the
// loader runs with KnownFields(true) (load.go), a yauth.yaml that still
// carries `default_secret_env` would go from an advisory the operator can act
// on at their leisure to a hard boot failure reading `field default_secret_env
// not found`. That is a strictly worse failure mode for a field the library
// documented as accepted, and it would single this field out from the other
// two deprecations (oauth2_server.require_pkce, api_key.header_name) that are
// kept on exactly the same accept-and-warn terms.
//
// So what these cases assert is the property that matters rather than the
// deletion: such a config still LOADS, the operator is still TOLD to remove
// it, and its value cannot influence the key webhooks ends up sealing secrets
// with — that key now comes from plugins.webhooks.encryption_key_env, or from
// the JWT-secret fallback.
package yauthcfg

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestWebhooksDefaultSecretEnv_StillLoadsAndWarns is the finding as it stands
// after the fix: an existing yauth.yaml that sets the dead field must keep
// booting, and must keep being told to drop it.
func TestWebhooksDefaultSecretEnv_StillLoadsAndWarns(t *testing.T) {
	const doc = `
database:
  driver: memory
plugins:
  webhooks:
    enabled: true
    default_secret_env: WEBHOOK_DEFAULT_SECRET
`
	c, err := Decode([]byte(doc), FormatYAML)
	if err != nil {
		t.Fatalf("a config still carrying the deprecated default_secret_env must load, not "+
			"hard-fail under KnownFields(true): %v", err)
	}
	if got := c.Plugins.Webhooks.DefaultSecretEnv; got != "WEBHOOK_DEFAULT_SECRET" {
		t.Fatalf("default_secret_env decoded to %q, want %q", got, "WEBHOOK_DEFAULT_SECRET")
	}

	var found string
	for _, w := range c.DeprecationWarnings() {
		if strings.Contains(w, "default_secret_env") {
			found = w
		}
	}
	if found == "" {
		t.Fatalf("DeprecationWarnings() no longer names plugins.webhooks.default_secret_env, so "+
			"`yauth check`, `yauth status` and NewFromConfig stop telling the operator to remove "+
			"a field that does nothing. Got: %v", c.DeprecationWarnings())
	}
	if !strings.Contains(found, "ignored") {
		t.Fatalf("the advisory should say the field is ignored, got %q", found)
	}
}

// TestWebhooksDefaultSecretEnv_UnreadByTheWiring is the substance of the
// finding: the field must remain inert. If from_config.go ever started reading
// it, the value would become a second, undocumented source of key material
// alongside plugins.webhooks.encryption_key_env, and an operator rotating one
// while the other was live would silently orphan every stored secret.
func TestWebhooksDefaultSecretEnv_UnreadByTheWiring(t *testing.T) {
	src, err := os.ReadFile("../from_config.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "DefaultSecretEnv") {
		t.Fatalf("from_config.go now reads Webhooks.DefaultSecretEnv — the field is documented " +
			"as accepted-and-ignored and must stay inert; the webhook key comes from " +
			"plugins.webhooks.encryption_key_env or the JWT-secret fallback")
	}
	if !strings.Contains(string(src), "Webhooks.EncryptionKeyEnv") {
		t.Fatalf("from_config.go does not wire Webhooks.EncryptionKeyEnv — the declarative path " +
			"has no way to give webhooks a key of its own")
	}
}

// TestWebhooksConfig_KeepsItsLiveKnobs is the paired positive control: pinning
// the deprecated field in place must not come at the cost of the settings that
// change real behaviour (delivery retries, whether the server will dial a
// private-network receiver, and the at-rest key).
func TestWebhooksConfig_KeepsItsLiveKnobs(t *testing.T) {
	ty := reflect.TypeOf(WebhooksPluginConfig{})
	for name, kind := range map[string]reflect.Kind{
		"Enabled":                  reflect.Bool,
		"MaxAttempts":              reflect.Int,
		"AllowPrivateDestinations": reflect.Bool,
		"EncryptionKeyEnv":         reflect.String,
	} {
		f, ok := ty.FieldByName(name)
		if !ok {
			t.Fatalf("WebhooksPluginConfig lost its %s field", name)
		}
		if f.Type.Kind() != kind {
			t.Fatalf("WebhooksPluginConfig.%s is %s, want %s", name, f.Type.Kind(), kind)
		}
	}
}
