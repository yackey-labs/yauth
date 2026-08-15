// from_config_webhook_key_test.go — regression suite for "the declarative path
// gives webhooks no key of its own, so rotating JWT_SECRET bricks every stored
// webhook secret".
//
// webhook signing secrets are stored encrypted under
// deriveWebhookKey(Config.EncryptionKey) and, when that is empty,
// deriveWebhookKey(host.JWTSecret()) — see plugins/webhooks/plugin.go
// encryptionKey(). Config.EncryptionKey is reachable from Go
// (webhooks.New(webhooks.Config{EncryptionKey: ...})), but NOT from a
// yauth.yaml: yauthcfg.WebhooksPluginConfig has no encryption_key_env, and
// from_config.go's `if p.Webhooks.Enabled` block sets only MaxAttempts and
// AllowPrivateDestinations. Every plugin that seals data at rest has such a
// knob — plugins.mfa.encryption_key_env, plugins.oauth.encryption_key_env,
// plugins.sso_oidc.encryption_key_env — and webhooks is the one that does not.
//
// Two consequences follow for anybody running yauth from config, which is the
// documented way to run it:
//
//   - The webhook secrets are chained to the bearer plugin's JWT secret. Rotating
//     JWT_SECRET is a routine, expected operation (it invalidates tokens, which is
//     the point) and it silently makes every yauth_webhooks.secret row
//     undecryptable. The receivers keep verifying signatures that will never
//     arrive again, and nothing says why.
//   - A deployment that does not want bearer at all cannot store a webhook secret
//     ever: host.JWTSecret() is nil, encryptionKey() returns nil, and the plugin
//     logs "no encryption key configured" at boot and refuses every POST/PATCH
//     that carries a secret (see plugins/webhooks/secret_at_rest_test.go). From
//     config there is no way out of that; from Go there is.
//
// The cases below are written so they compile against the schema as it stands
// today: the field is looked up by name with reflect, so the failure is "the
// config type has no EncryptionKeyEnv field" rather than a build error, and the
// same file goes green once the field exists and is wired.
package yauth_test

import (
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// noKeyLog is the boot-time error plugins/webhooks emits when it has no key
// material at all. Its presence means "this deployment cannot store a webhook
// signing secret".
const noKeyLog = "no encryption key configured"

// setWebhookKeyEnv sets plugins.webhooks.encryption_key_env by name. The field
// does not exist yet, so this is where the missing knob is reported.
func setWebhookKeyEnv(t *testing.T, c *yauthcfg.Config, envName string) {
	t.Helper()
	f := reflect.ValueOf(&c.Plugins.Webhooks).Elem().FieldByName("EncryptionKeyEnv")
	if !f.IsValid() {
		t.Fatalf("yauthcfg.WebhooksPluginConfig has no EncryptionKeyEnv field: a declarative " +
			"deployment cannot give webhooks a key of its own, so its stored signing secrets " +
			"are chained to JWT_SECRET (or, without bearer, cannot be stored at all)")
	}
	if f.Kind() != reflect.String {
		t.Fatalf("EncryptionKeyEnv should be a string env-var name (the *_env convention), got %s", f.Kind())
	}
	f.SetString(envName)
}

// bootLogs builds the config through the real NewFromConfig entry point over an
// in-memory repo and returns everything the plugins logged at startup.
func bootLogs(t *testing.T, c *yauthcfg.Config) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := yauth.NewFromConfig(context.Background(), c,
		yauth.WithRepo(memrepo.New()),
		yauth.WithConfigLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	); err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	return buf.String()
}

func webhookConfig(t *testing.T) *yauthcfg.Config {
	t.Helper()
	c := yauthcfg.Default()
	c.Database.Driver = "memory"
	c.Database.DSN = ""
	c.Plugins.EmailPassword.Enabled = true
	c.Plugins.Webhooks.Enabled = true
	return c
}

// TestWebhooksEncryptionKeyEnv_AcceptedFromYAML is the schema half. The loader
// runs with KnownFields(true), so a yauth.yaml that tries to give webhooks its
// own key is not merely ignored — it is refused outright, and the operator has
// nowhere to put the value.
func TestWebhooksEncryptionKeyEnv_AcceptedFromYAML(t *testing.T) {
	const doc = `
database:
  driver: memory
plugins:
  email_password:
    enabled: true
  bearer:
    enabled: true
    jwt_secret_env: YA_JWT_SECRET
  webhooks:
    enabled: true
    encryption_key_env: YA_WEBHOOK_KEY
`
	c, err := yauthcfg.Decode([]byte(doc), yauthcfg.FormatYAML)
	if err != nil {
		t.Fatalf("a config giving webhooks its own key env is refused by the loader: %v", err)
	}
	f := reflect.ValueOf(c.Plugins.Webhooks).FieldByName("EncryptionKeyEnv")
	if !f.IsValid() {
		t.Fatalf("yauthcfg.WebhooksPluginConfig has no EncryptionKeyEnv field")
	}
	if got := f.String(); got != "YA_WEBHOOK_KEY" {
		t.Fatalf("encryption_key_env decoded to %q, want %q", got, "YA_WEBHOOK_KEY")
	}
}

// TestWebhooksEncryptionKeyEnv_WiresWithoutBearer is the wiring half: the value
// has to reach webhooks.Config.EncryptionKey, not just land in a struct. The
// observable is the plugin's own boot-time verdict on its key material — with a
// dedicated key present it must NOT announce that secrets cannot be stored.
func TestWebhooksEncryptionKeyEnv_WiresWithoutBearer(t *testing.T) {
	t.Setenv("YA_WEBHOOK_KEY", "a-dedicated-webhook-encryption-key-32b")

	c := webhookConfig(t) // deliberately no bearer plugin: no JWT secret exists
	setWebhookKeyEnv(t, c, "YA_WEBHOOK_KEY")

	if logs := bootLogs(t, c); strings.Contains(logs, noKeyLog) {
		t.Fatalf("webhooks reports no key material despite plugins.webhooks.encryption_key_env "+
			"being set — the value never reached webhooks.Config.EncryptionKey:\n%s", logs)
	}
}

// TestWebhooksNoKeyMaterial_StillLoudAtBoot is the paired control for the case
// above. Wiring a dedicated key must not be achieved by making the plugin
// quietly accept having none: a deployment with neither bearer nor a webhook key
// still has to say so at startup, because every secret-bearing write will fail.
func TestWebhooksNoKeyMaterial_StillLoudAtBoot(t *testing.T) {
	c := webhookConfig(t)
	if logs := bootLogs(t, c); !strings.Contains(logs, noKeyLog) {
		t.Fatalf("webhooks with no key material at all should log %q at boot, got:\n%s", noKeyLog, logs)
	}
}

// TestWebhooksJWTSecretFallback_StillWorks is the no-regression control for the
// historical key source: a deployment that configures bearer and no webhook key
// keeps deriving from the JWT secret exactly as before.
func TestWebhooksJWTSecretFallback_StillWorks(t *testing.T) {
	t.Setenv("YA_JWT_SECRET", "test-hs256-secret-that-is-long-enough-32+")

	c := webhookConfig(t)
	c.Plugins.Bearer.Enabled = true
	c.Plugins.Bearer.JWTSecretEnv = "YA_JWT_SECRET"

	if logs := bootLogs(t, c); strings.Contains(logs, noKeyLog) {
		t.Fatalf("webhooks should still fall back to the bearer JWT secret:\n%s", logs)
	}
}
