// gen_secrets_unconsumed_test.go — regression suite for "gen-secrets writes a
// secret that nothing in the product reads".
//
// `yauth gen-secrets` writes a .env with three values (gen_secrets.go):
// JWT_SECRET, MFA_ENCRYPTION_KEY and WEBHOOK_DEFAULT_SECRET. The first two are
// consumed — plugins.bearer.jwt_secret_env and plugins.mfa.encryption_key_env
// name them, and from_config.go resolves both. The third is not consumed by
// anything: the only config field that ever pointed at it,
// plugins.webhooks.default_secret_env, has been accepted-and-ignored for
// several releases (yauthcfg/config.go documents it as Deprecated, and
// Config.DeprecationWarnings tells operators to remove it), because webhook
// signing secrets are issued per-endpoint by POST /webhooks.
//
// A scaffold that mints a high-entropy value, calls it a secret, and wires it
// to nothing is a live liability rather than a harmless leftover: it gets
// committed, copied into a secret manager, rotated on a schedule and audited,
// all for a variable no code path reads — and, worse, it teaches the operator
// that yauth has a global webhook secret when the security property depends on
// each endpoint having its own.
//
// The assertion is on the FILE the command writes, which is the artifact the
// operator actually deals with.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenSecrets_EmitsNoUnconsumedSecret is the finding: the generated .env must
// not carry WEBHOOK_DEFAULT_SECRET, because no config field and no plugin reads
// it.
func TestGenSecrets_EmitsNoUnconsumedSecret(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, ".env")
	if _, _, err := runCmd(t, "gen-secrets", "-o", out); err != nil {
		t.Fatalf("gen-secrets: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "WEBHOOK_DEFAULT_SECRET") {
		t.Fatalf("gen-secrets writes WEBHOOK_DEFAULT_SECRET, which nothing consumes — "+
			"plugins.webhooks.default_secret_env is deprecated and ignored, and webhook "+
			"signing secrets are issued per endpoint. Generated file:\n%s", body)
	}
}

// TestGenSecrets_StillEmitsTheConsumedOnes is the paired positive control: the
// two values that ARE wired to config fields must keep being generated, with
// enough entropy to be usable. Dropping the dead one must not turn gen-secrets
// into a command that scaffolds nothing.
func TestGenSecrets_StillEmitsTheConsumedOnes(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, ".env")
	if _, _, err := runCmd(t, "gen-secrets", "-o", out); err != nil {
		t.Fatalf("gen-secrets: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			values[k] = v
		}
	}
	for _, key := range []string{"JWT_SECRET", "MFA_ENCRYPTION_KEY"} {
		v, ok := values[key]
		if !ok {
			t.Fatalf(".env missing %s; body:\n%s", key, body)
		}
		if len(v) < 32 {
			t.Fatalf("%s is only %d chars — too short to be the 256-bit value it claims to be", key, len(v))
		}
	}
}
