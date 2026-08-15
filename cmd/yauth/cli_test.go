package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runCmd executes the root command with args, isolating stdout/stderr
// so tests can assert on them. Returns (stdout, stderr, error).
func runCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	setOutput(root, &out, &errOut)
	root.SetArgs(args)
	// Propagate context for commands that need it.
	for _, c := range collectCommands(root) {
		c.SetContext(context.Background())
	}
	err := root.Execute()
	return out.String(), errOut.String(), err
}

func collectCommands(c *cobra.Command) []*cobra.Command {
	out := []*cobra.Command{c}
	for _, sub := range c.Commands() {
		out = append(out, collectCommands(sub)...)
	}
	return out
}

func TestInitWritesFileAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")

	if _, _, err := runCmd(t, "init", "-o", path); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}

	if _, _, err := runCmd(t, "init", "-o", path); err == nil {
		t.Fatal("expected refusal on overwrite without --force")
	}

	if _, _, err := runCmd(t, "init", "-o", path, "--force"); err != nil {
		t.Fatalf("init --force: %v", err)
	}
}

func TestStatusReadsConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "yauth.yaml")
	if _, _, err := runCmd(t, "init", "-o", cfgPath); err != nil {
		t.Fatal(err)
	}
	out, _, err := runCmd(t, "status", "-c", cfgPath)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "driver:") || !strings.Contains(out, "email_password") {
		t.Errorf("unexpected status output:\n%s", out)
	}
}

func TestMigrateAndCheckRoundTrip(t *testing.T) {
	// pgx is the only SQL backend, so this round-trip needs a real Postgres.
	// CI's test-postgres job provides DATABASE_URL; otherwise skip.
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("set DATABASE_URL (Postgres) to run the migrate/check round-trip")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "yauth.yaml")

	body := []byte("database:\n  driver: pgx\n  dsn: \"" + dsn + "\"\nplugins:\n  email_password:\n    enabled: true\n")
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCmd(t, "migrate", "-c", cfgPath)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !strings.Contains(out, "yauth_users") {
		t.Errorf("migrate output missing yauth_users:\n%s", out)
	}

	if _, _, err := runCmd(t, "check", "-c", cfgPath); err != nil {
		t.Fatalf("check after migrate should pass: %v", err)
	}
}

func TestGenSecretsWritesEnv(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, ".env")
	if _, _, err := runCmd(t, "gen-secrets", "-o", out); err != nil {
		t.Fatalf("gen-secrets: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// WEBHOOK_DEFAULT_SECRET was pinned here until this commit. It was never
	// read by anything — plugins.webhooks.default_secret_env, the only field
	// that named it, is accepted-and-ignored — so this assertion was pinning
	// the bug. WEBHOOK_ENCRYPTION_KEY replaces it and is consumed by
	// plugins.webhooks.encryption_key_env.
	for _, key := range []string{"JWT_SECRET=", "MFA_ENCRYPTION_KEY=", "WEBHOOK_ENCRYPTION_KEY="} {
		if !strings.Contains(string(body), key) {
			t.Errorf(".env missing %s; body:\n%s", key, body)
		}
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "JWT_SECRET=") && len(strings.TrimPrefix(line, "JWT_SECRET=")) < 32 {
			t.Errorf("JWT_SECRET unexpectedly short: %q", line)
		}
	}
	if _, _, err := runCmd(t, "gen-secrets", "-o", out); err == nil {
		t.Fatal("gen-secrets should refuse to overwrite without --force")
	}
}

func TestGenKeysRSAAndECDSA(t *testing.T) {
	for _, kt := range []string{"rs256", "es256"} {
		t.Run(kt, func(t *testing.T) {
			dir := t.TempDir()
			if _, _, err := runCmd(t, "gen-keys", "--type", kt, "--out", dir); err != nil {
				t.Fatalf("gen-keys %s: %v", kt, err)
			}
			priv, err := os.ReadFile(filepath.Join(dir, "private.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(priv), "BEGIN PRIVATE KEY") {
				t.Errorf("private.pem missing PKCS8 header for %s", kt)
			}
			info, err := os.Stat(filepath.Join(dir, "private.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("private.pem perms = %o, want 0600", info.Mode().Perm())
			}
		})
	}
}

func TestVersion(t *testing.T) {
	out, _, err := runCmd(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(out, "yauth") {
		t.Errorf("version output unexpected: %q", out)
	}
}
