package main

// Item-7: os.WriteFile's mode applies only at CREATION. A pre-existing
// private.pem / secrets file keeps whatever mode it already had, so a
// world-readable key or .env stayed world-readable after regeneration. Both
// generators now Chmod to 0600 after writing and fail if the repair fails.

import (
	"os"
	"path/filepath"
	"testing"
)

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestGenSecretsForceRepairsMode: a world-readable .env must come back 0600
// after gen-secrets --force overwrites it.
func TestGenSecretsForceRepairsMode(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, ".env")

	if err := os.WriteFile(out, []byte("JWT_SECRET=old\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(out, 0o644); err != nil {
		t.Fatalf("seed chmod: %v", err)
	}
	if got := fileMode(t, out); got != 0o644 {
		t.Fatalf("seed mode = %o, want 644", got)
	}

	if _, _, err := runCmd(t, "gen-secrets", "--out", out, "--force"); err != nil {
		t.Fatalf("gen-secrets --force: %v", err)
	}
	if got := fileMode(t, out); got != 0o600 {
		t.Fatalf("mode after --force = %o, want 600 (world-readable secret survived)", got)
	}
}

// TestGenSecretsFreshFileIs0600 pins the creation path too.
func TestGenSecretsFreshFileIs0600(t *testing.T) {
	out := filepath.Join(t.TempDir(), ".env")
	if _, _, err := runCmd(t, "gen-secrets", "--out", out); err != nil {
		t.Fatalf("gen-secrets: %v", err)
	}
	if got := fileMode(t, out); got != 0o600 {
		t.Fatalf("fresh mode = %o, want 600", got)
	}
}

// TestGenKeysRepairsPrivateKeyMode: a world-readable private.pem must come
// back 0600 after gen-keys overwrites it. The public key stays 0644.
func TestGenKeysRepairsPrivateKeyMode(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "private.pem")
	if err := os.WriteFile(priv, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(priv, 0o644); err != nil {
		t.Fatalf("seed chmod: %v", err)
	}

	if _, _, err := runCmd(t, "gen-keys", "--out", dir); err != nil {
		t.Fatalf("gen-keys: %v", err)
	}
	if got := fileMode(t, priv); got != 0o600 {
		t.Fatalf("private.pem mode = %o, want 600 (world-readable key survived)", got)
	}
	if got := fileMode(t, filepath.Join(dir, "public.pem")); got != 0o644 {
		t.Fatalf("public.pem mode = %o, want 644", got)
	}
}
