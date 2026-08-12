package yauth_test

// Insecure defaults that Validate() never rejected, and that nothing at startup
// mentioned. Each case here pins one of the reject-or-warn decisions.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// minimalBearerConfig enables just enough to reach the bearer wiring.
func minimalBearerConfig() *yauthcfg.Config {
	c := *yauthcfg.Default()
	c.Database.Driver = "memory"
	c.Database.DSN = ""
	c.Plugins.EmailPassword.Enabled = true
	c.Plugins.Bearer.Enabled = true
	c.Plugins.Bearer.JWTSecretEnv = "YA_SEC_TEST_JWT"
	return &c
}

// TestNewFromConfig_RejectsShortJWTSecret. from_config.go checked only that
// JWT_SECRET was non-empty and yauth.go's WithJWTSecret checked nothing at all,
// so JWT_SECRET=a started cleanly and signed every bearer access token, refresh
// binding and machine credential in the deployment with a key an attacker
// recovers offline from a single captured token. RFC 7518 §3.2 requires at
// least the hash output size for HS256.
func TestNewFromConfig_RejectsShortJWTSecret(t *testing.T) {
	for _, secret := range []string{"a", "short", strings.Repeat("x", yauthcfg.MinJWTSecretBytes-1)} {
		t.Run(secret[:min(len(secret), 8)], func(t *testing.T) {
			t.Setenv("YA_SEC_TEST_JWT", secret)
			_, err := yauth.NewFromConfig(context.Background(), minimalBearerConfig())
			if err == nil {
				t.Fatalf("a %d-byte HS256 secret was accepted", len(secret))
			}
			if !strings.Contains(err.Error(), "HS256") {
				t.Errorf("error does not explain the rule: %v", err)
			}
		})
	}
}

// TestNewFromConfig_AcceptsAdequateJWTSecret is the control: the boundary value
// still starts, so the rule is a floor rather than a wall.
func TestNewFromConfig_AcceptsAdequateJWTSecret(t *testing.T) {
	t.Setenv("YA_SEC_TEST_JWT", strings.Repeat("x", yauthcfg.MinJWTSecretBytes))
	if _, err := yauth.NewFromConfig(context.Background(), minimalBearerConfig()); err != nil {
		t.Fatalf("a %d-byte secret was rejected: %v", yauthcfg.MinJWTSecretBytes, err)
	}
}

// TestNewFromConfig_WarnsOnInsecureCookieDefault. CookieSecure=false is left
// PERMITTED — yauth cannot see whether a proxy terminates TLS, and rejecting it
// would break every local dev run — but it must be said. The console mailer's
// one-time WARN is the precedent for "dangerous but allowed".
func TestNewFromConfig_WarnsOnInsecureCookieDefault(t *testing.T) {
	t.Setenv("YA_SEC_TEST_JWT", strings.Repeat("x", yauthcfg.MinJWTSecretBytes))

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := minimalBearerConfig()
	cfg.Session.CookieSecure = false
	if _, err := yauth.NewFromConfig(context.Background(), cfg, yauth.WithConfigLogger(logger)); err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(buf.String(), "cookie_secure") {
		t.Fatalf("startup said nothing about cookie_secure=false; log was:\n%s", buf.String())
	}

	// ...and stays quiet once it is set.
	buf.Reset()
	cfg = minimalBearerConfig()
	cfg.Session.CookieSecure = true
	if _, err := yauth.NewFromConfig(context.Background(), cfg, yauth.WithConfigLogger(logger)); err != nil {
		t.Fatalf("build: %v", err)
	}
	if strings.Contains(buf.String(), "cookie_secure") {
		t.Fatalf("advisory fired with cookie_secure=true:\n%s", buf.String())
	}
}

// TestWithJWTSecret_RejectsShortSecret is the programmatic sibling of
// TestNewFromConfig_RejectsShortJWTSecret. The builder setter cannot return an
// error, so the failure has to surface at Build() — the alternative was
// swallowing it, which is how a one-byte signing key reaches a deployment.
func TestWithJWTSecret_RejectsShortSecret(t *testing.T) {
	if _, err := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("a")).
		Build(); err == nil {
		t.Fatalf("Build accepted a 1-byte HS256 secret")
	}

	// The controls: an adequate secret still builds, and so does no secret at
	// all (plenty of deployments are cookie-only and never set one).
	if _, err := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).
		WithJWTSecret([]byte(strings.Repeat("x", yauthcfg.MinJWTSecretBytes))).
		Build(); err != nil {
		t.Fatalf("adequate secret rejected: %v", err)
	}
	if _, err := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).Build(); err != nil {
		t.Fatalf("no secret at all rejected: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
