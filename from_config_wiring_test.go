package yauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/status"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// writeRSAKeys writes a fresh RSA-2048 keypair (PKCS#8 / PKIX PEM) into dir and
// returns the private/public paths.
func writeRSAKeys(t *testing.T, dir string) (priv, pub string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	priv = filepath.Join(dir, "priv.pem")
	pub = filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// fullConfig enables every plugin with the minimum fields each requires, on the
// in-memory backend. Secrets/keys are seeded into the environment via t.Setenv.
func fullConfig(t *testing.T) *yauthcfg.Config {
	t.Helper()
	dir := t.TempDir()
	priv, pub := writeRSAKeys(t, dir)

	aesKey := base64.StdEncoding.EncodeToString(bytesRepeat(0x2b, 32))
	t.Setenv("YA_JWT_SECRET", "test-hs256-secret-that-is-long-enough-32+")
	t.Setenv("YA_MFA_KEY", aesKey)
	t.Setenv("YA_OAUTH_KEY", aesKey)
	t.Setenv("YA_GOOGLE_ID", "google-client-id")
	t.Setenv("YA_GOOGLE_SECRET", "google-client-secret")

	c := yauthcfg.Default()
	c.Database.Driver = "memory"
	c.Database.DSN = ""
	c.Server.BaseURL = "https://idp.test.example" // becomes the IdP issuer
	c.Server.Prefix = "/api/auth"

	p := &c.Plugins
	p.EmailPassword.Enabled = true
	p.Bearer.Enabled = true
	p.Bearer.JWTSecretEnv = "YA_JWT_SECRET"
	p.APIKey.Enabled = true
	p.MagicLink.Enabled = true
	p.AccountLock.Enabled = true
	p.Status.Enabled = true
	p.Admin.Enabled = true
	p.MFA.Enabled = true
	p.MFA.EncryptionKeyEnv = "YA_MFA_KEY"
	p.Passkey.Enabled = true
	p.Passkey.RPID = "localhost"
	p.Passkey.RPOrigin = "http://localhost:3000"
	p.OAuth.Enabled = true
	p.OAuth.EncryptionKeyEnv = "YA_OAUTH_KEY"
	p.OAuth.Providers = map[string]yauthcfg.OAuthProvider{
		"google": {Enabled: true, ClientIDEnv: "YA_GOOGLE_ID", ClientSecretEnv: "YA_GOOGLE_SECRET", RedirectURL: "https://idp.test.example/api/auth/oauth/google/callback"},
	}
	p.Webhooks.Enabled = true
	p.AsymJWT.Enabled = true
	p.AsymJWT.KeyType = "rs256" // lowercase yaml form; wiring uppercases for the builder
	p.AsymJWT.PrivateKeyPath = priv
	p.AsymJWT.PublicKeyPath = pub
	p.AsymJWT.KeyID = "test-key-1"
	p.OIDC.Enabled = true
	p.OAuth2Server.Enabled = true
	p.OAuth2Server.DCREnabled = true
	return c
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// TestNewFromConfigWiresEveryPlugin is the forward-safety guard: every plugin
// enabled in config must be wired by NewFromConfig. If someone adds a plugin
// section without wiring it (or wiring silently drops one), the counts diverge.
func TestNewFromConfigWiresEveryPlugin(t *testing.T) {
	c := fullConfig(t)
	ya, err := yauth.NewFromConfig(context.Background(), c)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	enabled := c.EnabledPlugins()
	wired := ya.PluginNames()
	if len(wired) != len(enabled) {
		t.Fatalf("wired %d plugins (%v) but %d are enabled (%v) — a plugin was silently dropped",
			len(wired), wired, len(enabled), enabled)
	}
}

// TestNewFromConfigIdPValuesFlow spot-checks that config values actually reach
// the running plugins (not just that routes exist): the issuer is consistent
// across the OIDC and OAuth2 metadata, JWKS is served (asymjwt wired), and the
// registration endpoint is advertised (DCR enabled + oauth2server linked).
func TestNewFromConfigIdPValuesFlow(t *testing.T) {
	c := fullConfig(t)
	ya, err := yauth.NewFromConfig(context.Background(), c)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	srv := httptest.NewServer(ya.Router())
	defer srv.Close()

	get := func(path string) map[string]any {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, resp.StatusCode)
		}
		var m map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return m
	}

	const wantIssuer = "https://idp.test.example"

	oidcDoc := get("/.well-known/openid-configuration")
	if oidcDoc["issuer"] != wantIssuer {
		t.Errorf("openid-configuration issuer = %v, want %q", oidcDoc["issuer"], wantIssuer)
	}
	if oidcDoc["registration_endpoint"] == nil {
		t.Errorf("openid-configuration should advertise registration_endpoint when DCR is on + oauth2server loaded")
	}

	asDoc := get("/.well-known/oauth-authorization-server")
	if asDoc["issuer"] != wantIssuer {
		t.Errorf("oauth-authorization-server issuer = %v, want %q", asDoc["issuer"], wantIssuer)
	}
	if oidcDoc["issuer"] != asDoc["issuer"] {
		t.Errorf("OIDC and OAuth2 issuers diverge: %v vs %v", oidcDoc["issuer"], asDoc["issuer"])
	}

	jwks := get("/.well-known/jwks.json")
	if keys, ok := jwks["keys"].([]any); !ok || len(keys) == 0 {
		t.Errorf("jwks.json should contain keys (asymjwt wired), got %v", jwks["keys"])
	}
}

func minimalConfig() *yauthcfg.Config {
	c := yauthcfg.Default()
	c.Database.Driver = "memory"
	c.Database.DSN = ""
	return c // email_password only
}

// TestNewBuilderFromConfigMix verifies the mix-and-match path: yaml wires the
// standard plugins, then the builder adds a custom one before Build().
func TestNewBuilderFromConfigMix(t *testing.T) {
	b, err := yauth.NewBuilderFromConfig(context.Background(), minimalConfig())
	if err != nil {
		t.Fatalf("NewBuilderFromConfig: %v", err)
	}
	ya, err := b.WithPlugin(status.New()).Build() // status is NOT enabled in yaml
	if err != nil {
		t.Fatalf("Build after WithPlugin: %v", err)
	}
	if !slices.Contains(ya.PluginNames(), "status") {
		t.Errorf("mixed-in status plugin missing from %v", ya.PluginNames())
	}
}

// TestDuplicatePluginRejected verifies the mix footgun guard: the same plugin
// from yaml AND the builder is a clear error, not a huma panic.
func TestDuplicatePluginRejected(t *testing.T) {
	c := minimalConfig()
	c.Plugins.Status.Enabled = true // status wired from yaml...
	b, err := yauth.NewBuilderFromConfig(context.Background(), c)
	if err != nil {
		t.Fatalf("NewBuilderFromConfig: %v", err)
	}
	_, err = b.WithPlugin(status.New()).Build() // ...and again via builder
	if err == nil {
		t.Fatal("expected duplicate-plugin error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate plugin") {
		t.Errorf("error should mention duplicate plugin, got: %v", err)
	}
}
