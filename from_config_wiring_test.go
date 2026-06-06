package yauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/status"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/repo/pgxrepo"
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
	p.Organizations.Enabled = true // workforce tenancy (org-scoped groups + keys)
	p.SCIM.Enabled = true          // SCIM 2.0 provisioning over the org-scoped surface
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

// TestNewFromConfig_BootstrapAdmin drives bootstrap end-to-end through the real
// NewFromConfig entry point on the memory driver: the admin is provisioned, the
// generated password is logged once, a disabled config is a no-op, and a second
// NewFromConfig over the SAME repo (restart simulation) does not re-provision.
func TestNewFromConfig_BootstrapAdmin(t *testing.T) {
	mkCfg := func(enabled bool) *yauthcfg.Config {
		c := &yauthcfg.Config{}
		c.Database.Driver = "memory"
		c.Plugins.EmailPassword.Enabled = true
		c.Plugins.EmailPassword.BootstrapAdmin = yauthcfg.BootstrapAdminConfig{
			Enabled: enabled, Email: "admin@example.com",
		}
		return c
	}

	// Disabled = no-op.
	var disabledBuf bytes.Buffer
	repoOff := memrepo.New()
	if _, err := yauth.NewFromConfig(context.Background(), mkCfg(false),
		yauth.WithRepo(repoOff), yauth.WithConfigLogger(slog.New(slog.NewJSONHandler(&disabledBuf, nil)))); err != nil {
		t.Fatalf("NewFromConfig disabled: %v", err)
	}
	if _, err := repoOff.GetUserByEmail(context.Background(), "admin@example.com"); err == nil {
		t.Fatalf("disabled bootstrap created an admin")
	}

	// Enabled = provisions + logs once. Reuse one repo across two NewFromConfig
	// calls to simulate a restart.
	shared := memrepo.New()
	var buf1 bytes.Buffer
	if _, err := yauth.NewFromConfig(context.Background(), mkCfg(true),
		yauth.WithRepo(shared), yauth.WithConfigLogger(slog.New(slog.NewJSONHandler(&buf1, nil)))); err != nil {
		t.Fatalf("NewFromConfig enabled: %v", err)
	}
	if u, err := shared.GetUserByEmail(context.Background(), "admin@example.com"); err != nil || u.Role != "admin" || !u.MustChangePassword {
		t.Fatalf("admin not provisioned correctly: u=%v err=%v", u, err)
	}
	if !strings.Contains(buf1.String(), "bootstrap admin provisioned") {
		t.Fatalf("expected provisioning log:\n%s", buf1.String())
	}

	var buf2 bytes.Buffer
	if _, err := yauth.NewFromConfig(context.Background(), mkCfg(true),
		yauth.WithRepo(shared), yauth.WithConfigLogger(slog.New(slog.NewJSONHandler(&buf2, nil)))); err != nil {
		t.Fatalf("NewFromConfig restart: %v", err)
	}
	if strings.Contains(buf2.String(), "bootstrap admin provisioned") {
		t.Fatalf("restart re-provisioned the admin:\n%s", buf2.String())
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

// TestOrganizationsSCIMConfigInvariants pins the cross-plugin rules that make
// the org-scoped SCIM surface coherent: scim is organization-scoped, and both
// organizations and scim authenticate org-scoped API keys through the api-key
// resolver — so each dependency is a loud config error rather than a runtime
// surprise (e.g. a SCIM key that never resolves).
func TestOrganizationsSCIMConfigInvariants(t *testing.T) {
	t.Run("scim requires organizations", func(t *testing.T) {
		c := minimalConfig()
		c.Plugins.APIKey.Enabled = true
		c.Plugins.SCIM.Enabled = true // organizations left off
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "organizations") {
			t.Fatalf("want scim-requires-organizations error, got %v", err)
		}
	})
	t.Run("organizations requires api_key", func(t *testing.T) {
		c := minimalConfig()
		c.Plugins.Organizations.Enabled = true // api_key left off
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "api_key") {
			t.Fatalf("want organizations-requires-api_key error, got %v", err)
		}
	})
	t.Run("orgs+scim+apikey wire and share the prefix", func(t *testing.T) {
		c := minimalConfig()
		c.Plugins.APIKey.Enabled = true
		c.Plugins.APIKey.Prefix = "tiny"
		c.Plugins.Organizations.Enabled = true
		c.Plugins.SCIM.Enabled = true
		ya, err := yauth.NewFromConfig(context.Background(), c)
		if err != nil {
			t.Fatalf("NewFromConfig: %v", err)
		}
		for _, want := range []string{"organizations", "scim"} {
			if !slices.Contains(ya.PluginNames(), want) {
				t.Errorf("%q plugin not wired; have %v", want, ya.PluginNames())
			}
		}
	})
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

// TestNewBuilderFromConfigWithRepo proves the injected repo bypasses the
// cfg.Database switch entirely: the config names driver=pgx with a
// syntactically-valid-but-unreachable DSN, yet Build succeeds because the
// injected memrepo is used and no pool is ever dialed. If the switch were NOT
// skipped, NewBuilderFromConfig would try to Open/Ping that DSN and fail —
// so success here is positive proof the injected repo is the one in use.
func TestNewBuilderFromConfigWithRepo(t *testing.T) {
	c := minimalConfig()
	c.Database.Driver = "pgx"
	c.Database.DSN = "postgres://u:p@127.0.0.1:1/db" // valid syntax, unreachable

	b, err := yauth.NewBuilderFromConfig(context.Background(), c, yauth.WithRepo(memrepo.New()))
	if err != nil {
		t.Fatalf("NewBuilderFromConfig with injected repo: %v", err)
	}
	if _, err := b.Build(); err != nil {
		t.Fatalf("Build with injected repo: %v", err)
	}
}

// TestNewFromConfigWithRepoIgnoresCacheAndMigrate confirms that injecting a
// repo makes cfg.Cache and cfg.Database.AutoMigrate no-ops (the caller owns
// both): the config enables a redis cache pointed at an unreachable address
// and sets auto_migrate, yet construction succeeds because neither is applied
// to the injected repo.
func TestNewFromConfigWithRepoIgnoresCacheAndMigrate(t *testing.T) {
	c := minimalConfig()
	c.Database.Driver = "pgx"
	c.Database.DSN = "postgres://u:p@127.0.0.1:1/db"
	c.Database.AutoMigrate = true // would dial+migrate if honored — it must be ignored
	c.Cache.Enabled = true
	c.Cache.Provider = "redis"
	c.Cache.RedisAddr = "127.0.0.1:1" // wrapping would still construct, but must be skipped

	ya, err := yauth.NewFromConfig(context.Background(), c, yauth.WithRepo(memrepo.New()))
	if err != nil {
		t.Fatalf("NewFromConfig with injected repo + cache/migrate set: %v", err)
	}
	if ya == nil {
		t.Fatal("expected a built *YAuth, got nil")
	}
}

// TestWithRepoAndWithPoolMutuallyExclusive verifies setting both injection
// options is a loud error rather than a silent last-wins.
func TestWithRepoAndWithPoolMutuallyExclusive(t *testing.T) {
	c := minimalConfig()
	_, err := yauth.NewBuilderFromConfig(context.Background(), c,
		yauth.WithRepo(memrepo.New()),
		yauth.WithPool(nil),
	)
	if err == nil {
		t.Fatal("expected mutual-exclusion error, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutual exclusion, got: %v", err)
	}
}

// TestNewBuilderFromConfigWithPool exercises the WithPool path end-to-end
// against a real Postgres (testcontainers): the caller's pool is reused,
// auto_migrate runs against it, and the resulting instance works. Skips when
// Docker is unavailable, matching the pgxrepo suite's convention.
func TestNewBuilderFromConfigWithPool(t *testing.T) {
	ctx := context.Background()
	ctr, err := tcpostgres.Run(ctx, "docker.io/library/postgres:16-alpine",
		tcpostgres.WithDatabase("yauth_test"),
		tcpostgres.WithUsername("yauth"),
		tcpostgres.WithPassword("yauth"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Skipf("Docker not available; WithPool test skipped: %v", err)
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Skipf("connection string: %v", err)
	}
	pool, err := pgxrepo.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	c := minimalConfig()
	c.Database.Driver = "pgx"
	c.Database.DSN = dsn
	c.Database.AutoMigrate = true // must run against the injected pool

	b, err := yauth.NewBuilderFromConfig(ctx, c, yauth.WithPool(pool))
	if err != nil {
		t.Fatalf("NewBuilderFromConfig with injected pool: %v", err)
	}
	ya, err := b.Build()
	if err != nil {
		t.Fatalf("Build with injected pool: %v", err)
	}
	if ya == nil {
		t.Fatal("expected a built *YAuth, got nil")
	}

	// auto_migrate ran against the shared pool: yauth's tables now exist in
	// the caller's database.
	var n int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'yauth_%'",
	).Scan(&n); err != nil {
		t.Fatalf("count yauth tables: %v", err)
	}
	if n == 0 {
		t.Error("expected auto_migrate to create yauth_* tables via the injected pool, found none")
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
