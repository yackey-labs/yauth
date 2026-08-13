package yauthcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigPasses(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	got := c.EnabledPlugins()
	if len(got) != 1 || got[0] != "email_password" {
		t.Fatalf("EnabledPlugins() = %v, want [email_password]", got)
	}
}

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")
	body := []byte(`database:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
session:
  ttl: 1h
  cookie_name: yauth_session
  cookie_same_site: lax
plugins:
  email_password:
    enabled: true
    min_password_length: 8
  bearer:
    enabled: true
    jwt_secret_env: JWT_SECRET
    access_ttl: 15m
    refresh_ttl: 720h
    issuer: yauth
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Session.TTL != time.Hour {
		t.Errorf("session.ttl = %v, want 1h", cfg.Session.TTL)
	}
	if !cfg.Plugins.Bearer.Enabled {
		t.Error("bearer should be enabled")
	}
	if cfg.Plugins.Bearer.AccessTTL != 15*time.Minute {
		t.Errorf("bearer.access_ttl = %v, want 15m", cfg.Plugins.Bearer.AccessTTL)
	}
}

func TestLoadYAML_OAuth2ServerTTLs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")
	body := []byte(`database:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
plugins:
  oauth2_server:
    enabled: true
    authorization_code_ttl: 10m
    device_code_ttl: 5m
    access_ttl: 5m
    backchannel_logout_timeout: 3s
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	o := cfg.Plugins.OAuth2Server
	if o.AccessTTL != 5*time.Minute {
		t.Errorf("oauth2_server.access_ttl = %v, want 5m", o.AccessTTL)
	}
	if o.BackchannelLogoutTimeout != 3*time.Second {
		t.Errorf("oauth2_server.backchannel_logout_timeout = %v, want 3s", o.BackchannelLogoutTimeout)
	}
	if o.AuthorizationCodeTTL != 10*time.Minute {
		t.Errorf("oauth2_server.authorization_code_ttl = %v, want 10m", o.AuthorizationCodeTTL)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Negative values are rejected.
	cfg.Plugins.OAuth2Server.AccessTTL = -time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative access_ttl")
	}
}

func TestValidate_MemoryDriverNeedsNoDSN(t *testing.T) {
	c := &Config{Database: DatabaseConfig{Driver: "memory"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("memory driver should validate without a DSN: %v", err)
	}
	// An unknown driver is still rejected.
	bad := &Config{Database: DatabaseConfig{Driver: "cassandra"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected unsupported-driver error")
	}
	// Non-memory drivers still require a DSN.
	noDSN := &Config{Database: DatabaseConfig{Driver: "postgres"}}
	if err := noDSN.Validate(); err == nil {
		t.Fatal("expected dsn-required error for postgres")
	}
}

func TestLoadTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.toml")
	body := []byte(`[database]
driver = "sqlite"
dsn = "file::memory:?cache=shared"

[plugins.email_password]
enabled = true
min_password_length = 10
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("driver = %q", cfg.Database.Driver)
	}
	if cfg.Plugins.EmailPassword.MinPasswordLength != 10 {
		t.Errorf("min_password_length = %d", cfg.Plugins.EmailPassword.MinPasswordLength)
	}
}

func TestLoadEnvDSN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")
	body := []byte(`database:
  driver: postgres
  dsn: "env:TEST_DB_URL"
plugins:
  email_password:
    enabled: true
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("unset", func(t *testing.T) {
		os.Unsetenv("TEST_DB_URL")
		if _, err := Load(path); err == nil {
			t.Fatal("expected error for unset env var")
		}
	})
	t.Run("set", func(t *testing.T) {
		t.Setenv("TEST_DB_URL", "postgres://localhost/test")
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Database.DSN != "postgres://localhost/test" {
			t.Errorf("dsn = %q", cfg.Database.DSN)
		}
	})
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:    "default",
			mutate:  func(*Config) {},
			wantErr: false,
		},
		{
			name:    "missing driver",
			mutate:  func(c *Config) { c.Database.Driver = "" },
			wantErr: true,
		},
		{
			name:    "bad driver",
			mutate:  func(c *Config) { c.Database.Driver = "oracle" },
			wantErr: true,
		},
		{
			name:    "missing dsn",
			mutate:  func(c *Config) { c.Database.DSN = "" },
			wantErr: true,
		},
		{
			name: "bad samesite",
			mutate: func(c *Config) {
				c.Session.CookieSameSite = "bogus"
			},
			wantErr: true,
		},
		{
			name: "bearer without secret",
			mutate: func(c *Config) {
				c.Plugins.Bearer.Enabled = true
			},
			wantErr: true,
		},
		{
			name: "asym_jwt valid",
			mutate: func(c *Config) {
				c.Plugins.AsymJWT.Enabled = true
				c.Plugins.AsymJWT.KeyType = "rs256"
				c.Plugins.AsymJWT.PrivateKeyPath = "/k/p.pem"
				c.Plugins.AsymJWT.PublicKeyPath = "/k/pub.pem"
			},
			wantErr: false,
		},
		{
			name: "asym_jwt missing paths",
			mutate: func(c *Config) {
				c.Plugins.AsymJWT.Enabled = true
				c.Plugins.AsymJWT.KeyType = "rs256"
			},
			wantErr: true,
		},
		{
			name: "passkey requires rp",
			mutate: func(c *Config) {
				c.Plugins.Passkey.Enabled = true
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestEnabledPluginsOrder(t *testing.T) {
	c := Default()
	c.Plugins.Bearer.Enabled = true
	c.Plugins.Bearer.JWTSecretEnv = "JWT_SECRET"
	c.Plugins.APIKey.Enabled = true
	c.Plugins.Status.Enabled = true
	got := c.EnabledPlugins()
	want := []string{"email_password", "bearer", "api_key", "status"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestValidateRejectsDivergentIdPIssuer(t *testing.T) {
	c := Default()
	c.Plugins.OIDC.Enabled = true
	c.Plugins.OAuth2Server.Enabled = true

	// Matching issuers (or only one set) are fine.
	c.Plugins.OIDC.Issuer = "https://idp.example.com"
	c.Plugins.OAuth2Server.Issuer = "https://idp.example.com"
	if err := c.Validate(); err != nil {
		t.Fatalf("matching issuers should validate: %v", err)
	}

	// Divergent issuers are a misconfiguration (one would be silently ignored).
	c.Plugins.OAuth2Server.Issuer = "https://other.example.com"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for divergent oidc/oauth2_server issuers, got nil")
	}
}

func TestEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")
	body := "database:\n  driver: memory\nserver:\n  addr: \":3000\"\nsession:\n  ttl: 1h\nplugins:\n  email_password:\n    enabled: true\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("YAUTH_SERVER_ADDR", ":8080")           // string, nested
	t.Setenv("YAUTH_SESSION_TTL", "24h")             // duration
	t.Setenv("YAUTH_PLUGINS_BEARER_ENABLED", "true") // deep nested bool
	t.Setenv("YAUTH_PLUGINS_BEARER_JWT_SECRET_ENV", "JS")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Addr != ":8080" {
		t.Errorf("server.addr = %q, want :8080 (env override)", c.Server.Addr)
	}
	if c.Session.TTL != 24*time.Hour {
		t.Errorf("session.ttl = %v, want 24h (env override)", c.Session.TTL)
	}
	if !c.Plugins.Bearer.Enabled {
		t.Error("plugins.bearer.enabled should be true from env override")
	}
}

// TestEnvDSNUnified shows the DSN is overridable the same generic way as any
// field (YAUTH_DATABASE_DSN), and that it wins over the `env:` indirection.
func TestEnvDSNUnified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")
	body := "database:\n  driver: pgx\n  dsn: env:PLATFORM_DB_URL\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLATFORM_DB_URL", "postgres://from-indirection")
	t.Setenv("YAUTH_DATABASE_DSN", "postgres://from-generic-override")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Database.DSN != "postgres://from-generic-override" {
		t.Errorf("dsn = %q, want the YAUTH_DATABASE_DSN override to win", c.Database.DSN)
	}
}

func TestDeprecationWarnings(t *testing.T) {
	// Zero/absent deprecated fields → no noise (the common scaffolded case).
	c := Default()
	c.Plugins.OAuth2Server.Enabled = true // require_pkce defaults false → quiet
	if w := c.DeprecationWarnings(); len(w) != 0 {
		t.Fatalf("expected no warnings for default config, got %v", w)
	}

	// Meaningfully-set deprecated fields → one warning each, naming the field.
	c.Plugins.OAuth2Server.RequirePKCE = true
	c.Plugins.APIKey.HeaderName = "X-Custom"
	c.Plugins.Webhooks.DefaultSecretEnv = "WH"
	w := c.DeprecationWarnings()
	if len(w) != 3 {
		t.Fatalf("expected 3 deprecation warnings, got %d: %v", len(w), w)
	}
	joined := strings.Join(w, "\n")
	for _, field := range []string{"require_pkce", "header_name", "default_secret_env"} {
		if !strings.Contains(joined, field) {
			t.Errorf("warnings should mention %q; got:\n%s", field, joined)
		}
	}
}

func TestExpectedTablesGrowsWithPlugins(t *testing.T) {
	c := Default()
	base := len(c.ExpectedTables())
	c.Plugins.Bearer.Enabled = true
	c.Plugins.Bearer.JWTSecretEnv = "JWT_SECRET"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := len(c.ExpectedTables()); got <= base {
		t.Errorf("enabling bearer should add expected tables: was %d, now %d", base, got)
	}
}

func TestDecodeUnknownYAMLField(t *testing.T) {
	body := []byte(`database:
  driver: sqlite
  dsn: ":memory:"
  not_a_real_field: 1
`)
	if _, err := Decode(body, FormatYAML); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	c := Default()
	b, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b, FormatYAML)
	if err != nil {
		t.Fatalf("decode round-trip: %v", err)
	}
	if got.Database.Driver != c.Database.Driver {
		t.Errorf("driver round-trip: got %q, want %q", got.Database.Driver, c.Database.Driver)
	}
}

// The cloudflare mailer block must survive the real file-loading path, not
// just struct-literal construction. The YAML decoder runs with
// KnownFields(true), so a typo in a `yaml:` tag fails here and nowhere else;
// Validate() does not inspect the mailer block at all.
func TestLoadYAML_MailerCloudflare(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")
	body := []byte(`database:
  driver: memory
mailer:
  provider: cloudflare
  from: "no-reply@example.com"
  cloudflare:
    account_id: "acct123"
    api_token_env: CLOUDFLARE_API_TOKEN
    base_url: "https://proxy.example.com/client/v4"
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mailer.Provider != "cloudflare" {
		t.Errorf("provider = %q", cfg.Mailer.Provider)
	}
	if cfg.Mailer.From != "no-reply@example.com" {
		t.Errorf("from = %q", cfg.Mailer.From)
	}
	if cfg.Mailer.Cloudflare.AccountID != "acct123" {
		t.Errorf("account_id = %q", cfg.Mailer.Cloudflare.AccountID)
	}
	if cfg.Mailer.Cloudflare.APITokenEnv != "CLOUDFLARE_API_TOKEN" {
		t.Errorf("api_token_env = %q", cfg.Mailer.Cloudflare.APITokenEnv)
	}
	if cfg.Mailer.Cloudflare.BaseURL != "https://proxy.example.com/client/v4" {
		t.Errorf("base_url = %q", cfg.Mailer.Cloudflare.BaseURL)
	}
}

// Same block via TOML, which uses separate struct tags.
func TestLoadTOML_MailerCloudflare(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.toml")
	body := []byte(`[database]
driver = "memory"

[mailer]
provider = "cloudflare"
from = "no-reply@example.com"

[mailer.cloudflare]
account_id = "acct123"
api_token_env = "CLOUDFLARE_API_TOKEN"
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mailer.Cloudflare.AccountID != "acct123" {
		t.Errorf("account_id = %q", cfg.Mailer.Cloudflare.AccountID)
	}
	if cfg.Mailer.Cloudflare.APITokenEnv != "CLOUDFLARE_API_TOKEN" {
		t.Errorf("api_token_env = %q", cfg.Mailer.Cloudflare.APITokenEnv)
	}
}

// Encode (used by `yauth init`) must round-trip the block back through the
// strict decoder.
func TestEncodeDecode_MailerCloudflareRoundTrips(t *testing.T) {
	in := &Config{}
	in.Mailer = MailerConfig{
		Provider:   "cloudflare",
		From:       "no-reply@example.com",
		Cloudflare: CloudflareConfig{AccountID: "acct123", APITokenEnv: "CLOUDFLARE_API_TOKEN"},
	}
	raw, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := Decode(raw, FormatYAML)
	if err != nil {
		t.Fatalf("Decode of encoded config: %v", err)
	}
	if out.Mailer.Cloudflare != in.Mailer.Cloudflare {
		t.Errorf("cloudflare block did not round-trip: %+v vs %+v", out.Mailer.Cloudflare, in.Mailer.Cloudflare)
	}
}

// server.security_headers must survive the real file-loading path in BOTH
// formats. It is the operator's only handle on the response-header floor that
// closed the "every yauth response goes out with no CSP / no X-Frame-Options /
// no nosniff" finding, and the YAML decoder runs with KnownFields(true): a typo
// in either struct tag turns a working config file into a hard startup failure
// and is caught nowhere else. The tri-state Enabled is asserted as an explicit
// false because that is the value with a consequence — omitted means ON.
func TestLoadYAML_ServerSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")
	body := []byte(`database:
  driver: memory
server:
  security_headers:
    enabled: false
    hsts: "max-age=31536000; includeSubDomains"
    override:
      X-Frame-Options: SAMEORIGIN
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.SecurityHeaders.Enabled == nil || *cfg.Server.SecurityHeaders.Enabled {
		t.Errorf("enabled = %v, want explicit false", cfg.Server.SecurityHeaders.Enabled)
	}
	if got := cfg.Server.SecurityHeaders.HSTS; got != "max-age=31536000; includeSubDomains" {
		t.Errorf("hsts = %q", got)
	}
	if got := cfg.Server.SecurityHeaders.Override["X-Frame-Options"]; got != "SAMEORIGIN" {
		t.Errorf("override[X-Frame-Options] = %q", got)
	}

	// POSITIVE CONTROL: omitting the block leaves Enabled nil, which is how
	// "headers ON by default" is expressed. A fix that flipped the default
	// to opt-in would show up here.
	plain := filepath.Join(dir, "plain.yaml")
	if err := os.WriteFile(plain, []byte("database:\n  driver: memory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	def, err := Load(plain)
	if err != nil {
		t.Fatalf("Load plain: %v", err)
	}
	if def.Server.SecurityHeaders.Enabled != nil {
		t.Errorf("omitted enabled = %v, want nil (meaning true)", *def.Server.SecurityHeaders.Enabled)
	}
}

// Same block via TOML, which uses separate struct tags.
func TestLoadTOML_ServerSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.toml")
	body := []byte(`[database]
driver = "memory"

[server.security_headers]
enabled = false
hsts = "max-age=31536000"

[server.security_headers.override]
X-Frame-Options = "SAMEORIGIN"
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.SecurityHeaders.Enabled == nil || *cfg.Server.SecurityHeaders.Enabled {
		t.Errorf("enabled = %v, want explicit false", cfg.Server.SecurityHeaders.Enabled)
	}
	if got := cfg.Server.SecurityHeaders.HSTS; got != "max-age=31536000" {
		t.Errorf("hsts = %q", got)
	}
	if got := cfg.Server.SecurityHeaders.Override["X-Frame-Options"]; got != "SAMEORIGIN" {
		t.Errorf("override[X-Frame-Options] = %q", got)
	}
}
