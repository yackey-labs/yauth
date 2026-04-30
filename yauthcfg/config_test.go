package yauthcfg

import (
	"os"
	"path/filepath"
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
