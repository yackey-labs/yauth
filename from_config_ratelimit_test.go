package yauth

import (
	"testing"
	"time"

	"github.com/yackey-labs/yauth/yauthcfg"
)

func intp(n int) *int { return &n }

// The yaml layer's half of the finding. `max: 0` is documented as "no
// limit", but overrideRule only copied a value when it was > 0, so the
// documented way to switch a limiter off silently kept the default — and an
// omitted key and an explicit zero were the same int either way.
func TestConfigToYAuthConfig_RateLimitOverrides(t *testing.T) {
	cases := []struct {
		name       string
		src        yauthcfg.RateLimitRule
		wantMax    *int
		wantWindow time.Duration
	}{
		{
			name:       "omitted keeps the default",
			src:        yauthcfg.RateLimitRule{},
			wantMax:    intp(10),
			wantWindow: 60 * time.Second,
		},
		{
			name:       "an explicit max is applied",
			src:        yauthcfg.RateLimitRule{Max: intp(3)},
			wantMax:    intp(3),
			wantWindow: 60 * time.Second,
		},
		{
			name:       "max 0 disables, as documented",
			src:        yauthcfg.RateLimitRule{Max: intp(0)},
			wantMax:    intp(0),
			wantWindow: 60 * time.Second,
		},
		{
			name:       "window alone is applied",
			src:        yauthcfg.RateLimitRule{Window: 5 * time.Second},
			wantMax:    intp(10),
			wantWindow: 5 * time.Second,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &yauthcfg.Config{}
			c.RateLimit.Login = tc.src
			out := configToYAuthConfig(c)

			got := out.RateLimit.Login
			if got.Max == nil || tc.wantMax == nil {
				t.Fatalf("Max = %v, want %v", got.Max, tc.wantMax)
			}
			if *got.Max != *tc.wantMax {
				t.Fatalf("rate_limit.login.max = %d; want %d", *got.Max, *tc.wantMax)
			}
			if got.Window != tc.wantWindow {
				t.Fatalf("rate_limit.login.window = %s; want %s", got.Window, tc.wantWindow)
			}
		})
	}
}

func TestConfigToYAuthConfig_TrustedProxies(t *testing.T) {
	c := &yauthcfg.Config{}
	c.Server.TrustedProxies = []string{"private", "173.245.48.0/20"}
	out := configToYAuthConfig(c)
	if len(out.TrustedProxies) != 2 || out.TrustedProxies[1] != "173.245.48.0/20" {
		t.Fatalf("TrustedProxies = %v; want the server.trusted_proxies list verbatim", out.TrustedProxies)
	}
}

// A typo must fail the config, not quietly fall back to a policy the
// operator did not ask for.
func TestValidate_RejectsMalformedTrustedProxies(t *testing.T) {
	c := &yauthcfg.Config{}
	c.Database.Driver = "memory"
	c.Server.TrustedProxies = []string{"10.0.0.0/8", "not-a-cidr"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected Validate to reject a malformed server.trusted_proxies entry")
	}

	c.Server.TrustedProxies = []string{"10.0.0.0/8", "private", "203.0.113.7"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid trusted_proxies rejected: %v", err)
	}
}

// The OAuth2 wire endpoints (/oauth/token, /oauth/device/code,
// /oauth/introspect, /oauth/revoke) were unmetered at every layer, so an
// anonymous caller armed with nothing but a public client_id could drive a
// 64 MiB argon2id verify per request. They are metered now, which means the
// operator needs a knob — and a knob that never reaches configToYAuthConfig
// is exactly how rate_limit went inert the last time. Both keys must survive
// the yaml -> runtime mapping, including the documented `max: 0`.
func TestConfigToYAuthConfig_OAuthRateLimitOverrides(t *testing.T) {
	c := &yauthcfg.Config{}
	c.RateLimit.OAuthToken = yauthcfg.RateLimitRule{Max: intp(0)}
	c.RateLimit.OAuthIntrospect = yauthcfg.RateLimitRule{Max: intp(42), Window: 30 * time.Second}
	out := configToYAuthConfig(c)

	if out.RateLimit.OAuthToken.Max == nil || *out.RateLimit.OAuthToken.Max != 0 {
		t.Fatalf("rate_limit.oauth_token.max = %v; want an explicit 0 (no limit)", out.RateLimit.OAuthToken.Max)
	}
	if out.RateLimit.OAuthIntrospect.Max == nil || *out.RateLimit.OAuthIntrospect.Max != 42 {
		t.Fatalf("rate_limit.oauth_introspect.max = %v; want 42", out.RateLimit.OAuthIntrospect.Max)
	}
	if out.RateLimit.OAuthIntrospect.Window != 30*time.Second {
		t.Fatalf("rate_limit.oauth_introspect.window = %s; want 30s", out.RateLimit.OAuthIntrospect.Window)
	}

	// An omitted key must stay nil so the plugin's own default (the single
	// source of truth for these two numbers) still applies.
	empty := configToYAuthConfig(&yauthcfg.Config{})
	if empty.RateLimit.OAuthToken.Max != nil {
		t.Fatalf("an omitted rate_limit.oauth_token materialised a max of %d; it must stay nil so the plugin default wins",
			*empty.RateLimit.OAuthToken.Max)
	}
}

func TestValidate_RejectsNegativeRateLimit(t *testing.T) {
	c := &yauthcfg.Config{}
	c.Database.Driver = "memory"
	c.RateLimit.Login = yauthcfg.RateLimitRule{Max: intp(-1)}
	if err := c.Validate(); err == nil {
		t.Fatal("expected Validate to reject a negative rate_limit.login.max")
	}
}

// A negative max disables the limiter through the same path as an explicit 0,
// so on the OAuth2 wire endpoints a typo would silently reopen the argon2 DoS.
// The new keys must be validated exactly like the original six.
func TestValidate_RejectsNegativeOAuthRateLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*yauthcfg.Config)
	}{
		{"oauth_token", func(c *yauthcfg.Config) { c.RateLimit.OAuthToken = yauthcfg.RateLimitRule{Max: intp(-1)} }},
		{"oauth_introspect", func(c *yauthcfg.Config) {
			c.RateLimit.OAuthIntrospect = yauthcfg.RateLimitRule{Window: -time.Second}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &yauthcfg.Config{}
			c.Database.Driver = "memory"
			tc.set(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected Validate to reject a negative rate_limit.%s value", tc.name)
			}

			// Positive control: a sane rule on the same key validates.
			ok := &yauthcfg.Config{}
			ok.Database.Driver = "memory"
			ok.RateLimit.OAuthToken = yauthcfg.RateLimitRule{Max: intp(150), Window: time.Minute}
			ok.RateLimit.OAuthIntrospect = yauthcfg.RateLimitRule{Max: intp(300), Window: time.Minute}
			if err := ok.Validate(); err != nil {
				t.Fatalf("a valid oauth rate-limit config was rejected: %v", err)
			}
		})
	}
}

// Building with a broken list must fail loudly rather than start on the
// default policy.
func TestBuild_RejectsMalformedTrustedProxies(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.TrustedProxies = []string{"nonsense"}
	if _, err := New(nil, cfg).Build(); err == nil {
		t.Fatal("expected Build to reject a malformed TrustedProxies entry")
	}
}
