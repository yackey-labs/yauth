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

func TestValidate_RejectsNegativeRateLimit(t *testing.T) {
	c := &yauthcfg.Config{}
	c.Database.Driver = "memory"
	c.RateLimit.Login = yauthcfg.RateLimitRule{Max: intp(-1)}
	if err := c.Validate(); err == nil {
		t.Fatal("expected Validate to reject a negative rate_limit.login.max")
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
