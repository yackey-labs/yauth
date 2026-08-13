// The yaml layer's half of the security-header finding.
//
// What was broken: YAuth.Router() emitted no Content-Security-Policy, no
// X-Frame-Options, no X-Content-Type-Options and no Referrer-Policy on any
// response, which left the browser-facing, state-changing text/html page at
// GET /oauth/end_session framable. The router-level proof lives in
// security_headers_test.go; this file guards the one seam between the config
// file and the middleware, which is where the fix is easiest to get silently
// backwards.
//
// The polarity FLIPS at configToYAuthConfig. yauthcfg spells the switch as a
// tri-state `enabled` pointer (nil = the omitted key = ON), because that is the
// house style for a defaulted-true config knob and it is what an operator
// writes. middleware.SecurityHeadersConfig spells it as `Disabled`, because
// New(repo, cfg) stores the YAuthConfig it is handed verbatim with no
// defaulting pass — an `Enabled bool` there would read false for every embedder
// that builds its config in Go, and the middleware would ship doing nothing.
// A single inverted comparison in that translation turns the headers off for
// every yaml-configured deployment while every other test in the repo stays
// green, so all three states are pinned here explicitly.
package yauth

import (
	"testing"

	"github.com/yackey-labs/yauth/yauthcfg"
)

func boolp(b bool) *bool { return &b }

func TestConfigToYAuthConfig_SecurityHeadersTriState(t *testing.T) {
	cases := []struct {
		name         string
		enabled      *bool
		wantDisabled bool
	}{
		// POSITIVE CONTROL for the default: an operator who never heard of
		// this setting must still get the headers. This is the state
		// essentially every deployment is in.
		{"omitted means on", nil, false},
		{"explicit true means on", boolp(true), false},
		// The only state with a consequence.
		{"explicit false means off", boolp(false), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &yauthcfg.Config{}
			c.Server.SecurityHeaders.Enabled = tc.enabled
			out := configToYAuthConfig(c)
			if out.SecurityHeaders.Disabled != tc.wantDisabled {
				t.Errorf("Disabled = %v, want %v", out.SecurityHeaders.Disabled, tc.wantDisabled)
			}
		})
	}
}

// HSTS and the per-header overrides are carried through verbatim. HSTS
// especially: an empty value is what keeps Strict-Transport-Security off, so a
// mapping that invented a default here would strand a domain in every
// browser that ever saw the deployment.
func TestConfigToYAuthConfig_SecurityHeadersHSTSAndOverride(t *testing.T) {
	c := &yauthcfg.Config{}
	if got := configToYAuthConfig(c).SecurityHeaders.HSTS; got != "" {
		t.Errorf("unset hsts mapped to %q, want empty — HSTS must never be defaulted on", got)
	}

	c.Server.SecurityHeaders.HSTS = "max-age=31536000; includeSubDomains"
	c.Server.SecurityHeaders.Override = map[string]string{"X-Frame-Options": "SAMEORIGIN"}
	out := configToYAuthConfig(c)
	if out.SecurityHeaders.HSTS != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS = %q", out.SecurityHeaders.HSTS)
	}
	if got := out.SecurityHeaders.Override["X-Frame-Options"]; got != "SAMEORIGIN" {
		t.Errorf("Override[X-Frame-Options] = %q", got)
	}
}
