package auth_test

import (
	"testing"

	"github.com/yackey-labs/yauth/auth"
)

// TestSafeRedirect is the consolidated table that plugins/oauth,
// plugins/ssooidc and plugins/ssosaml all now share a single implementation
// of. The backslash and control-character rows are the regression: they were
// ALLOWED by the pre-fix `HasPrefix(in,"/") && !HasPrefix(in,"//")` check and
// every one of them navigates a browser to another origin.
func TestSafeRedirect(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		input   string
		want    string
	}{
		// Empty allow-list: only relative paths get through.
		{"empty_list_rejects_absolute", nil, "https://evil.com/", ""},
		{"empty_list_rejects_attacker_subdomain", nil, "https://app.example.com.evil.com/", ""},
		{"empty_list_allows_relative", nil, "/dashboard", "/dashboard"},
		{"empty_list_rejects_protocol_relative", nil, "//evil.com/path", ""},
		{"empty_list_rejects_javascript_uri", nil, "javascript:alert(1)", ""},
		{"empty_input", nil, "", ""},
		{"whitespace_only", nil, "   ", ""},

		// --- the bypasses ---------------------------------------------
		// WHATWG relative-slash state normalises \ to / — the browser
		// resolves each of these to another origin.
		{"rejects_backslash_escape", nil, `/\evil.com`, ""},
		{"rejects_backslash_slash", nil, `/\/evil.com`, ""},
		{"rejects_double_backslash", nil, `\\evil.com`, ""},
		{"rejects_slash_backslash_path", nil, `/\evil.com/path`, ""},
		// Browsers strip tab/LF/CR from a URL before parsing it.
		{"rejects_tab", nil, "/\tevil.com", ""},
		{"rejects_lf", nil, "/\n/evil.com", ""},
		{"rejects_cr", nil, "/\r/evil.com", ""},
		{"rejects_embedded_crlf_header_injection", nil, "/ok\r\nX-Injected: 1", ""},
		{"rejects_null_byte", nil, "/ok\x00/evil.com", ""},
		{"rejects_del", nil, "/ok\x7f/evil.com", ""},
		// ...including inside an otherwise allow-listed absolute URL.
		{"rejects_control_in_allowed_absolute", []string{"https://app.example.com"}, "https://app.example.com/\r\nX: 1", ""},

		// A backslash that is not part of the leading slash run is harmless
		// and must still work — it cannot change the origin.
		{"allows_backslash_deeper_in_path", nil, `/files/a\b`, `/files/a\b`},

		// Allow-list with one entry.
		{"allow_exact", []string{"https://app.example.com"}, "https://app.example.com", "https://app.example.com"},
		{"allow_prefix", []string{"https://app.example.com"}, "https://app.example.com/dashboard?x=1", "https://app.example.com/dashboard?x=1"},
		{"reject_unrelated_host", []string{"https://app.example.com"}, "https://evil.com/", ""},
		{"reject_subdomain_attack", []string{"https://app.example.com"}, "https://app.example.com.evil.com/", ""},
		{"empty_string_in_list_ignored", []string{"", "https://app.example.com"}, "https://app.example.com/x", "https://app.example.com/x"},

		// Multiple allowed prefixes.
		{"multi_allow_first", []string{"https://a.example.com", "https://b.example.com"}, "https://a.example.com/", "https://a.example.com/"},
		{"multi_allow_second", []string{"https://a.example.com", "https://b.example.com"}, "https://b.example.com/x", "https://b.example.com/x"},
		{"multi_reject_third", []string{"https://a.example.com", "https://b.example.com"}, "https://c.example.com/", ""},

		// Whitespace trim.
		{"trims_whitespace", []string{"https://app.example.com"}, "  https://app.example.com/  ", "https://app.example.com/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := auth.SafeRedirect(tc.input, tc.allowed)
			if got != tc.want {
				t.Errorf("SafeRedirect(%q, %v): got %q want %q", tc.input, tc.allowed, got, tc.want)
			}
		})
	}
}
