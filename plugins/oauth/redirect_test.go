package oauth

import "testing"

// TestSafeRedirect verifies the open-redirect mitigation: the plugin
// honors only redirect_url values on the AllowedRedirectURLs list (or
// host-relative paths). Closes the gap surfaced by
// pentest_test.go::TestPentest_OAuthOpenRedirect_NotEnforced.
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
			p := &oauthPlugin{cfg: Config{AllowedRedirectURLs: tc.allowed}}
			got := p.safeRedirect(tc.input)
			if got != tc.want {
				t.Errorf("safeRedirect(%q) with allow=%v: got %q want %q", tc.input, tc.allowed, got, tc.want)
			}
		})
	}
}
