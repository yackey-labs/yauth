package auth

import "testing"

func TestCanonicalizeDomain_UnderscoreAllowedInjectionNot(t *testing.T) {
	got, err := CanonicalizeDomain("My_Corp.Example.")
	if err != nil || got != "my_corp.example" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"a b.com", "a.com/x", "a@b.com", "-a.com", "a..com"} {
		if _, err := CanonicalizeDomain(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
