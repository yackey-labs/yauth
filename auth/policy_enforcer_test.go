package auth_test

import (
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
)

func i64p(v int64) *int64 { return &v }

func TestPolicyEnforcer_NilPolicyInheritsGlobal(t *testing.T) {
	enf := auth.NewPolicyEnforcer(nil, auth.GlobalPolicyDefaults{
		SessionTTL:   time.Hour,
		GlobalBindIP: true,
		GlobalBindUA: false,
	})
	if got := enf.ClampSessionTTL(2 * time.Hour); got != time.Hour {
		t.Fatalf("expected clamp to global; got %v", got)
	}
	bindIP, bindUA := enf.SessionBinding()
	if !bindIP || bindUA {
		t.Fatalf("expected (true, false); got (%v, %v)", bindIP, bindUA)
	}
	if !enf.CheckIPAllowlist("10.0.0.1") {
		t.Fatalf("empty allowlist must permit all")
	}
	if !enf.IsAuthMethodAllowed("password") {
		t.Fatalf("empty methods must permit all")
	}
}

func TestPolicyEnforcer_NilEnforcerIsPassThrough(t *testing.T) {
	var enf *auth.PolicyEnforcer
	if got := enf.ClampSessionTTL(time.Hour); got != time.Hour {
		t.Fatalf("nil enforcer must pass through ttl; got %v", got)
	}
	if !enf.CheckIPAllowlist("10.0.0.1") {
		t.Fatalf("nil enforcer must permit IPs")
	}
	if !enf.IsAuthMethodAllowed("password") {
		t.Fatalf("nil enforcer must permit methods")
	}
	if enf.MaxConcurrentSessions() != 0 {
		t.Fatalf("nil enforcer must return 0 cap")
	}
}

func TestPolicyEnforcer_StricterWinsOnSessionTTL(t *testing.T) {
	policy := &domain.OrganizationPolicy{
		OrganizationID:         "o1",
		MaxSessionDurationSecs: i64p(3600), // 1h
	}
	enf := auth.NewPolicyEnforcer(policy, auth.GlobalPolicyDefaults{
		SessionTTL: 24 * time.Hour,
	})
	if got := enf.ClampSessionTTL(8 * time.Hour); got != time.Hour {
		t.Fatalf("expected clamp to org's stricter 1h; got %v", got)
	}
}

func TestPolicyEnforcer_GlobalStricterThanOrg(t *testing.T) {
	policy := &domain.OrganizationPolicy{
		OrganizationID:         "o1",
		MaxSessionDurationSecs: i64p(24 * 3600),
	}
	enf := auth.NewPolicyEnforcer(policy, auth.GlobalPolicyDefaults{
		SessionTTL: time.Hour,
	})
	if got := enf.ClampSessionTTL(2 * time.Hour); got != time.Hour {
		t.Fatalf("expected clamp to global 1h; got %v", got)
	}
}

func TestPolicyEnforcer_IPAllowlistMatch(t *testing.T) {
	policy := &domain.OrganizationPolicy{
		OrganizationID: "o1",
		IPAllowlist:    []string{"10.0.0.0/8", "192.168.1.10"},
	}
	enf := auth.NewPolicyEnforcer(policy, auth.GlobalPolicyDefaults{})
	cases := map[string]bool{
		"10.0.0.5":     true,
		"10.255.255.1": true,
		"192.168.1.10": true,
		"192.168.1.11": false,
		"172.16.0.1":   false,
		"not-an-ip":    false,
		"":             true, // empty IP returns true to avoid bricking on proxy strip
	}
	for ip, want := range cases {
		if got := enf.CheckIPAllowlist(ip); got != want {
			t.Errorf("CheckIPAllowlist(%q): want %v got %v", ip, want, got)
		}
	}
}

func TestPolicyEnforcer_IPAllowlistEmptyAllowsAll(t *testing.T) {
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{}, auth.GlobalPolicyDefaults{})
	if !enf.CheckIPAllowlist("203.0.113.5") {
		t.Fatalf("empty allowlist must allow all")
	}
}

func TestPolicyEnforcer_AuthMethodAllowlist(t *testing.T) {
	policy := &domain.OrganizationPolicy{
		AllowedAuthMethods: []string{auth.AuthMethodPasskey, auth.AuthMethodSSOOIDC},
	}
	enf := auth.NewPolicyEnforcer(policy, auth.GlobalPolicyDefaults{})
	if !enf.IsAuthMethodAllowed(auth.AuthMethodPasskey) {
		t.Errorf("passkey must be allowed")
	}
	if enf.IsAuthMethodAllowed(auth.AuthMethodPassword) {
		t.Errorf("password must NOT be allowed")
	}
	// Case-insensitive match.
	if !enf.IsAuthMethodAllowed("Passkey") {
		t.Errorf("case-insensitive match failed")
	}
}

func TestPolicyEnforcer_IdleExceeded(t *testing.T) {
	policy := &domain.OrganizationPolicy{
		IdleTimeoutSecs: i64p(60),
	}
	enf := auth.NewPolicyEnforcer(policy, auth.GlobalPolicyDefaults{})
	now := time.Now().UTC()
	if enf.IdleExceeded(now.Add(-30*time.Second), now) {
		t.Errorf("30s lap < 60s idle must not exceed")
	}
	if !enf.IdleExceeded(now.Add(-2*time.Minute), now) {
		t.Errorf("2m lap > 60s idle must exceed")
	}
}

func TestPolicyEnforcer_IdleZeroDisabled(t *testing.T) {
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{}, auth.GlobalPolicyDefaults{})
	now := time.Now().UTC()
	if enf.IdleExceeded(now.Add(-365*24*time.Hour), now) {
		t.Errorf("zero idle timeout must always pass")
	}
}

func TestPolicyEnforcer_SessionBindingOverridesGlobal(t *testing.T) {
	// Org explicitly sets binding=none; global wanted IP binding.
	policy := &domain.OrganizationPolicy{SessionBinding: domain.SessionBindingNone}
	enf := auth.NewPolicyEnforcer(policy, auth.GlobalPolicyDefaults{GlobalBindIP: true})
	bindIP, bindUA := enf.SessionBinding()
	if bindIP || bindUA {
		t.Errorf("explicit none must override; got (%v, %v)", bindIP, bindUA)
	}
}

func TestPolicyEnforcer_SessionBindingUnsetInheritsGlobal(t *testing.T) {
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{}, auth.GlobalPolicyDefaults{GlobalBindIP: true, GlobalBindUA: true})
	bindIP, bindUA := enf.SessionBinding()
	if !bindIP || !bindUA {
		t.Errorf("unset must inherit; got (%v, %v)", bindIP, bindUA)
	}
}

func TestPolicyEnforcer_SessionBindingBothOverrides(t *testing.T) {
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{SessionBinding: domain.SessionBindingBoth}, auth.GlobalPolicyDefaults{})
	bindIP, bindUA := enf.SessionBinding()
	if !bindIP || !bindUA {
		t.Errorf("explicit both must enable; got (%v, %v)", bindIP, bindUA)
	}
}

func TestValidateCIDRStrings(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.0/8":  true,
		"192.168.1.1": true, // bare IP is normalized to /32
		"::1":         true,
		"::1/128":     true,
		"not-an-ip":   false,
		"10.0.0.0/99": false,
	}
	for in, ok := range cases {
		bad := auth.ValidateCIDRStrings([]string{in})
		got := bad == ""
		if got != ok {
			t.Errorf("ValidateCIDRStrings(%q): want ok=%v got bad=%q", in, ok, bad)
		}
	}
}

func TestValidateAuthMethods(t *testing.T) {
	if bad := auth.ValidateAuthMethods([]string{auth.AuthMethodPassword, auth.AuthMethodPasskey}); bad != "" {
		t.Errorf("known methods must validate; got %q", bad)
	}
	if bad := auth.ValidateAuthMethods([]string{"telepathy"}); bad != "telepathy" {
		t.Errorf("expected bad=telepathy; got %q", bad)
	}
}

func TestPolicyEnforcer_MaxConcurrentSessions(t *testing.T) {
	cap5 := int32(5)
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{MaxConcurrentSessions: &cap5}, auth.GlobalPolicyDefaults{})
	if got := enf.MaxConcurrentSessions(); got != 5 {
		t.Fatalf("expected 5; got %d", got)
	}
	zero := int32(0)
	enf2 := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{MaxConcurrentSessions: &zero}, auth.GlobalPolicyDefaults{})
	if got := enf2.MaxConcurrentSessions(); got != 0 {
		t.Fatalf("zero cap must collapse to no-cap; got %d", got)
	}
}

func TestPolicyEnforcer_MFAGracePeriod(t *testing.T) {
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{MfaRequired: true, MfaGracePeriodDays: 14}, auth.GlobalPolicyDefaults{})
	if !enf.IsMFARequired() {
		t.Errorf("MFA must be required")
	}
	want := 14 * 24 * time.Hour
	if got := enf.MFAGracePeriod(); got != want {
		t.Errorf("expected %v grace; got %v", want, got)
	}
}
