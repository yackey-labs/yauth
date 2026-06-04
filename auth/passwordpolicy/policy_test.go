package passwordpolicy

import (
	"errors"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/auth"
)

func strictPolicy() Policy {
	return Policy{
		MinLength:      8,
		MaxLength:      128,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		DisallowCommon: true,
	}
}

func TestPolicy_ValidPasswordPasses(t *testing.T) {
	if err := strictPolicy().Check("MyP@ssw0rd!"); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestPolicy_TooShort(t *testing.T) {
	err := strictPolicy().Check("Aa1!")
	if !errors.Is(err, ErrPolicyTooShort) {
		t.Fatalf("want ErrPolicyTooShort, got %v", err)
	}
}

func TestPolicy_TooLong(t *testing.T) {
	long := strings.Repeat("Aa1!", 40) // 160 chars
	err := strictPolicy().Check(long)
	if !errors.Is(err, ErrPolicyTooLong) {
		t.Fatalf("want ErrPolicyTooLong, got %v", err)
	}
}

func TestPolicy_MissingUpper(t *testing.T) {
	err := strictPolicy().Check("myp@ssw0rd!")
	if !errors.Is(err, ErrPolicyMissingUpper) {
		t.Fatalf("want ErrPolicyMissingUpper, got %v", err)
	}
}

func TestPolicy_MissingLower(t *testing.T) {
	err := strictPolicy().Check("MYP@SSW0RD!")
	if !errors.Is(err, ErrPolicyMissingLower) {
		t.Fatalf("want ErrPolicyMissingLower, got %v", err)
	}
}

func TestPolicy_MissingDigit(t *testing.T) {
	err := strictPolicy().Check("MyP@ssword!")
	if !errors.Is(err, ErrPolicyMissingDigit) {
		t.Fatalf("want ErrPolicyMissingDigit, got %v", err)
	}
}

func TestPolicy_MissingSpecial(t *testing.T) {
	err := strictPolicy().Check("MyPassw0rd")
	if !errors.Is(err, ErrPolicyMissingSpecial) {
		t.Fatalf("want ErrPolicyMissingSpecial, got %v", err)
	}
}

func TestPolicy_CommonRejected(t *testing.T) {
	p := Policy{DisallowCommon: true}
	if err := p.Check("password"); !errors.Is(err, ErrPolicyCommon) {
		t.Fatalf("want ErrPolicyCommon, got %v", err)
	}
	// Case-insensitive.
	if err := p.Check("PASSWORD"); !errors.Is(err, ErrPolicyCommon) {
		t.Fatalf("want ErrPolicyCommon (uppercase), got %v", err)
	}
}

func TestPolicy_EmptyAllowsAnything(t *testing.T) {
	if err := (Policy{}).Check("a"); err != nil {
		t.Fatalf("zero-value policy: want nil, got %v", err)
	}
}

func TestPolicy_Violations_AllReturned(t *testing.T) {
	violations := strictPolicy().Violations("aa")
	if len(violations) < 4 {
		t.Fatalf("want >=4 violations on 'aa', got %d: %v", len(violations), violations)
	}
}

func TestCheckHistory_DetectsReuse(t *testing.T) {
	old := "OldP@ssw0rd1"
	hash, err := auth.HashPassword(old)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	p := Policy{HistoryCount: 3}
	if err := p.CheckHistory(old, []string{hash}); !errors.Is(err, ErrPolicyReused) {
		t.Fatalf("want ErrPolicyReused, got %v", err)
	}
	if err := p.CheckHistory("FreshP@ssw0rd1", []string{hash}); err != nil {
		t.Fatalf("want nil for fresh password, got %v", err)
	}
}

func TestCheckHistory_EmptyHashesIgnored(t *testing.T) {
	p := Policy{HistoryCount: 3}
	if err := p.CheckHistory("anything", []string{"", ""}); err != nil {
		t.Fatalf("want nil with empty history, got %v", err)
	}
}
