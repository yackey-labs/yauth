// Package passwordpolicy validates passwords against a configurable
// complexity policy: minimum / maximum length, required character
// classes, common-password rejection, and reuse history.
//
// Policy.Check returns an error describing the first violation; the
// returned error wraps one of the package's sentinel errors
// (ErrPolicyTooShort, ErrPolicyTooLong, ErrPolicyMissingUpper,
// ErrPolicyMissingLower, ErrPolicyMissingDigit, ErrPolicyMissingSpecial,
// ErrPolicyCommon) so callers can branch with errors.Is.
//
// CheckHistory verifies a candidate password is not present in a
// supplied list of recent password hashes. It uses argon2id verify
// against each hash, so the hashes must be the PHC-formatted strings
// produced by auth.HashPassword.
package passwordpolicy

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/yackey-labs/yauth-go/auth"
)

// Sentinel errors returned (wrapped) by Policy.Check.
var (
	ErrPolicyTooShort       = errors.New("password too short")
	ErrPolicyTooLong        = errors.New("password too long")
	ErrPolicyMissingUpper   = errors.New("password missing uppercase letter")
	ErrPolicyMissingLower   = errors.New("password missing lowercase letter")
	ErrPolicyMissingDigit   = errors.New("password missing digit")
	ErrPolicyMissingSpecial = errors.New("password missing special character")
	ErrPolicyCommon         = errors.New("password is too common")
	ErrPolicyReused         = errors.New("password matches a recently used password")
)

// Policy is the set of complexity rules enforced by Check. Zero value
// imposes no rules; populate fields to enable the corresponding check.
type Policy struct {
	MinLength      int
	MaxLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
	DisallowCommon bool

	// HistoryCount is the number of most-recent password hashes to
	// match against in CheckHistory. The repository decides which N
	// hashes to return; this field is informational here and used by
	// callers to size their query.
	HistoryCount int
}

// Check validates password against the policy and returns nil on
// success or a wrapped sentinel error on the first violation
// encountered. Callers that want every violation in one pass should
// use Violations.
func (p Policy) Check(password string) error {
	if errs := p.Violations(password); len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Violations returns every violation found in password, in declaration
// order. An empty slice means the password satisfies the policy.
func (p Policy) Violations(password string) []error {
	var out []error
	if p.MinLength > 0 && len(password) < p.MinLength {
		out = append(out, fmt.Errorf("%w: must be at least %d characters", ErrPolicyTooShort, p.MinLength))
	}
	if p.MaxLength > 0 && len(password) > p.MaxLength {
		out = append(out, fmt.Errorf("%w: must be at most %d characters", ErrPolicyTooLong, p.MaxLength))
	}
	if p.RequireUpper && !containsRune(password, unicode.IsUpper) {
		out = append(out, ErrPolicyMissingUpper)
	}
	if p.RequireLower && !containsRune(password, unicode.IsLower) {
		out = append(out, ErrPolicyMissingLower)
	}
	if p.RequireDigit && !containsRune(password, unicode.IsDigit) {
		out = append(out, ErrPolicyMissingDigit)
	}
	if p.RequireSpecial && !containsRune(password, isSpecial) {
		out = append(out, ErrPolicyMissingSpecial)
	}
	if p.DisallowCommon && IsCommonPassword(password) {
		out = append(out, ErrPolicyCommon)
	}
	return out
}

// CheckHistory returns ErrPolicyReused (wrapped) if password matches
// any hash in history. history is expected to be the PHC-encoded
// argon2id hashes produced by auth.HashPassword. A nil/empty history
// always succeeds.
func (p Policy) CheckHistory(password string, history []string) error {
	for _, h := range history {
		if h == "" {
			continue
		}
		ok, err := auth.VerifyPassword(password, h)
		if err != nil {
			// Bad hash in history — skip rather than failing closed.
			continue
		}
		if ok {
			return ErrPolicyReused
		}
	}
	return nil
}

func containsRune(s string, pred func(rune) bool) bool {
	for _, r := range s {
		if pred(r) {
			return true
		}
	}
	return false
}

// isSpecial mirrors the Rust definition: any ASCII non-alphanumeric
// character. Non-ASCII runes do not satisfy the requirement so users
// stay portable across keyboards.
func isSpecial(r rune) bool {
	if r > unicode.MaxASCII {
		return false
	}
	return !unicode.IsLetter(r) && !unicode.IsDigit(r)
}

//go:embed common.txt
var commonRaw string

// commonSet is the canonicalised lookup table of common passwords.
// Entries are lower-cased.
var commonSet = func() map[string]struct{} {
	m := make(map[string]struct{}, 128)
	for _, line := range strings.Split(commonRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = struct{}{}
	}
	return m
}()

// IsCommonPassword reports whether password (case-insensitive) is in
// the embedded common-passwords list.
func IsCommonPassword(password string) bool {
	_, ok := commonSet[strings.ToLower(password)]
	return ok
}
