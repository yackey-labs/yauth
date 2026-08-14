package passwordpolicy

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// This generator used to live in package yauth (bootstrap_admin.go) where it
// served exactly one caller: the startup bootstrap admin. plugins/admin needed
// the same thing for the temp password POST /admin/users hands back, but a
// plugin cannot import package yauth (cycle), so it grew a second, worse
// generator of its own — a 24-char alphabet with NO special character, sized
// independently of the configured MinLength/MaxLength, and indexed with a
// modulo-biased `alphabet[b[i]%len(alphabet)]`. The result was a server that
// issued a credential its own configured policy rejects.
//
// Moving the correct generator down to auth/passwordpolicy — which both
// package yauth and plugins/admin already depend on — is what lets the second
// one be deleted rather than patched. Behaviour is unchanged from the yauth
// original; only the package moved.

// Character classes for generated passwords. Special chars are restricted to a
// shell/URL-safe subset so an operator copying a generated password out of a
// terminal (or an admin pasting the one-time password into a form) can't be
// tripped up by quoting.
const (
	bsUpper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	bsLower   = "abcdefghijkmnopqrstuvwxyz"
	bsDigit   = "23456789"
	bsSpecial = "!@#$%^*-_=+"
	bsAll     = bsUpper + bsLower + bsDigit + bsSpecial
)

// Generate returns a cryptographically-random password that satisfies p by
// construction: it always includes at least one upper, lower, digit, and
// special character (covering RequireUpper/Lower/Digit/Special regardless of
// which are set), and is long enough for MinLength (with a 20-char floor). It
// then verifies against the policy and retries a few times defensively. A
// random password is never in the common-password list and (being random) is
// never an HIBP breach hit.
//
// The zero Policy therefore yields a 20-character password from the full
// alphabet — the safe default for a caller that has no configured policy.
func Generate(p Policy) (string, error) {
	length := p.MinLength
	if length < 20 {
		length = 20
	}
	if p.MaxLength > 0 && length > p.MaxLength {
		length = p.MaxLength
	}
	// Need room for the four guaranteed class characters.
	if length < 4 {
		length = 4
	}

	for attempt := 0; attempt < 8; attempt++ {
		pw, err := randomPassword(length)
		if err != nil {
			return "", err
		}
		if p.Check(pw) == nil {
			return pw, nil
		}
	}
	return "", errors.New("could not generate a policy-compliant password after 8 attempts")
}

// randomPassword builds a length-n password guaranteeing one char from each
// class, then filling the remainder from the full alphabet, and finally
// shuffling so the guaranteed characters aren't positionally predictable.
func randomPassword(n int) (string, error) {
	out := make([]byte, 0, n)
	// Guarantee one of each class.
	for _, class := range []string{bsUpper, bsLower, bsDigit, bsSpecial} {
		c, err := randomChar(class)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	for len(out) < n {
		c, err := randomChar(bsAll)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	if err := shuffle(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// randomChar draws one character from set using rejection sampling
// (crypto/rand.Int), so every symbol is equally likely — unlike a `%len(set)`
// reduction of a random byte, which favours the first 256%len(set) symbols.
func randomChar(set string) (byte, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[idx.Int64()], nil
}

// shuffle performs an in-place Fisher–Yates shuffle using crypto/rand.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		jb, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(jb.Int64())
		b[i], b[j] = b[j], b[i]
	}
	return nil
}
