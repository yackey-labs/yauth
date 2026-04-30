// Package auth provides cryptographic primitives shared by all yauth-go
// plugins: Argon2id password hashing, session-token generation/hashing, and
// HTTP cookie construction. It is a leaf package — it depends only on the
// standard library, golang.org/x/crypto, and the module's own domain/repo
// packages, so it can be imported safely from anywhere without creating a
// cycle through the root yauth package.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These match the OWASP "second recommended" profile
// (m=64MiB, t=1, p=4) and the parameter set used by the Rust reference
// implementation in yauth/crates/yauth/src/auth/password.rs (which relies on
// the argon2 crate's defaults).
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024 // 64 MiB, expressed in KiB
	argonThreads uint8  = 4
	argonSaltLen        = 16
	argonKeyLen  uint32 = 32
)

// ErrInvalidHash is returned when a PHC string cannot be parsed.
var ErrInvalidHash = errors.New("auth: invalid argon2id hash format")

// ErrIncompatibleVariant is returned when the PHC string is not argon2id.
var ErrIncompatibleVariant = errors.New("auth: incompatible argon2 variant")

// ErrIncompatibleVersion is returned when the PHC string version is not v=19.
var ErrIncompatibleVersion = errors.New("auth: incompatible argon2 version")

// rawStdEncoding is the encoding used by the reference argon2 PHC format:
// raw base64 (standard alphabet) without padding.
var rawStdEncoding = base64.RawStdEncoding

// HashPassword hashes the supplied password using Argon2id with the
// package-level parameters and returns a PHC-formatted string of the form:
//
//	$argon2id$v=19$m=65536,t=1,p=4$<base64salt>$<base64hash>
//
// Each call generates a fresh random salt; calling HashPassword twice with the
// same input produces different output.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read random salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonTime,
		argonThreads,
		rawStdEncoding.EncodeToString(salt),
		rawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword parses a PHC-encoded argon2id hash, recomputes the digest of
// the supplied password against the embedded salt and parameters, and returns
// true on a constant-time match. A non-nil error indicates a malformed or
// incompatible hash, not a failed verification.
func VerifyPassword(password, encoded string) (bool, error) {
	params, salt, want, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}

	got := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.threads,
		uint32(len(want)),
	)

	return subtle.ConstantTimeCompare(want, got) == 1, nil
}

// DummyVerify performs a constant-time Argon2id computation against a
// pre-computed dummy hash to mitigate user-enumeration timing attacks. It
// always returns false. Callers should invoke this on the user-not-found
// branch of a login flow so that the request takes roughly the same wall time
// as a real verification.
func DummyVerify(password string) bool {
	encoded := dummyHash()
	ok, _ := VerifyPassword(password, encoded)
	// By construction the dummy hash never matches a real password, but we
	// still guard here in the implausible case of a collision.
	return ok && false
}

// dummyHash lazily computes a hash of a random throwaway password the first
// time DummyVerify is called and caches the PHC string for the lifetime of the
// process. Lazy initialisation keeps program start-up cheap (Argon2id with
// 64MiB takes ~50ms on commodity hardware).
var (
	dummyOnce sync.Once
	dummyVal  string
)

func dummyHash() string {
	dummyOnce.Do(func() {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			// rand.Read failure is effectively unrecoverable; fall back to a
			// deterministic seed so DummyVerify still does the work.
			seed = []byte("yauth-dummy-fallback-seed-0123456")
		}
		h, err := HashPassword(string(seed))
		if err != nil {
			// Same fallback rationale: keep DummyVerify usable.
			h = "$argon2id$v=19$m=65536,t=1,p=4$" +
				rawStdEncoding.EncodeToString(make([]byte, argonSaltLen)) +
				"$" + rawStdEncoding.EncodeToString(make([]byte, argonKeyLen))
		}
		dummyVal = h
	})
	return dummyVal
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

// parsePHC parses an argon2id PHC string. The reference grammar is:
//
//	$argon2id$v=<version>$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>
//
// Salt and hash are raw standard base64 (no padding). Anything else is
// rejected with ErrInvalidHash.
func parsePHC(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// Leading "$" produces an empty first element, so we expect six parts.
	if len(parts) != 6 || parts[0] != "" {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return argonParams{}, nil, nil, ErrIncompatibleVariant
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return argonParams{}, nil, nil, ErrIncompatibleVersion
	}

	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	salt, err := rawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	hash, err := rawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	return p, salt, hash, nil
}
