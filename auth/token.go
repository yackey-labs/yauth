package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// sessionTokenBytes is the entropy budget for raw session tokens. 32 random
// bytes encoded as base64url is 43 characters, well above the 128-bit minimum
// recommended for opaque session identifiers.
const sessionTokenBytes = 32

// GenerateSessionToken produces a fresh session token. The first return value
// (raw) is the base64url-encoded token suitable for placing in a Set-Cookie
// header or returning in an API response. The second return value (hash) is
// the SHA-256 hex digest of the raw token; this is what should be persisted
// alongside the session row so that a database leak does not yield usable
// credentials.
func GenerateSessionToken() (string, string, error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("auth: read random token: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashToken(raw), nil
}

// HashToken returns the canonical hex-encoded SHA-256 digest of a raw session
// token. Use this on every authenticated request to look up the session by
// hash instead of by raw value.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
