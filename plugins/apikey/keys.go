package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Key format: <prefix-tag>_<8 hex prefix>_<32 hex secret>.
//
// The prefix-tag is the configurable Config.Prefix (default "yak"). The
// prefix is stored verbatim and used as the database lookup index. The
// secret is never stored — only its SHA-256 hex digest. On verification
// the incoming secret is hashed and compared to the stored hash with
// crypto/subtle.ConstantTimeCompare.
const (
	// prefixHexLen is the hex-encoded length of the random prefix (=4 bytes).
	prefixHexLen = 8
	// secretHexLen is the hex-encoded length of the random secret (=16 bytes).
	secretHexLen = 32

	prefixRandomBytes = prefixHexLen / 2
	secretRandomBytes = secretHexLen / 2
)

// GeneratedKey is the output of GenerateKey.
//
// ID is a fresh UUID-style identifier for the row (the caller assigns it
// because the plugin never imports uuid here — see handlers.go).
//
// Plaintext is the full "<prefix-tag>_<prefix>_<secret>" string returned
// to the caller exactly once (on creation). The server retains only Prefix
// and Hash.
type GeneratedKey struct {
	Prefix    string // 8 hex chars
	Secret    string // 32 hex chars (caller never sees this directly)
	Hash      string // sha256 hex of Secret
	Plaintext string // <prefixTag>_<Prefix>_<Secret>
}

// GenerateKey allocates a random 4-byte prefix and 16-byte secret, hex-
// encodes both, and returns the assembled plaintext key plus the SHA-256
// hex digest of the secret. The plaintext is shown to the user once; only
// the prefix and hash are persisted server-side.
func GenerateKey(prefixTag string) (GeneratedKey, error) {
	pBuf := make([]byte, prefixRandomBytes)
	if _, err := rand.Read(pBuf); err != nil {
		return GeneratedKey{}, fmt.Errorf("apikey: read prefix entropy: %w", err)
	}
	sBuf := make([]byte, secretRandomBytes)
	if _, err := rand.Read(sBuf); err != nil {
		return GeneratedKey{}, fmt.Errorf("apikey: read secret entropy: %w", err)
	}
	prefix := hex.EncodeToString(pBuf)
	secret := hex.EncodeToString(sBuf)
	return GeneratedKey{
		Prefix:    prefix,
		Secret:    secret,
		Hash:      hashSecret(secret),
		Plaintext: prefixTag + "_" + prefix + "_" + secret,
	}, nil
}

// hashSecret returns the canonical hex-encoded SHA-256 digest used for
// stored key_hash values.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ParseHeader splits a header value of the form "<prefixTag>_<prefix>_<secret>"
// into its prefix and secret components. It returns ok=false if the value
// is empty, malformed, or the prefix-tag does not match expectedTag.
//
// ParseHeader is permissive about case for the prefix-tag and strict about
// the hex character counts (8 + 32) so a lookup failure can be handled at
// the resolver layer rather than here.
func ParseHeader(value, expectedTag string) (prefix, secret string, ok bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	parts := strings.SplitN(value, "_", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	if !strings.EqualFold(parts[0], expectedTag) {
		return "", "", false
	}
	if len(parts[1]) != prefixHexLen || len(parts[2]) != secretHexLen {
		return "", "", false
	}
	if !isHex(parts[1]) || !isHex(parts[2]) {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// isHex reports whether s consists entirely of lowercase hex characters.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'f',
			c >= 'A' && c <= 'F':
			continue
		default:
			return false
		}
	}
	return true
}
