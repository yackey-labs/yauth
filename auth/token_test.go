package auth

import (
	"encoding/base64"
	"testing"
)

func TestGenerateSessionToken(t *testing.T) {
	raw, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	if raw == "" {
		t.Fatalf("expected non-empty raw token")
	}
	if hash == "" {
		t.Fatalf("expected non-empty hash")
	}

	// Raw value should decode as base64url with no padding and yield 32 bytes.
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("raw token is not base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 random bytes, got %d", len(decoded))
	}

	// SHA-256 hex is 64 chars.
	if len(hash) != 64 {
		t.Fatalf("expected 64-char hex hash, got %d (%q)", len(hash), hash)
	}

	// HashToken must be deterministic and match the hash returned by the
	// generator — that's the contract that lets the middleware look sessions
	// up by hashing the cookie value.
	if got := HashToken(raw); got != hash {
		t.Fatalf("HashToken(raw)=%q, want %q", got, hash)
	}
}

func TestGenerateSessionToken_Unique(t *testing.T) {
	a, _, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	b, _, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	if a == b {
		t.Fatalf("expected unique tokens, got duplicate %q", a)
	}
}

func TestHashToken_Stable(t *testing.T) {
	const raw = "abc123"
	first := HashToken(raw)
	second := HashToken(raw)
	if first != second {
		t.Fatalf("HashToken not deterministic")
	}
	if HashToken(raw) == HashToken(raw+"x") {
		t.Fatalf("HashToken collisions on distinct inputs")
	}
}
