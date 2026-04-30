package oauth

import (
	"crypto/rand"
	"strings"
	"testing"
)

func newKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestEncryptToken_RoundTrip(t *testing.T) {
	k := newKey(t)
	for _, tc := range []string{
		"",
		"short",
		"a longer access token with spaces and symbols !@#$%^&*()",
		strings.Repeat("x", 4096),
	} {
		ct, err := encryptToken(k, tc)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := decryptToken(k, ct)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != tc {
			t.Fatalf("round trip mismatch: want %q, got %q", tc, got)
		}
	}
}

func TestEncryptToken_WrongKey(t *testing.T) {
	k1 := newKey(t)
	k2 := newKey(t)
	ct, err := encryptToken(k1, "secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptToken(k2, ct); err == nil {
		t.Fatalf("decrypt with wrong key: expected error, got nil")
	}
}

func TestEncryptToken_TamperedCiphertext(t *testing.T) {
	k := newKey(t)
	ct, err := encryptToken(k, "hello")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Mangle the last char (the auth tag).
	mangled := ct[:len(ct)-1] + "A"
	if mangled == ct {
		mangled = ct[:len(ct)-1] + "B"
	}
	if _, err := decryptToken(k, mangled); err == nil {
		t.Fatalf("decrypt tampered: expected error, got nil")
	}
}

func TestEncryptToken_NonceFreshness(t *testing.T) {
	k := newKey(t)
	a, err := encryptToken(k, "same plaintext")
	if err != nil {
		t.Fatalf("encrypt a: %v", err)
	}
	b, err := encryptToken(k, "same plaintext")
	if err != nil {
		t.Fatalf("encrypt b: %v", err)
	}
	if a == b {
		t.Fatalf("two encryptions of the same plaintext produced identical ciphertext (nonce reuse?)")
	}
}

func TestDecryptToken_BadBase64(t *testing.T) {
	k := newKey(t)
	if _, err := decryptToken(k, "not!base!64!"); err == nil {
		t.Fatalf("decrypt bad base64: expected error, got nil")
	}
}

func TestDecryptToken_TooShort(t *testing.T) {
	k := newKey(t)
	if _, err := decryptToken(k, "AAAA"); err == nil {
		t.Fatalf("decrypt too-short: expected error, got nil")
	}
}
