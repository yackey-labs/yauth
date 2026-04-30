package mfa

import (
	"crypto/rand"
	"strings"
	"testing"
)

func randKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := randKey(t)
	plaintext := "JBSWY3DPEHPK3PXP" // a sample base32 TOTP secret
	ct, err := encryptSecret(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct == plaintext {
		t.Fatalf("ciphertext equals plaintext")
	}
	pt, err := decryptSecret(key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt != plaintext {
		t.Fatalf("plaintext mismatch: got %q want %q", pt, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := randKey(t)
	a, err := encryptSecret(key, "secret")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := encryptSecret(key, "secret")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Fatalf("expected distinct ciphertexts (random nonce), got identical: %s", a)
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	key := randKey(t)
	ct, err := encryptSecret(key, "hello")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// flip a character to corrupt the base64 payload
	tampered := strings.Replace(ct, ct[len(ct)-2:], "AA", 1)
	if tampered == ct {
		t.Fatalf("tamper produced identical input")
	}
	if _, err := decryptSecret(key, tampered); err == nil {
		t.Fatalf("expected decryption error on tampered ciphertext")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	k1 := randKey(t)
	k2 := randKey(t)
	ct, err := encryptSecret(k1, "hello")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptSecret(k2, ct); err == nil {
		t.Fatalf("expected decryption to fail with wrong key")
	}
}
