package webhooks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// encPrefix tags ciphertexts stored in the database so the dispatcher
// can distinguish encrypted secrets from legacy plaintext ones.
const encPrefix = "$enc:v1$"

// deriveWebhookKey derives a 32-byte AES-256 key from jwtSecret using
// HKDF-SHA256. Returns nil when jwtSecret is empty (no-op mode).
func deriveWebhookKey(jwtSecret []byte) []byte {
	if len(jwtSecret) == 0 {
		return nil
	}
	r := hkdf.New(sha256.New, jwtSecret, nil, []byte("yauth:webhook:secret:v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil
	}
	return key
}

// encryptSecret encrypts plaintext using AES-256-GCM and returns a
// tagged base64 string. When key is nil the plaintext is returned as-is
// for backward compatibility.
func encryptSecret(key []byte, plaintext string) (string, error) {
	if len(key) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptSecret reverses encryptSecret. Strings without the prefix are
// returned unchanged (transparent plaintext pass-through for any rows
// stored before encryption was enabled).
func decryptSecret(key []byte, stored string) (string, error) {
	if !strings.HasPrefix(stored, encPrefix) {
		return stored, nil // legacy plaintext
	}
	if len(key) == 0 {
		return "", errors.New("webhooks: encrypted secret but no decryption key configured")
	}
	b, err := base64.StdEncoding.DecodeString(stored[len(encPrefix):])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(b) < ns {
		return "", errors.New("webhooks: ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, b[:ns], b[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
