// crypto.go — AES-256-GCM helpers for encrypting IdP client_secrets at
// rest. Format-compatible with plugins/oauth/crypto.go and
// plugins/mfa/crypto.go (same base64(nonce||sealed) layout) so deployments
// using all three can share a single key without churning ciphertexts.
package ssooidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func encryptString(key [32]byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("ssooidc: aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("ssooidc: new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("ssooidc: read nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func decryptString(key [32]byte, b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("ssooidc: base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("ssooidc: aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("ssooidc: new gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ssooidc: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("ssooidc: gcm open: %w", err)
	}
	return string(pt), nil
}
