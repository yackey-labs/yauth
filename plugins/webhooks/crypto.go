package webhooks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// encPrefix tags ciphertexts stored in the database so the dispatcher
// can distinguish encrypted secrets from legacy plaintext ones.
const encPrefix = "$enc:v1$"

// ErrNoEncryptionKey is returned by encryptSecret when no key material is
// available. It is deliberately an error and not a fallback: a webhook signing
// secret is the only thing standing between a reader of yauth_webhooks and the
// ability to forge a signed delivery to every endpoint the deployment trusts,
// so "store it in the clear" is never the right answer to "we have no key".
var ErrNoEncryptionKey = errors.New("webhooks: no encryption key configured — cannot store a webhook signing secret; set webhooks.Config.EncryptionKey or configure a JWT secret (yauth.Builder.WithJWTSecret / the bearer plugin)")

// deriveWebhookKey derives a 32-byte AES-256 key from secret using
// HKDF-SHA256. Returns nil when secret is empty — the caller MUST treat a nil
// key as "cannot store secrets" rather than as plaintext mode.
//
// Both key sources (webhooks.Config.EncryptionKey and PluginHost.JWTSecret)
// run through the same derivation with the same info string, so rotating the
// JWT secret rotates the webhook key exactly as it always has, and pointing
// Config.EncryptionKey at the same bytes yields the same key.
func deriveWebhookKey(secret []byte) []byte {
	if len(secret) == 0 {
		return nil
	}
	r := hkdf.New(sha256.New, secret, nil, []byte("yauth:webhook:secret:v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil
	}
	return key
}

// encryptSecret encrypts plaintext using AES-256-GCM and returns a
// tagged base64 string.
//
// An empty key returns ErrNoEncryptionKey. It used to return the plaintext
// unchanged, which meant a deployment running webhooks WITHOUT the bearer
// plugin — the only thing that populates PluginHost.JWTSecret — persisted
// every 32-byte HMAC signing secret to yauth_webhooks.secret in cleartext,
// with no warning at any point and no way to tell from the row that it had
// happened. Refusing here is what makes that path impossible to hit unnoticed.
func encryptSecret(key []byte, plaintext string) (string, error) {
	if len(key) == 0 {
		return "", ErrNoEncryptionKey
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

// isEncrypted reports whether a stored secret carries the ciphertext tag.
// Anything else is legacy plaintext, written either before encryption existed
// or by a build that still fell back to it.
func isEncrypted(stored string) bool { return strings.HasPrefix(stored, encPrefix) }

// decryptSecret reverses encryptSecret. Strings without the prefix are
// returned unchanged and flagged legacy=true.
//
// The pass-through has to stay — rows written before encryption existed must
// keep delivering — but it is no longer a silent one. legacy=true is what the
// startup sweep (migrateLegacySecrets) re-encrypts and what the dispatcher
// warns about if it ever meets a plaintext row after that sweep has run.
func decryptSecret(key []byte, stored string) (plaintext string, legacy bool, err error) {
	if !isEncrypted(stored) {
		return stored, true, nil
	}
	if len(key) == 0 {
		return "", false, errors.New("webhooks: encrypted secret but no decryption key configured")
	}
	b, err := base64.StdEncoding.DecodeString(stored[len(encPrefix):])
	if err != nil {
		return "", false, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false, err
	}
	ns := gcm.NonceSize()
	if len(b) < ns {
		return "", false, errors.New("webhooks: ciphertext too short")
	}
	opened, err := gcm.Open(nil, b[:ns], b[ns:], nil)
	if err != nil {
		return "", false, err
	}
	return string(opened), false, nil
}

// migrateLegacySecrets re-encrypts every webhook row whose secret is still
// stored in cleartext, and returns how many it rewrote.
//
// Encryption arrived after webhooks did, and the read path pass-through meant
// a row written before it (or written by the plaintext-fallback bug this
// commit removes) stayed in cleartext forever, even once key material showed
// up. This runs at plugin start whenever a key IS available, so the fix
// applies to the rows already on disk rather than only to future writes.
//
// It is idempotent and safe to run concurrently on several replicas: two
// replicas racing on the same row write two different ciphertexts of the same
// secret, and both decrypt to it. Errors are returned for the caller to log —
// an unreachable webhook table must not stop the process from booting.
func migrateLegacySecrets(ctx context.Context, r repo.Repository, key []byte) (migrated int, err error) {
	if len(key) == 0 {
		return 0, nil
	}
	hooks, err := r.ListWebhooks(ctx)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	var firstErr error
	for _, h := range hooks {
		// An empty secret used to be skipped here, which made the one row shape
		// that produces an unsigned delivery also the one shape the normalising
		// sweep refused to look at. Because decryptSecret reports any untagged
		// value as legacy=true, such a row additionally made the dispatcher log
		// "stored in CLEARTEXT, rotate it" on EVERY delivery, forever, about a
		// secret that does not exist. encryptSecret seals an empty plaintext
		// fine and decryptSecret round-trips it to ("", legacy=false), which
		// silences the bogus warning and leaves no un-normalised row behind.
		if h == nil || isEncrypted(h.Secret) {
			continue
		}
		enc, encErr := encryptSecret(key, h.Secret)
		if encErr != nil {
			if firstErr == nil {
				firstErr = encErr
			}
			continue
		}
		if _, upErr := r.UpdateWebhook(ctx, h.ID, domain.UpdateWebhook{Secret: &enc, UpdatedAt: &now}); upErr != nil {
			if firstErr == nil {
				firstErr = upErr
			}
			continue
		}
		migrated++
	}
	return migrated, firstErr
}
