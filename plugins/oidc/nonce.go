package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// ErrNonceReplay is returned by RecordNonce when the supplied nonce
// has already been recorded for a different authorization code (or
// when a record exists at all — the repo enforces single-use).
var ErrNonceReplay = errors.New("oidc: nonce replay detected")

// HashNonce returns the hex-encoded SHA-256 of the supplied raw nonce.
// Storing only the hash matches the existing yauth pattern for token
// material (sessions, refresh tokens, magic links).
func HashNonce(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// RecordNonce persists the hash of nonce against authorizationCodeID,
// rejecting any subsequent attempt to record the same nonce hash. It
// is safe to invoke from the oauth2-server's authorization-code
// issuance path: the unique-hash constraint on the underlying table
// guarantees replay protection across processes.
func RecordNonce(ctx context.Context, r repo.OIDCNonceRepository, nonce, authorizationCodeID string) error {
	if nonce == "" {
		return nil
	}
	hash := HashNonce(nonce)
	if existing, err := r.GetOIDCNonceByHash(ctx, hash); err == nil && existing != nil {
		return ErrNonceReplay
	} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		return err
	}
	return r.CreateOIDCNonce(ctx, domain.NewOIDCNonce{
		ID:                  uuid.NewString(),
		NonceHash:           hash,
		AuthorizationCodeID: authorizationCodeID,
		CreatedAt:           time.Now().UTC(),
	})
}

// CheckNonce reports whether nonce has already been recorded. It is a
// read-only complement to RecordNonce, useful for id_token validation
// paths that want to fail early before invoking the repo writer.
func CheckNonce(ctx context.Context, r repo.OIDCNonceRepository, nonce string) (bool, error) {
	if nonce == "" {
		return false, nil
	}
	hash := HashNonce(nonce)
	rec, err := r.GetOIDCNonceByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return rec != nil, nil
}
