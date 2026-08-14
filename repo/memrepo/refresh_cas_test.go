package memrepo

// RevokeRefreshToken is the write half of refresh-token rotation, and it is
// not a compare-and-swap. Both implementations set revoked unconditionally —
// memrepo's `t.Revoked = true` here, and pgxrepo's
// `UPDATE yauth_refresh_tokens SET revoked = true WHERE id = $1` — so the
// SECOND caller to revoke the same row is told it succeeded, exactly like the
// first. Rotation in plugins/bearer and plugins/oauth2server reads the row,
// tests Revoked in Go, and then calls this method, so two callers racing on
// one token both believe they rotated it and the family forks.
//
// The sibling statement, RevokeRefreshTokenFamily, already narrows on
// `revoked = false` and returns a count, which is exactly the shape this needs:
// the loser of the race must be able to see that it lost.
//
// POSITIVE CONTROL: TestRevokeRefreshToken_FirstCallStillRevokes proves the
// legitimate first revocation keeps working and keeps setting the flag, so a
// fix cannot pass by refusing every revocation.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

func seedRefreshRow(t *testing.T, r *Repo, id, familyID string) string {
	t.Helper()
	now := time.Now().UTC()
	hash := "hash-" + id
	if err := r.CreateRefreshToken(context.Background(), domain.NewRefreshToken{
		ID:        id,
		UserID:    "user-1",
		TokenHash: hash,
		FamilyID:  familyID,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	return hash
}

// TestRevokeRefreshToken_IsCompareAndSwap is the regression: revoking an
// already-revoked row must report that it changed nothing, so the caller can
// tell rotation from a collision.
func TestRevokeRefreshToken_IsCompareAndSwap(t *testing.T) {
	r := New()
	seedRefreshRow(t, r, "tok-1", "fam-1")

	if err := r.RevokeRefreshToken(context.Background(), "tok-1"); err != nil {
		t.Fatalf("first revoke must succeed: %v", err)
	}
	err := r.RevokeRefreshToken(context.Background(), "tok-1")
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Errorf("revoking an already-revoked refresh token returned %v; it must return ErrNotFound so a losing rotation can detect the collision and trip reuse detection", err)
	}
}

// TestRevokeRefreshToken_FirstCallStillRevokes is the POSITIVE CONTROL.
func TestRevokeRefreshToken_FirstCallStillRevokes(t *testing.T) {
	r := New()
	hash := seedRefreshRow(t, r, "tok-2", "fam-2")

	if err := r.RevokeRefreshToken(context.Background(), "tok-2"); err != nil {
		t.Fatalf("first revoke must succeed: %v", err)
	}
	got, err := r.GetRefreshTokenByHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if !got.Revoked {
		t.Fatalf("first revoke did not set revoked")
	}

	// An unknown id is still ErrNotFound, and the family sweep — which already
	// narrows on revoked = false — is unaffected.
	if err := r.RevokeRefreshToken(context.Background(), "no-such-token"); !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("unknown id must be ErrNotFound, got %v", err)
	}
	seedRefreshRow(t, r, "tok-3", "fam-2")
	n, err := r.RevokeRefreshTokenFamily(context.Background(), "fam-2")
	if err != nil {
		t.Fatalf("RevokeRefreshTokenFamily: %v", err)
	}
	if n != 1 {
		t.Fatalf("family sweep should have revoked exactly the one live row, got %d", n)
	}
}
