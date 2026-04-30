package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
)

// IssueSession generates a fresh session token, persists a session row whose
// TokenHash is the SHA-256 of that token, and returns the raw token (to be
// placed in the cookie / response) along with the persisted session.
//
// The caller is responsible for any audit logging or event emission; this
// helper does the cryptographic and persistence work only.
func IssueSession(
	ctx context.Context,
	sessions repo.SessionRepository,
	userID string,
	ip *string,
	ua *string,
	ttl time.Duration,
) (string, *domain.Session, error) {
	raw, hash, err := GenerateSessionToken()
	if err != nil {
		return "", nil, fmt.Errorf("auth: generate session token: %w", err)
	}

	now := time.Now().UTC()
	sess := domain.Session{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: hash,
		IPAddress: ip,
		UserAgent: ua,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}

	input := domain.NewSession{
		ID:        sess.ID,
		UserID:    sess.UserID,
		TokenHash: sess.TokenHash,
		IPAddress: sess.IPAddress,
		UserAgent: sess.UserAgent,
		ExpiresAt: sess.ExpiresAt,
		CreatedAt: sess.CreatedAt,
	}
	if err := sessions.CreateSession(ctx, input); err != nil {
		return "", nil, fmt.Errorf("auth: persist session: %w", err)
	}

	return raw, &sess, nil
}
