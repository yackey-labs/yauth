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

// IssueSessionWithPolicy is the policy-aware variant of IssueSession.
// Port of yauth Rust #92 / yauth-go #21 session-create enforcement.
//
// Behaviour:
//
//   - Clamps ttl to the enforcer's effective max-session-duration.
//   - When max_concurrent_sessions is set, revokes the user's oldest
//     sessions until the post-create live count is at or below the
//     cap. "Oldest" is by CreatedAt; ties are broken by id so the
//     ordering is total + stable. Prune happens AFTER the new row is
//     persisted so the new session always survives the cap.
//
// A nil enforcer behaves identically to IssueSession.
func IssueSessionWithPolicy(
	ctx context.Context,
	sessions repo.SessionRepository,
	userID string,
	ip *string,
	ua *string,
	ttl time.Duration,
	enforcer *PolicyEnforcer,
) (string, *domain.Session, error) {
	clampedTTL := ttl
	if enforcer != nil {
		clampedTTL = enforcer.ClampSessionTTL(ttl)
	}

	raw, sess, err := IssueSession(ctx, sessions, userID, ip, ua, clampedTTL)
	if err != nil {
		return "", nil, err
	}

	if enforcer != nil {
		if cap := enforcer.MaxConcurrentSessions(); cap > 0 {
			if err := pruneOldestSessions(ctx, sessions, userID, cap); err != nil {
				return raw, sess, fmt.Errorf("auth: prune concurrent sessions: %w", err)
			}
		}
	}

	return raw, sess, nil
}

// pruneOldestSessions deletes the user's oldest sessions until the
// remaining count is at or below cap. Idempotent on cap=0.
func pruneOldestSessions(ctx context.Context, sessions repo.SessionRepository, userID string, cap int) error {
	if cap <= 0 {
		return nil
	}
	uid := userID
	rows, _, err := sessions.ListSessions(ctx, domain.ListSessionsFilters{UserID: &uid, Limit: 0})
	if err != nil {
		return err
	}
	if len(rows) <= cap {
		return nil
	}
	sortSessionsNewestFirst(rows)
	for _, s := range rows[cap:] {
		if s == nil {
			continue
		}
		if err := sessions.DeleteSessionByID(ctx, s.ID); err != nil {
			return err
		}
	}
	return nil
}

func sortSessionsNewestFirst(rows []*domain.Session) {
	// Insertion sort — typical user has <10 sessions; the simpler
	// algorithm avoids pulling in sort just for this.
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && sessionNewer(rows[j], rows[j-1]) {
			rows[j], rows[j-1] = rows[j-1], rows[j]
			j--
		}
	}
}

func sessionNewer(a, b *domain.Session) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	if a.CreatedAt.Equal(b.CreatedAt) {
		return a.ID > b.ID
	}
	return a.CreatedAt.After(b.CreatedAt)
}
