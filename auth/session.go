package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// IssueSession generates a fresh session token, persists a session row whose
// TokenHash is the SHA-256 of that token, and returns the raw token (to be
// placed in the cookie / response) along with the persisted session.
//
// The caller is responsible for any audit logging or event emission; this
// helper does the cryptographic and persistence work only.
//
// POLICY CAPS ARE OPT-IN, not automatic: IssueSession applies NO org policy.
// MaxSessionDuration / MaxConcurrentSessions are enforced ONLY by
// IssueSessionWithPolicy (pass an explicit *PolicyEnforcer). Every login
// path in the tree currently calls this plain variant, so stored org caps
// are returned by GET /organizations/{id}/policy but applied to no session
// yauth issues until each path is migrated. Known plain-IssueSession login
// call sites (audit of 2026-11-01; re-grep `IssueSession\(` when migrating):
// plugins/emailpassword/handlers.go (login, password-change re-issue,
// admin reset), plugins/magiclink, plugins/mfa, plugins/oauth,
// plugins/passkey, plugins/ssooidc/handlers_login.go,
// plugins/ssosaml/handlers_login.go, plugins/admin impersonation.
// There is no single choke to wire: a user may belong to several orgs with
// different caps, and turning a stored cap into a live one is a behavioural
// change for deployments that set it decoratively. See
// docs/org-policy-enforcement.md. New login paths MUST call
// IssueSessionWithPolicy; migrating the list above is tracked work, not
// part of this helper's contract.
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

// IssueSessionWithPolicy is the policy-aware variant of IssueSession and
// the DOCUMENTED CHOKE for session-create enforcement (port of yauth Rust
// #92 / yauth-go #21).
//
// NOTHING IN YAUTH CALLS THIS YET (see the IssueSession caller registry
// above: every login path calls plain IssueSession), so an organization's
// max_session_duration_secs and max_concurrent_sessions are stored and
// returned by GET /organizations/{id}/policy but applied to no session
// yauth issues. The caps are therefore OPT-IN per call site until the
// migration lands: pass the request's governing org enforcer explicitly.
// A nil enforcer behaves identically to IssueSession.
//
// Wiring it is not a drop-in swap: a user may belong to several orgs with
// different caps, and turning a stored cap into a live one is a
// behavioural change for deployments that have been setting it
// decoratively. See docs/org-policy-enforcement.md.
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
