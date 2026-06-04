package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// seedRefreshToken inserts a refresh token for userID and returns its raw value
// (so the test can look it up by hash) — used to prove the kill switch revokes
// refresh tokens, not just sessions.
func (e *testEnv) seedRefreshToken(t *testing.T, userID string) string {
	t.Helper()
	raw := uuid.NewString() + uuid.NewString()
	now := time.Now().UTC()
	if err := e.repo.CreateRefreshToken(context.Background(), domain.NewRefreshToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: auth.HashToken(raw),
		FamilyID:  uuid.NewString(),
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	return raw
}

func (e *testEnv) targetHasSession(t *testing.T, userID string) bool {
	t.Helper()
	left, _, err := e.repo.ListSessions(context.Background(), domain.ListSessionsFilters{Limit: 200})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	for _, s := range left {
		if s.UserID == userID {
			return true
		}
	}
	return false
}

// TestAdmin_SuspendUnsuspend proves the offboarding kill switch: suspend sets
// suspended_at, terminates the user's sessions AND revokes their refresh
// tokens, and unsuspend reverses the suspension.
func TestAdmin_SuspendUnsuspend(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	// Pre-existing session + refresh token — both must be killed on suspend.
	_ = env.issueSession(t, target.ID)
	rawRefresh := env.seedRefreshToken(t, target.ID)
	tok := env.issueSession(t, admin.ID)

	if !env.targetHasSession(t, target.ID) {
		t.Fatalf("precondition: target should have a session")
	}

	// Suspend.
	res := env.do(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/suspend", tok, map[string]any{
		"reason": "offboarded",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("suspend: %d (%s)", res.StatusCode, drain(res))
	}
	var suspended struct {
		Suspended       bool       `json:"suspended"`
		SuspendedAt     *time.Time `json:"suspended_at"`
		SuspendedReason *string    `json:"suspended_reason"`
	}
	if err := json.NewDecoder(res.Body).Decode(&suspended); err != nil {
		t.Fatalf("decode suspend: %v", err)
	}
	res.Body.Close()
	if !suspended.Suspended || suspended.SuspendedAt == nil {
		t.Fatalf("expected suspended=true with timestamp, got %+v", suspended)
	}
	if suspended.SuspendedReason == nil || *suspended.SuspendedReason != "offboarded" {
		t.Fatalf("expected suspended_reason=offboarded, got %v", suspended.SuspendedReason)
	}

	// Kill switch: sessions gone.
	if env.targetHasSession(t, target.ID) {
		t.Fatalf("expected target's sessions revoked after suspend")
	}
	// Kill switch: refresh token revoked.
	rt, err := env.repo.GetRefreshTokenByHash(context.Background(), auth.HashToken(rawRefresh))
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	if !rt.Revoked {
		t.Fatalf("expected refresh token revoked after suspend")
	}

	// Unsuspend.
	res = env.do(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/unsuspend", tok, struct{}{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unsuspend: %d (%s)", res.StatusCode, drain(res))
	}
	var reactivated struct {
		Suspended   bool       `json:"suspended"`
		SuspendedAt *time.Time `json:"suspended_at"`
	}
	if err := json.NewDecoder(res.Body).Decode(&reactivated); err != nil {
		t.Fatalf("decode unsuspend: %v", err)
	}
	res.Body.Close()
	if reactivated.Suspended || reactivated.SuspendedAt != nil {
		t.Fatalf("expected suspended cleared, got %+v", reactivated)
	}
}

// TestAdmin_SuspendedSessionRejected proves enforcement at the cookie path:
// once a user is suspended, an existing session cookie is rejected on the next
// request (instant termination for browser sessions).
func TestAdmin_SuspendedSessionRejected(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	// A suspended admin: gives us a protected route (admin gate) to probe, and
	// proves the middleware rejects the cookie regardless of role.
	victim := env.seedUser(t, "victim@example.com", "admin")
	cookie := env.issueSession(t, victim.ID)

	// Sanity: the session works before suspension.
	res := env.do(t, http.MethodGet, "/api/auth/admin/users", cookie, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("precondition: expected 200 before suspend, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Suspend directly in the repo so the session cookie survives (the admin
	// endpoint would delete it); we want to prove the *middleware* rejects a
	// live cookie for a suspended user, not just that the kill switch ran.
	now := time.Now().UTC()
	nowPtr := &now
	reason := "offboarded"
	reasonPtr := &reason
	if _, err := env.repo.UpdateUser(context.Background(), victim.ID, domain.UpdateUser{
		SuspendedAt:     &nowPtr,
		SuspendedReason: &reasonPtr,
		UpdatedAt:       &now,
	}); err != nil {
		t.Fatalf("suspend in repo: %v", err)
	}

	res = env.do(t, http.MethodGet, "/api/auth/admin/users", cookie, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for suspended user's cookie, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestAdmin_ScheduleStart proves staged onboarding: a future activates_at marks
// the user not-yet-started, and the cookie path rejects them until the start
// time. Clearing activates_at restores access.
func TestAdmin_ScheduleStart(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	tok := env.issueSession(t, admin.ID)

	staged := env.seedUser(t, "newhire@example.com", "admin")
	future := time.Now().UTC().Add(72 * time.Hour)

	res := env.do(t, http.MethodPost, "/api/auth/admin/users/"+staged.ID+"/schedule-start", tok, map[string]any{
		"activates_at": future,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("schedule-start: %d (%s)", res.StatusCode, drain(res))
	}
	var out struct {
		ActivatesAt *time.Time `json:"activates_at"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode schedule-start: %v", err)
	}
	res.Body.Close()
	if out.ActivatesAt == nil {
		t.Fatalf("expected activates_at to be set")
	}

	// A staged user cannot authenticate yet: their session cookie is rejected.
	cookie := env.issueSession(t, staged.ID)
	res = env.do(t, http.MethodGet, "/api/auth/admin/users", cookie, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for not-yet-started user, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Clear the schedule (activates_at: null) → access restored.
	res = env.do(t, http.MethodPost, "/api/auth/admin/users/"+staged.ID+"/schedule-start", tok, map[string]any{
		"activates_at": nil,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("clear schedule: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	cookie = env.issueSession(t, staged.ID)
	res = env.do(t, http.MethodGet, "/api/auth/admin/users", cookie, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after clearing schedule, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}
