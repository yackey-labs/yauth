package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
)

func TestIssueSessionWithPolicy_ClampsTTL(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()

	// Seed user so foreign-key chains work in any backend.
	now := time.Now().UTC()
	if _, err := r.CreateUser(ctx, domain.NewUser{ID: "u1", Email: "a@b.com", Role: "user", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	max := int64(60)
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{MaxSessionDurationSecs: &max}, auth.GlobalPolicyDefaults{})
	_, sess, err := auth.IssueSessionWithPolicy(ctx, r, "u1", nil, nil, time.Hour, enf)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	delta := sess.ExpiresAt.Sub(sess.CreatedAt)
	if delta > 65*time.Second {
		t.Fatalf("expected clamped expiry near 60s; got %v", delta)
	}
}

func TestIssueSessionWithPolicy_PrunesOldestBeyondCap(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()

	now := time.Now().UTC()
	if _, err := r.CreateUser(ctx, domain.NewUser{ID: "u1", Email: "a@b.com", Role: "user", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Pre-seed two old sessions for u1.
	for i := 0; i < 2; i++ {
		s := domain.NewSession{
			ID:        uuid.NewString(),
			UserID:    "u1",
			TokenHash: uuid.NewString(),
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(time.Duration(-i) * time.Minute),
		}
		if err := r.CreateSession(ctx, s); err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}

	cap := int32(2)
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{MaxConcurrentSessions: &cap}, auth.GlobalPolicyDefaults{})

	// Issue a fresh session. Pre-existing count was 2; with cap 2 the
	// oldest pre-existing session should be pruned, leaving the new one
	// and the freshest pre-existing one.
	_, _, err := auth.IssueSessionWithPolicy(ctx, r, "u1", nil, nil, time.Hour, enf)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	uid := "u1"
	rows, total, err := r.ListSessions(ctx, domain.ListSessionsFilters{UserID: &uid})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected 2 surviving sessions; got %d (rows=%d)", total, len(rows))
	}
}

func TestIssueSessionWithPolicy_NilEnforcerPassesThrough(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	now := time.Now().UTC()
	if _, err := r.CreateUser(ctx, domain.NewUser{ID: "u1", Email: "a@b.com", Role: "user", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, sess, err := auth.IssueSessionWithPolicy(ctx, r, "u1", nil, nil, 30*time.Minute, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	delta := sess.ExpiresAt.Sub(sess.CreatedAt)
	if delta < 29*time.Minute || delta > 31*time.Minute {
		t.Fatalf("expected ~30m ttl; got %v", delta)
	}
}
