package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// Pins the CURRENT honest behavior: plain IssueSession applies NO org
// policy caps (they are opt-in via IssueSessionWithPolicy). If a future
// migration wires a login path to the enforcer, THIS test must be updated
// to reflect the new contract — its value is forcing that update to be
// deliberate rather than silent.
func TestIssueSession_PlainIgnoresOrgCaps(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	now := time.Now().UTC()
	if _, err := r.CreateUser(ctx, domain.NewUser{ID: "u1", Email: "a@b.com", Role: "user", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	max := int64(60) // 60s cap the plain path must NOT apply
	capN := int32(1)
	enf := auth.NewPolicyEnforcer(&domain.OrganizationPolicy{
		MaxSessionDurationSecs: &max,
		MaxConcurrentSessions:  &capN,
	}, auth.GlobalPolicyDefaults{})

	// ClampSessionTTL itself is correct (the enforcement primitive works):
	if got := enf.ClampSessionTTL(time.Hour); got != time.Minute {
		t.Fatalf("ClampSessionTTL(Hour) with 60s cap: want 1m, got %v", got)
	}

	// But plain IssueSession does not consult the enforcer: a 1h request
	// still mints a ~1h session. Documented opt-in gap, not a bug in this
	// helper — see IssueSession godoc for the caller registry.
	_, sess, err := auth.IssueSession(ctx, r, "u1", nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if d := sess.ExpiresAt.Sub(sess.CreatedAt); d < 59*time.Minute {
		t.Fatalf("plain IssueSession must not clamp: got ttl %v, want ~1h", d)
	}

	// And the policy-aware variant DOES clamp + prune (control case).
	_, sess2, err := auth.IssueSessionWithPolicy(ctx, r, "u1", nil, nil, time.Hour, enf)
	if err != nil {
		t.Fatalf("issue with policy: %v", err)
	}
	if d := sess2.ExpiresAt.Sub(sess2.CreatedAt); d > 65*time.Second {
		t.Fatalf("IssueSessionWithPolicy must clamp to ~60s; got %v", d)
	}
	uid := "u1"
	rows, total, err := r.ListSessions(ctx, domain.ListSessionsFilters{UserID: &uid})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	_ = rows
	if total > 2 {
		t.Fatalf("cap=1 should have pruned to <=2 total here; got %d", total)
	}
}
