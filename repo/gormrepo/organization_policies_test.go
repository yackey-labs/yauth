package gormrepo

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

var orgPolicyTestDBCounter uint64

func newOrgPolicyTestRepo(t *testing.T) *Repo {
	t.Helper()
	id := atomic.AddUint64(&orgPolicyTestDBCounter, 1)
	dsn := fmt.Sprintf("file:orgpol-%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", id)
	db, err := OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(db)
}

func gpi64(v int64) *int64 { return &v }
func gpi32(v int32) *int32 { return &v }

func TestGormOrganizationPolicy_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	r := newOrgPolicyTestRepo(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	in := domain.NewOrganizationPolicy{
		OrganizationID:         "o1",
		MaxSessionDurationSecs: gpi64(7200),
		IdleTimeoutSecs:        gpi64(600),
		MfaRequired:            true,
		MfaGracePeriodDays:     10,
		IPAllowlist:            []string{"10.0.0.0/8", "192.168.0.0/16"},
		MaxConcurrentSessions:  gpi32(3),
		AllowedAuthMethods:     []string{"password", "passkey"},
		SessionBinding:         domain.SessionBindingBoth,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if _, err := r.CreateOrganizationPolicy(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := r.GetOrganizationPolicy(ctx, "o1")
	if err != nil || got == nil {
		t.Fatalf("get: %+v err=%v", got, err)
	}
	if got.SessionBinding != domain.SessionBindingBoth {
		t.Fatalf("binding mismatch: %q", got.SessionBinding)
	}
	if len(got.IPAllowlist) != 2 || got.IPAllowlist[0] != "10.0.0.0/8" {
		t.Fatalf("ip_allowlist mismatch: %+v", got.IPAllowlist)
	}
	if len(got.AllowedAuthMethods) != 2 || got.AllowedAuthMethods[1] != "passkey" {
		t.Fatalf("auth_methods mismatch: %+v", got.AllowedAuthMethods)
	}
}

func TestGormOrganizationPolicy_CreateDuplicate(t *testing.T) {
	ctx := context.Background()
	r := newOrgPolicyTestRepo(t)
	_, _ = r.CreateOrganizationPolicy(ctx, domain.NewOrganizationPolicy{OrganizationID: "o1"})
	_, err := r.CreateOrganizationPolicy(ctx, domain.NewOrganizationPolicy{OrganizationID: "o1"})
	if !errors.Is(err, yautherr.ErrConflict) {
		t.Fatalf("expected ErrConflict; got %v", err)
	}
}

func TestGormOrganizationPolicy_UpdatePartial(t *testing.T) {
	ctx := context.Background()
	r := newOrgPolicyTestRepo(t)
	_, _ = r.CreateOrganizationPolicy(ctx, domain.NewOrganizationPolicy{OrganizationID: "o1", MfaRequired: false})
	required := true
	updated, err := r.UpdateOrganizationPolicy(ctx, "o1", domain.UpdateOrganizationPolicy{MfaRequired: &required})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !updated.MfaRequired {
		t.Fatalf("expected MfaRequired=true; got %+v", updated)
	}
}

func TestGormOrganizationPolicy_UpdateNotFound(t *testing.T) {
	ctx := context.Background()
	r := newOrgPolicyTestRepo(t)
	required := true
	_, err := r.UpdateOrganizationPolicy(ctx, "missing", domain.UpdateOrganizationPolicy{MfaRequired: &required})
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestGormOrganizationPolicy_UpsertCreatesAndUpdates(t *testing.T) {
	ctx := context.Background()
	r := newOrgPolicyTestRepo(t)

	mc := gpi32(5)
	got, err := r.UpsertOrganizationPolicy(ctx, "o1", domain.UpdateOrganizationPolicy{MaxConcurrentSessions: &mc})
	if err != nil {
		t.Fatalf("upsert (create): %v", err)
	}
	if got.MaxConcurrentSessions == nil || *got.MaxConcurrentSessions != 5 {
		t.Fatalf("expected 5; got %+v", got.MaxConcurrentSessions)
	}

	// Clear via double-pointer to nil-i32.
	var clear *int32
	got, err = r.UpsertOrganizationPolicy(ctx, "o1", domain.UpdateOrganizationPolicy{MaxConcurrentSessions: &clear})
	if err != nil {
		t.Fatalf("upsert (clear): %v", err)
	}
	if got.MaxConcurrentSessions != nil {
		t.Fatalf("expected cleared; got %+v", got.MaxConcurrentSessions)
	}
}

func TestGormOrganizationPolicy_DeleteIdempotent(t *testing.T) {
	ctx := context.Background()
	r := newOrgPolicyTestRepo(t)
	if err := r.DeleteOrganizationPolicy(ctx, "missing"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	_, _ = r.CreateOrganizationPolicy(ctx, domain.NewOrganizationPolicy{OrganizationID: "o1"})
	if err := r.DeleteOrganizationPolicy(ctx, "o1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := r.GetOrganizationPolicy(ctx, "o1"); !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}
