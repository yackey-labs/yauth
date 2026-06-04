package memrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

func i64p(v int64) *int64 { return &v }
func i32p(v int32) *int32 { return &v }
func bp(v bool) *bool     { return &v }

func TestOrgPolicy_GetNotFound(t *testing.T) {
	r := New()
	got, err := r.GetOrganizationPolicy(context.Background(), "missing")
	if got != nil {
		t.Fatalf("expected nil; got %+v", got)
	}
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestOrgPolicy_CreateAndGet(t *testing.T) {
	r := New()
	now := time.Now().UTC()
	max := i64p(3600)
	in := domain.NewOrganizationPolicy{
		OrganizationID:         "o1",
		MaxSessionDurationSecs: max,
		IdleTimeoutSecs:        i64p(900),
		MfaRequired:            true,
		MfaGracePeriodDays:     14,
		IPAllowlist:            []string{"10.0.0.0/8"},
		MaxConcurrentSessions:  i32p(3),
		AllowedAuthMethods:     []string{"password", "passkey"},
		SessionBinding:         domain.SessionBindingIP,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	out, err := r.CreateOrganizationPolicy(context.Background(), in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.OrganizationID != "o1" || out.MfaRequired != true || out.MfaGracePeriodDays != 14 {
		t.Fatalf("create round-trip mismatch: %+v", out)
	}

	got, err := r.GetOrganizationPolicy(context.Background(), "o1")
	if err != nil || got == nil {
		t.Fatalf("get: %+v err=%v", got, err)
	}
	if got.SessionBinding != domain.SessionBindingIP {
		t.Fatalf("expected binding=ip; got %q", got.SessionBinding)
	}
	if got.MaxSessionDurationSecs == nil || *got.MaxSessionDurationSecs != 3600 {
		t.Fatalf("max_session_duration mismatch: %+v", got.MaxSessionDurationSecs)
	}
	// Mutating the returned slice MUST NOT poke through the repo.
	got.IPAllowlist[0] = "evil"
	again, _ := r.GetOrganizationPolicy(context.Background(), "o1")
	if again.IPAllowlist[0] != "10.0.0.0/8" {
		t.Fatalf("expected clone isolation; got %q", again.IPAllowlist[0])
	}
}

func TestOrgPolicy_CreateDuplicateConflict(t *testing.T) {
	r := New()
	if _, err := r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{OrganizationID: "o1"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{OrganizationID: "o1"}); !errors.Is(err, yautherr.ErrConflict) {
		t.Fatalf("expected ErrConflict; got %v", err)
	}
}

func TestOrgPolicy_UpdatePartial(t *testing.T) {
	r := New()
	if _, err := r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{
		OrganizationID: "o1", MfaRequired: false, MfaGracePeriodDays: 7,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	newRequired := true
	updated, err := r.UpdateOrganizationPolicy(context.Background(), "o1", domain.UpdateOrganizationPolicy{
		MfaRequired: &newRequired,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !updated.MfaRequired {
		t.Fatalf("expected MfaRequired=true; got %+v", updated)
	}
	if updated.MfaGracePeriodDays != 7 {
		t.Fatalf("grace period unexpectedly changed: %d", updated.MfaGracePeriodDays)
	}
}

func TestOrgPolicy_UpdateNotFound(t *testing.T) {
	r := New()
	_, err := r.UpdateOrganizationPolicy(context.Background(), "missing", domain.UpdateOrganizationPolicy{MfaRequired: bp(true)})
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestOrgPolicy_UpsertCreatesWhenAbsent(t *testing.T) {
	r := New()
	cap := i32p(2)
	mc := i32p(2)
	_ = mc
	wrap := &cap
	got, err := r.UpsertOrganizationPolicy(context.Background(), "o1", domain.UpdateOrganizationPolicy{
		MaxConcurrentSessions: wrap,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got.MaxConcurrentSessions == nil || *got.MaxConcurrentSessions != 2 {
		t.Fatalf("expected max_concurrent_sessions=2; got %+v", got.MaxConcurrentSessions)
	}
}

func TestOrgPolicy_UpsertUpdatesWhenPresent(t *testing.T) {
	r := New()
	_, _ = r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{OrganizationID: "o1", MfaRequired: false})
	required := true
	got, err := r.UpsertOrganizationPolicy(context.Background(), "o1", domain.UpdateOrganizationPolicy{MfaRequired: &required})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !got.MfaRequired {
		t.Fatalf("expected MfaRequired=true; got %+v", got)
	}
}

func TestOrgPolicy_DeleteIdempotent(t *testing.T) {
	r := New()
	if err := r.DeleteOrganizationPolicy(context.Background(), "missing"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	_, _ = r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{OrganizationID: "o1"})
	if err := r.DeleteOrganizationPolicy(context.Background(), "o1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := r.GetOrganizationPolicy(context.Background(), "o1"); !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete; got %v", err)
	}
}

func TestOrgPolicy_CascadeOnOrgDelete(t *testing.T) {
	r := New()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o1", Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if _, err := r.CreateOrganizationPolicy(context.Background(), domain.NewOrganizationPolicy{
		OrganizationID: "o1", MfaRequired: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := r.DeleteOrganization(context.Background(), "o1"); err != nil {
		t.Fatalf("delete org: %v", err)
	}
	if _, err := r.GetOrganizationPolicy(context.Background(), "o1"); !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected policy cascaded; got err=%v", err)
	}
}
