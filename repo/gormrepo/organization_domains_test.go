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

var orgDomainTestDBCounter uint64

func newOrgDomainTestRepo(t *testing.T) *Repo {
	t.Helper()
	id := atomic.AddUint64(&orgDomainTestDBCounter, 1)
	dsn := fmt.Sprintf("file:orgdom-%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", id)
	db, err := OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(db)
}

func seedGormOrg(t *testing.T, r *Repo, id string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: id, Name: "Acme", Slug: id, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

func TestGormOrganizationDomain_Roundtrip(t *testing.T) {
	ctx := context.Background()
	r := newOrgDomainTestRepo(t)
	seedGormOrg(t, r, "o1")
	now := time.Now().UTC().Truncate(time.Microsecond)
	d, err := r.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "ACME.com",
		Status: domain.DomainPending, VerificationToken: "tok",
		AutoJoinOnSignup: true, DefaultRoleOnAutoJoin: "member",
		RequireEmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.Domain != "acme.com" {
		t.Fatalf("canonical lowercase storage: got %q", d.Domain)
	}
	got, err := r.GetOrganizationDomainByDomain(ctx, "Acme.COM")
	if err != nil {
		t.Fatalf("get by domain: %v", err)
	}
	if got == nil || got.ID != "d1" {
		t.Fatalf("unexpected fetch: %+v", got)
	}
}

func TestGormOrganizationDomain_DuplicateConflict(t *testing.T) {
	ctx := context.Background()
	r := newOrgDomainTestRepo(t)
	seedGormOrg(t, r, "o1")
	seedGormOrg(t, r, "o2")
	if _, err := r.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "t1",
	}); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := r.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
		ID: "d2", OrganizationID: "o2", Domain: "ACME.com",
		Status: domain.DomainPending, VerificationToken: "t2",
	})
	if !errors.Is(err, yautherr.ErrConflict) {
		t.Fatalf("want ErrConflict on app-wide UNIQUE(domain); got %v", err)
	}
}

func TestGormOrganizationDomain_ListVerifiedAutoJoinFilters(t *testing.T) {
	ctx := context.Background()
	r := newOrgDomainTestRepo(t)
	seedGormOrg(t, r, "o1")
	for _, c := range []struct {
		id     string
		dom    string
		status domain.DomainStatus
		auto   bool
	}{
		{"d-p", "pending.com", domain.DomainPending, true},
		{"d-na", "noauto.com", domain.DomainVerified, false},
		{"d-yes", "acme.com", domain.DomainVerified, true},
	} {
		if _, err := r.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
			ID: c.id, OrganizationID: "o1", Domain: c.dom,
			Status: c.status, VerificationToken: c.id, AutoJoinOnSignup: c.auto,
		}); err != nil {
			t.Fatalf("seed %s: %v", c.id, err)
		}
	}
	rows, err := r.ListVerifiedAutoJoinOrganizationDomains(ctx, "acme.com")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "d-yes" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestGormOrganizationDomain_SetVerification(t *testing.T) {
	ctx := context.Background()
	r := newOrgDomainTestRepo(t)
	seedGormOrg(t, r, "o1")
	if _, err := r.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	verifiedAt := now.Add(time.Second)
	d, err := r.SetOrganizationDomainVerification(ctx, "d1", domain.DomainVerified, &verifiedAt, verifiedAt)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if d.Status != domain.DomainVerified {
		t.Fatalf("status: %+v", d)
	}
	if d.VerifiedAt == nil || !d.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("verified_at: %+v", d.VerifiedAt)
	}
	// Transition back to failed clears verified_at.
	failedAt := verifiedAt.Add(time.Hour)
	d2, err := r.SetOrganizationDomainVerification(ctx, "d1", domain.DomainFailed, nil, failedAt)
	if err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if d2.Status != domain.DomainFailed || d2.VerifiedAt != nil {
		t.Fatalf("transition failed: %+v", d2)
	}
}

func TestGormOrganizationDomain_DeleteIdempotent(t *testing.T) {
	ctx := context.Background()
	r := newOrgDomainTestRepo(t)
	seedGormOrg(t, r, "o1")
	if _, err := r.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := r.DeleteOrganizationDomain(ctx, "d1"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := r.DeleteOrganizationDomain(ctx, "d1"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestGormOrganizationDelete_CascadesDomains(t *testing.T) {
	ctx := context.Background()
	r := newOrgDomainTestRepo(t)
	seedGormOrg(t, r, "o1")
	if _, err := r.CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := r.DeleteOrganization(ctx, "o1"); err != nil {
		t.Fatalf("delete org: %v", err)
	}
	_, err := r.GetOrganizationDomainByID(ctx, "d1")
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected cascade-deleted domain; got %v", err)
	}
}
