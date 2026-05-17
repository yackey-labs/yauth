package memrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

func newRepoWithOrg(t *testing.T, orgID string) *Repo {
	t.Helper()
	r := New()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: orgID,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return r
}

func TestCreateOrganizationDomain_Roundtrip(t *testing.T) {
	r := newRepoWithOrg(t, "o1")
	now := time.Now().UTC()
	d, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "ACME.com",
		Status: domain.DomainPending, VerificationToken: "tok",
		AutoJoinOnSignup: true, DefaultRoleOnAutoJoin: "member",
		RequireEmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.Domain != "acme.com" {
		t.Fatalf("expected canonical lowercase domain; got %q", d.Domain)
	}
	got, err := r.GetOrganizationDomainByID(context.Background(), "d1")
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got == nil || got.Domain != "acme.com" || got.VerificationToken != "tok" {
		t.Fatalf("unexpected fetch: %+v", got)
	}
}

func TestCreateOrganizationDomain_DuplicateDomainConflict(t *testing.T) {
	r := newRepoWithOrg(t, "o1")
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o2", Name: "B", Slug: "b",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed org2: %v", err)
	}
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok",
	}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// Second org tries to claim the same canonical domain.
	_, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d2", OrganizationID: "o2", Domain: "ACME.com",
		Status: domain.DomainPending, VerificationToken: "tok2",
	})
	if !errors.Is(err, yautherr.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate domain (app-wide UNIQUE); got %v", err)
	}
}

func TestGetOrganizationDomainByDomain_CaseInsensitive(t *testing.T) {
	r := newRepoWithOrg(t, "o1")
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := r.GetOrganizationDomainByDomain(context.Background(), "ACME.com")
	if err != nil {
		t.Fatalf("get by domain mixed-case: %v", err)
	}
	if got.ID != "d1" {
		t.Fatalf("unexpected match: %+v", got)
	}
	_, err = r.GetOrganizationDomainByDomain(context.Background(), "missing.com")
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestListVerifiedAutoJoinOrganizationDomains_Filters(t *testing.T) {
	r := newRepoWithOrg(t, "o1")
	// Pending (verified=false → not eligible).
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d-pending", OrganizationID: "o1", Domain: "pending.com",
		Status: domain.DomainPending, VerificationToken: "p", AutoJoinOnSignup: true,
	}); err != nil {
		t.Fatalf("seed pending: %v", err)
	}
	// Verified but auto_join=false.
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d-noauto", OrganizationID: "o1", Domain: "noauto.com",
		Status: domain.DomainVerified, VerificationToken: "n", AutoJoinOnSignup: false,
	}); err != nil {
		t.Fatalf("seed noauto: %v", err)
	}
	// Verified + auto_join — should match.
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d-yes", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainVerified, VerificationToken: "y", AutoJoinOnSignup: true,
	}); err != nil {
		t.Fatalf("seed match: %v", err)
	}
	rows, err := r.ListVerifiedAutoJoinOrganizationDomains(context.Background(), "acme.com")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "d-yes" {
		t.Fatalf("expected single d-yes row; got %+v", rows)
	}
	// Mixed-case lookup matches.
	rows2, err := r.ListVerifiedAutoJoinOrganizationDomains(context.Background(), "ACME.COM")
	if err != nil {
		t.Fatalf("list mixed: %v", err)
	}
	if len(rows2) != 1 {
		t.Fatalf("mixed-case lookup mismatch: %+v", rows2)
	}
}

func TestSetOrganizationDomainVerification_Transitions(t *testing.T) {
	r := newRepoWithOrg(t, "o1")
	now := time.Now().UTC()
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	verifiedAt := now.Add(time.Second)
	d, err := r.SetOrganizationDomainVerification(context.Background(), "d1", domain.DomainVerified, &verifiedAt, verifiedAt)
	if err != nil {
		t.Fatalf("set verified: %v", err)
	}
	if d.Status != domain.DomainVerified {
		t.Fatalf("status not verified: %+v", d)
	}
	if d.VerifiedAt == nil || !d.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("verified_at not set: %+v", d.VerifiedAt)
	}
	if d.LastCheckedAt == nil {
		t.Fatalf("last_checked_at not set")
	}

	// Transition to failed clears verified_at when we pass nil.
	failedAt := verifiedAt.Add(time.Hour)
	d2, err := r.SetOrganizationDomainVerification(context.Background(), "d1", domain.DomainFailed, nil, failedAt)
	if err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if d2.Status != domain.DomainFailed {
		t.Fatalf("status not failed: %+v", d2)
	}
	if d2.VerifiedAt != nil {
		t.Fatalf("verified_at should be nil; got %+v", d2.VerifiedAt)
	}
}

func TestUpdateOrganizationDomain_PartialFields(t *testing.T) {
	r := newRepoWithOrg(t, "o1")
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok",
		AutoJoinOnSignup: false, DefaultRoleOnAutoJoin: "member",
		RequireEmailVerified: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	autoJoin := true
	role := "billing_admin"
	d, err := r.UpdateOrganizationDomain(context.Background(), "d1", domain.UpdateOrganizationDomain{
		AutoJoinOnSignup:      &autoJoin,
		DefaultRoleOnAutoJoin: &role,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !d.AutoJoinOnSignup || d.DefaultRoleOnAutoJoin != "billing_admin" {
		t.Fatalf("update did not apply: %+v", d)
	}
	if !d.RequireEmailVerified {
		t.Fatalf("require_email_verified should be unchanged: %+v", d)
	}
}

func TestDeleteOrganizationDomain_Idempotent(t *testing.T) {
	r := newRepoWithOrg(t, "o1")
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := r.DeleteOrganizationDomain(context.Background(), "d1"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	// Second delete is a no-op.
	if err := r.DeleteOrganizationDomain(context.Background(), "d1"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	// Index is cleared — recreate of the same domain on another row works.
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d2", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok2",
	}); err != nil {
		t.Fatalf("reclaim after delete failed: %v", err)
	}
}

func TestDeleteOrganization_CascadesDomains(t *testing.T) {
	r := newRepoWithOrg(t, "o1")
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d1", OrganizationID: "o1", Domain: "acme.com",
		Status: domain.DomainVerified, VerificationToken: "tok",
		AutoJoinOnSignup: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := r.DeleteOrganization(context.Background(), "o1"); err != nil {
		t.Fatalf("delete org: %v", err)
	}
	_, err := r.GetOrganizationDomainByID(context.Background(), "d1")
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("expected cascade-deleted domain to vanish; got %v", err)
	}
	// And the domain index is cleared — the canonical name is now reusable.
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o2", Name: "Acme2", Slug: "acme2",
	}); err != nil {
		t.Fatalf("seed o2: %v", err)
	}
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: "d2", OrganizationID: "o2", Domain: "acme.com",
		Status: domain.DomainPending, VerificationToken: "tok2",
	}); err != nil {
		t.Fatalf("re-claim should succeed after cascade: %v", err)
	}
}
