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

var orgTestDBCounter uint64

// newOrgTestRepo gives each subtest a fresh in-memory SQLite — keying
// the shared cache by a counter prevents organization tests from
// stealing rows from the package's other Smoke test.
func newOrgTestRepo(t *testing.T) *Repo {
	t.Helper()
	id := atomic.AddUint64(&orgTestDBCounter, 1)
	dsn := fmt.Sprintf("file:org-%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", id)
	db, err := OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(db)
}

func newOrgInput(id, name, slug string) domain.NewOrganization {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return domain.NewOrganization{
		ID:        id,
		Name:      name,
		Slug:      slug,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestGormOrganizationCreateAndGet(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	o, err := r.CreateOrganization(ctx, newOrgInput("org-1", "Acme", "acme"))
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if o.Slug != "acme" {
		t.Fatalf("got %+v", o)
	}
	got, err := r.GetOrganizationByID(ctx, "org-1")
	if err != nil {
		t.Fatalf("GetOrganizationByID: %v", err)
	}
	if got.Name != "Acme" {
		t.Fatalf("name mismatch: %q", got.Name)
	}
}

func TestGormOrganizationSlugIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	if _, err := r.CreateOrganization(ctx, newOrgInput("o1", "Acme", "Acme")); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := r.CreateOrganization(ctx, newOrgInput("o2", "Other", "ACME"))
	if !errors.Is(err, yautherr.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	o, err := r.GetOrganizationBySlug(ctx, "acme")
	if err != nil {
		t.Fatalf("GetOrganizationBySlug: %v", err)
	}
	if o.ID != "o1" {
		t.Fatalf("wrong org returned: %+v", o)
	}
}

func TestGormOrganizationUpdate(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("create: %v", err)
	}
	name := "Acme Inc"
	displayVal := "Acme, Inc."
	displayPtr := &displayVal
	o, err := r.UpdateOrganization(ctx, "o", domain.UpdateOrganization{
		Name:        &name,
		DisplayName: &displayPtr,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if o.Name != "Acme Inc" || o.DisplayName == nil || *o.DisplayName != "Acme, Inc." {
		t.Fatalf("update fields: %+v", o)
	}
	// Clear via double-ptr-to-nil.
	var nilPtr *string
	o, err = r.UpdateOrganization(ctx, "o", domain.UpdateOrganization{DisplayName: &nilPtr})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if o.DisplayName != nil {
		t.Fatalf("display_name not cleared: %v", *o.DisplayName)
	}
}

func TestGormOrganizationDeleteCascade(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID:             "m1",
		OrganizationID: "o",
		UserID:         "u1",
		Role:           "admin",
		Status:         domain.MembershipActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("membership: %v", err)
	}
	if _, err := r.CreateInvitation(ctx, domain.NewInvitation{
		ID:              "i1",
		OrganizationID:  "o",
		Email:           "bob@example.com",
		Role:            "member",
		TokenHash:       "h1",
		InvitedByUserID: "u1",
		ExpiresAt:       now.Add(time.Hour),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("invitation: %v", err)
	}
	if err := r.DeleteOrganization(ctx, "o"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Memberships gone.
	m, _ := r.GetMembershipByOrgUser(ctx, "o", "u1")
	if m != nil {
		t.Fatalf("expected cascade to remove membership, got %+v", m)
	}
	// Invitations gone.
	inv, _ := r.GetInvitationByTokenHash(ctx, "h1")
	if inv != nil {
		t.Fatalf("expected cascade to remove invitation, got %+v", inv)
	}
}

func TestGormMembershipUniquePerOrgUser(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: "m1", OrganizationID: "o", UserID: "u", Role: "admin",
		Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: "m2", OrganizationID: "o", UserID: "u", Role: "member",
		Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	})
	if !errors.Is(err, yautherr.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestGormMembershipGetByOrgUserNilForNonMember(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	m, err := r.GetMembershipByOrgUser(ctx, "ghost", "user")
	if err != nil {
		t.Fatalf("want nil err, got %v", err)
	}
	if m != nil {
		t.Fatalf("want nil, got %+v", m)
	}
}

func TestGormInvitationExpiredFiltered(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateInvitation(ctx, domain.NewInvitation{
		ID: "i1", OrganizationID: "o", Email: "x@y", Role: "member",
		TokenHash: "h", InvitedByUserID: "u",
		ExpiresAt: now.Add(-time.Minute), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	inv, err := r.GetInvitationByTokenHash(ctx, "h")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if inv != nil {
		t.Fatalf("expired invitation should be filtered, got %+v", inv)
	}
}

func TestGormInvitationMarkAcceptedSingleShot(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateInvitation(ctx, domain.NewInvitation{
		ID: "i1", OrganizationID: "o", Email: "x@y", Role: "member",
		TokenHash: "h", InvitedByUserID: "u",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.MarkInvitationAccepted(ctx, "i1", now); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	_, err := r.MarkInvitationAccepted(ctx, "i1", now)
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("second accept must be NotFound, got %v", err)
	}
	got, err := r.GetInvitationByTokenHash(ctx, "h")
	if err != nil {
		t.Fatalf("lookup after accept: %v", err)
	}
	if got != nil {
		t.Fatalf("accepted invitation must not surface, got %+v", got)
	}
}

func TestGormListOrganizationsForUserOrderedByCreatedAt(t *testing.T) {
	ctx := context.Background()
	r := newOrgTestRepo(t)
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(id string, off time.Duration) {
		t.Helper()
		in := newOrgInput(id, id, id)
		in.CreatedAt = t0.Add(off)
		in.UpdatedAt = in.CreatedAt
		if _, err := r.CreateOrganization(ctx, in); err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateMembership(ctx, domain.NewMembership{
			ID: "m-" + id, OrganizationID: id, UserID: "u", Role: "member",
			Status: domain.MembershipActive, CreatedAt: in.CreatedAt, UpdatedAt: in.CreatedAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("alpha", 1*time.Second)
	mk("beta", 0)
	mk("gamma", 2*time.Second)
	got, err := r.ListOrganizationsForUser(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"beta", "alpha", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d", len(got), len(want))
	}
	for i, o := range got {
		if o.ID != want[i] {
			t.Fatalf("pos %d: got %q want %q", i, o.ID, want[i])
		}
	}
}
