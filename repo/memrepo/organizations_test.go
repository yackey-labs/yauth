package memrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// newOrgInput builds a NewOrganization with the supplied id/slug/name —
// callers can override fields they care about. Created/Updated default
// to now-UTC.
func newOrgInput(id, name, slug string) domain.NewOrganization {
	now := time.Now().UTC()
	return domain.NewOrganization{
		ID:        id,
		Name:      name,
		Slug:      slug,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestOrganizationCreateAndGet(t *testing.T) {
	ctx := context.Background()
	r := New()
	in := newOrgInput("org-1", "Acme", "acme")
	o, err := r.CreateOrganization(ctx, in)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if o.ID != "org-1" || o.Slug != "acme" || o.Name != "Acme" {
		t.Fatalf("unexpected org: %+v", o)
	}
	got, err := r.GetOrganizationByID(ctx, "org-1")
	if err != nil {
		t.Fatalf("GetOrganizationByID: %v", err)
	}
	if got.Slug != "acme" {
		t.Fatalf("slug mismatch: %q", got.Slug)
	}
}

func TestOrganizationSlugIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	r := New()
	if _, err := r.CreateOrganization(ctx, newOrgInput("org-1", "Acme", "Acme")); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Duplicate slug with different case must be rejected.
	_, err := r.CreateOrganization(ctx, newOrgInput("org-2", "Other", "ACME"))
	if !errors.Is(err, yautherr.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	// Case-insensitive lookup must find the row.
	o, err := r.GetOrganizationBySlug(ctx, "acme")
	if err != nil {
		t.Fatalf("GetOrganizationBySlug: %v", err)
	}
	if o.ID != "org-1" {
		t.Fatalf("wrong org returned: %+v", o)
	}
}

func TestOrganizationGetMissing(t *testing.T) {
	ctx := context.Background()
	r := New()
	_, err := r.GetOrganizationByID(ctx, "nope")
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	_, err = r.GetOrganizationBySlug(ctx, "nope")
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("want ErrNotFound for slug, got %v", err)
	}
}

func TestOrganizationUpdate(t *testing.T) {
	ctx := context.Background()
	r := New()
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("create: %v", err)
	}
	name := "Acme Inc"
	dn := "Acme, Inc."
	display := &dn
	updated, err := r.UpdateOrganization(ctx, "o", domain.UpdateOrganization{
		Name:        &name,
		DisplayName: &display,
	})
	if err != nil {
		t.Fatalf("UpdateOrganization: %v", err)
	}
	if updated.Name != "Acme Inc" || updated.DisplayName == nil || *updated.DisplayName != "Acme, Inc." {
		t.Fatalf("unexpected update: %+v", updated)
	}
	// Clear display_name via double-pointer-to-nil.
	var nilPtr *string
	updated, err = r.UpdateOrganization(ctx, "o", domain.UpdateOrganization{DisplayName: &nilPtr})
	if err != nil {
		t.Fatalf("clear display_name: %v", err)
	}
	if updated.DisplayName != nil {
		t.Fatalf("display_name should be nil, got %v", *updated.DisplayName)
	}
}

func TestOrganizationUpdateSlugConflict(t *testing.T) {
	ctx := context.Background()
	r := New()
	if _, err := r.CreateOrganization(ctx, newOrgInput("o1", "One", "one")); err != nil {
		t.Fatalf("create o1: %v", err)
	}
	if _, err := r.CreateOrganization(ctx, newOrgInput("o2", "Two", "two")); err != nil {
		t.Fatalf("create o2: %v", err)
	}
	slug := "ONE"
	_, err := r.UpdateOrganization(ctx, "o2", domain.UpdateOrganization{Slug: &slug})
	if !errors.Is(err, yautherr.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestOrganizationDeleteCascade(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("create org: %v", err)
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
		t.Fatalf("create membership: %v", err)
	}
	if _, err := r.CreateInvitation(ctx, domain.NewInvitation{
		ID:              "i1",
		OrganizationID:  "o",
		Email:           "bob@example.com",
		Role:            "member",
		TokenHash:       "hash1",
		InvitedByUserID: "u1",
		ExpiresAt:       now.Add(time.Hour),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if err := r.DeleteOrganization(ctx, "o"); err != nil {
		t.Fatalf("delete org: %v", err)
	}
	// Memberships gone.
	got, _ := r.GetMembershipByOrgUser(ctx, "o", "u1")
	if got != nil {
		t.Fatalf("expected cascade to remove membership, got %+v", got)
	}
	// Invitations gone.
	inv, _ := r.GetInvitationByTokenHash(ctx, "hash1")
	if inv != nil {
		t.Fatalf("expected cascade to remove invitation, got %+v", inv)
	}
}

func TestOrganizationDeleteIdempotent(t *testing.T) {
	ctx := context.Background()
	r := New()
	if err := r.DeleteOrganization(ctx, "ghost"); err != nil {
		t.Fatalf("delete missing should be no-op, got %v", err)
	}
}

func TestMembershipUniquePerOrgUser(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("create org: %v", err)
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

func TestMembershipGetByOrgUserNotMemberReturnsNil(t *testing.T) {
	ctx := context.Background()
	r := New()
	// No-rows is not an error, just nil.
	m, err := r.GetMembershipByOrgUser(ctx, "ghost-org", "ghost-user")
	if err != nil {
		t.Fatalf("want nil err, got %v", err)
	}
	if m != nil {
		t.Fatalf("want nil membership, got %+v", m)
	}
}

func TestMembershipListByOrgAndUser(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	for _, o := range []string{"o1", "o2"} {
		if _, err := r.CreateOrganization(ctx, newOrgInput(o, o, o)); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(id, org, user string) {
		t.Helper()
		_, err := r.CreateMembership(ctx, domain.NewMembership{
			ID: id, OrganizationID: org, UserID: user, Role: "member",
			Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Millisecond)
	}
	mk("m1", "o1", "u1")
	mk("m2", "o1", "u2")
	mk("m3", "o2", "u1")

	byOrg, err := r.ListMembershipsByOrg(ctx, "o1")
	if err != nil || len(byOrg) != 2 {
		t.Fatalf("ListMembershipsByOrg: %v, len=%d", err, len(byOrg))
	}
	byUser, err := r.ListMembershipsByUser(ctx, "u1")
	if err != nil || len(byUser) != 2 {
		t.Fatalf("ListMembershipsByUser: %v, len=%d", err, len(byUser))
	}
	forUser, err := r.ListOrganizationsForUser(ctx, "u1")
	if err != nil || len(forUser) != 2 {
		t.Fatalf("ListOrganizationsForUser: %v, len=%d", err, len(forUser))
	}
}

func TestInvitationTokenExpiredFiltered(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("create org: %v", err)
	}
	// Expired invite — must not surface via token-hash lookup.
	if _, err := r.CreateInvitation(ctx, domain.NewInvitation{
		ID: "i1", OrganizationID: "o", Email: "x@y.com", Role: "member",
		TokenHash:       "ht",
		InvitedByUserID: "u",
		ExpiresAt:       now.Add(-time.Minute),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	inv, err := r.GetInvitationByTokenHash(ctx, "ht")
	if err != nil {
		t.Fatalf("GetInvitationByTokenHash: %v", err)
	}
	if inv != nil {
		t.Fatalf("expired invitation should not be returned, got %+v", inv)
	}
}

func TestInvitationMarkAcceptedSingleShot(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if _, err := r.CreateInvitation(ctx, domain.NewInvitation{
		ID: "i1", OrganizationID: "o", Email: "x@y.com", Role: "member",
		TokenHash:       "ht",
		InvitedByUserID: "u",
		ExpiresAt:       now.Add(time.Hour),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := r.MarkInvitationAccepted(ctx, "i1", now); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	_, err := r.MarkInvitationAccepted(ctx, "i1", now)
	if !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("second accept must be ErrNotFound, got %v", err)
	}
	// Already-accepted invitations are not surfaced via token-hash
	// lookup.
	got, err := r.GetInvitationByTokenHash(ctx, "ht")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != nil {
		t.Fatalf("accepted invite should not surface, got %+v", got)
	}
}

func TestInvitationListPendingFiltersAccepted(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(ctx, newOrgInput("o", "Acme", "acme")); err != nil {
		t.Fatalf("create org: %v", err)
	}
	mk := func(id, hash string) {
		t.Helper()
		if _, err := r.CreateInvitation(ctx, domain.NewInvitation{
			ID: id, OrganizationID: "o", Email: id + "@y.com", Role: "member",
			TokenHash:       hash,
			InvitedByUserID: "u",
			ExpiresAt:       now.Add(time.Hour),
			CreatedAt:       now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("i1", "h1")
	mk("i2", "h2")
	if _, err := r.MarkInvitationAccepted(ctx, "i2", now); err != nil {
		t.Fatalf("accept i2: %v", err)
	}
	pending, err := r.ListPendingInvitationsForOrg(ctx, "o")
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "i1" {
		t.Fatalf("pending list: %+v", pending)
	}
}
