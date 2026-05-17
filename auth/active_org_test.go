package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
)

// fakeLookup is a hand-rolled MembershipsLookup for the selection-rule
// tests. Keeps the tests free of the full memrepo wiring.
type fakeLookup struct {
	memberships map[string][]*domain.Membership // userID → memberships
	orgs        map[string]*domain.Organization
	err         error
}

func (f *fakeLookup) ListMembershipsByUser(_ context.Context, userID string) ([]*domain.Membership, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.memberships[userID], nil
}

func (f *fakeLookup) GetOrganizationByID(_ context.Context, id string) (*domain.Organization, error) {
	if o, ok := f.orgs[id]; ok {
		return o, nil
	}
	return nil, nil
}

func newFakeLookup() *fakeLookup {
	return &fakeLookup{
		memberships: map[string][]*domain.Membership{},
		orgs:        map[string]*domain.Organization{},
	}
}

func (f *fakeLookup) addOrg(id, name, slug string) {
	f.orgs[id] = &domain.Organization{ID: id, Name: name, Slug: slug, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
}

func (f *fakeLookup) addMembership(userID, orgID, role string, status domain.MembershipStatus) {
	f.memberships[userID] = append(f.memberships[userID], &domain.Membership{
		ID: orgID + "-" + userID, OrganizationID: orgID, UserID: userID,
		Role: role, Status: status,
	})
}

func TestSelectDefaultActiveOrg_ZeroMemberships(t *testing.T) {
	l := newFakeLookup()
	id, role, all, err := SelectDefaultActiveOrg(context.Background(), l, "u1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id != nil || role != nil {
		t.Fatalf("expected nil; got id=%v role=%v", id, role)
	}
	if len(all) != 0 {
		t.Fatalf("expected empty memberships; got %d", len(all))
	}
}

func TestSelectDefaultActiveOrg_OneMembershipAutoPicks(t *testing.T) {
	l := newFakeLookup()
	l.addOrg("org-1", "Acme", "acme")
	l.addMembership("u1", "org-1", "owner", domain.MembershipActive)
	id, role, all, err := SelectDefaultActiveOrg(context.Background(), l, "u1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id == nil || *id != "org-1" {
		t.Fatalf("expected id=org-1; got %v", id)
	}
	if role == nil || *role != "owner" {
		t.Fatalf("expected role=owner; got %v", role)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 membership; got %d", len(all))
	}
}

func TestSelectDefaultActiveOrg_MultipleSortedByName(t *testing.T) {
	l := newFakeLookup()
	l.addOrg("z", "Zebra", "zebra")
	l.addOrg("a", "Apex", "apex")
	l.addOrg("m", "Megacorp", "megacorp")
	l.addMembership("u1", "z", "member", domain.MembershipActive)
	l.addMembership("u1", "a", "owner", domain.MembershipActive)
	l.addMembership("u1", "m", "admin", domain.MembershipActive)

	id, role, all, err := SelectDefaultActiveOrg(context.Background(), l, "u1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id == nil || *id != "a" {
		t.Fatalf("expected id=a (alphabetically first); got %v", id)
	}
	if role == nil || *role != "owner" {
		t.Fatalf("expected role=owner; got %v", role)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 memberships; got %d", len(all))
	}
	if all[0].Slug != "apex" || all[1].Slug != "megacorp" || all[2].Slug != "zebra" {
		t.Fatalf("not sorted: %+v", all)
	}
}

func TestSelectDefaultActiveOrg_SkipsNonActiveStatus(t *testing.T) {
	l := newFakeLookup()
	l.addOrg("a", "Apex", "apex")
	l.addOrg("b", "Beta", "beta")
	l.addMembership("u1", "a", "member", domain.MembershipInvited) // not active
	l.addMembership("u1", "b", "admin", domain.MembershipActive)

	id, role, all, err := SelectDefaultActiveOrg(context.Background(), l, "u1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id == nil || *id != "b" {
		t.Fatalf("expected id=b; got %v", id)
	}
	if role == nil || *role != "admin" {
		t.Fatalf("expected role=admin; got %v", role)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 active membership; got %d", len(all))
	}
}

func TestSelectDefaultActiveOrg_SkipsDeletedOrg(t *testing.T) {
	l := newFakeLookup()
	// Membership row points at an org that was deleted between
	// membership listing and org fetch (returns nil, nil).
	l.addMembership("u1", "deleted-org", "owner", domain.MembershipActive)
	id, _, all, err := SelectDefaultActiveOrg(context.Background(), l, "u1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id != nil {
		t.Fatalf("expected nil id; got %v", id)
	}
	if len(all) != 0 {
		t.Fatalf("expected no memberships; got %d", len(all))
	}
}

func TestSelectDefaultActiveOrg_PropagatesListError(t *testing.T) {
	l := newFakeLookup()
	l.err = errors.New("backend down")
	_, _, _, err := SelectDefaultActiveOrg(context.Background(), l, "u1")
	if err == nil {
		t.Fatal("expected error to propagate")
	}
}

func TestResolveActiveOrg_MatchesActiveOrg(t *testing.T) {
	l := newFakeLookup()
	l.addOrg("a", "Apex", "apex")
	l.addOrg("b", "Beta", "beta")
	l.addMembership("u1", "a", "owner", domain.MembershipActive)
	l.addMembership("u1", "b", "member", domain.MembershipActive)

	active := "b"
	id, role, all, err := ResolveActiveOrg(context.Background(), l, "u1", &active)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id == nil || *id != "b" {
		t.Fatalf("expected id=b; got %v", id)
	}
	if role == nil || *role != "member" {
		t.Fatalf("expected role=member; got %v", role)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 memberships; got %d", len(all))
	}
}

func TestResolveActiveOrg_StaleActiveOrgReturnsNil(t *testing.T) {
	// Caller's session points at an org they no longer belong to —
	// resolve should return nil so middleware can clear it.
	l := newFakeLookup()
	l.addOrg("a", "Apex", "apex")
	l.addMembership("u1", "a", "owner", domain.MembershipActive)

	stale := "deleted-or-removed"
	id, role, all, err := ResolveActiveOrg(context.Background(), l, "u1", &stale)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id != nil || role != nil {
		t.Fatalf("expected nil resolved; got id=%v role=%v", id, role)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 membership; got %d", len(all))
	}
}

func TestResolveActiveOrg_NilActiveOrg(t *testing.T) {
	l := newFakeLookup()
	l.addOrg("a", "Apex", "apex")
	l.addMembership("u1", "a", "owner", domain.MembershipActive)

	id, role, all, err := ResolveActiveOrg(context.Background(), l, "u1", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id != nil || role != nil {
		t.Fatalf("expected nil resolved; got id=%v role=%v", id, role)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 membership; got %d", len(all))
	}
}
