package pgxrepo_test

// Concurrency and guard regression tests for the security review. Each test
// here fails against the pre-fix implementation and passes after it:
//
//   - TestOwnerProtectionConcurrentDemote / Delete: last-owner TOCTOU.
//   - TestDeviceCodeConcurrentApprove: guardless status transition.
//   - TestSearchEscapesLikeWildcards: LIKE injection in search.
//   - TestUpdateGroupConcurrentMerge: read-modify-write lost update.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo/pgxrepo"
	"github.com/yackey-labs/yauth/yautherr"
)

func secNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

func jsonRaw(s string) json.RawMessage { return json.RawMessage(s) }

func newSecRepo(t *testing.T) *pgxrepo.Repo {
	t.Helper()
	if sharedPool == nil {
		t.Skip("Docker not available; pgxrepo security tests skipped")
	}
	if err := truncatePgxTables(t, sharedStdDB); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pgxrepo.New(sharedPool)
}

func secCtx() context.Context { return context.Background() }

func secMustUser(t *testing.T, r *pgxrepo.Repo, id, email string) {
	t.Helper()
	now := secNow()
	if _, err := r.CreateUser(secCtx(), domain.NewUser{
		ID: id, Email: email, Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateUser(%s): %v", id, err)
	}
}

func secMustOrg(t *testing.T, r *pgxrepo.Repo, id, name, slug string) {
	t.Helper()
	now := secNow()
	if _, err := r.CreateOrganization(secCtx(), domain.NewOrganization{
		ID: id, Name: name, Slug: slug, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateOrganization(%s): %v", id, err)
	}
}

func secMustOwner(t *testing.T, r *pgxrepo.Repo, id, orgID, userID string) {
	t.Helper()
	now := secNow()
	if _, err := r.CreateMembership(secCtx(), domain.NewMembership{
		ID: id, OrganizationID: orgID, UserID: userID,
		Role: "owner", Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now, OwnerRoleAuthorized: true,
	}); err != nil {
		t.Fatalf("CreateMembership(%s): %v", id, err)
	}
}

// runPair releases two functions at the same instant and reports both errors.
func runPair(fn1, fn2 func() error) (error, error) {
	start := make(chan struct{})
	var e1, e2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-start; e1 = fn1() }()
	go func() { defer wg.Done(); <-start; e2 = fn2() }()
	close(start)
	wg.Wait()
	return e1, e2
}

// TestOwnerProtectionConcurrentDemote proves the last-owner TOCTOU: with two
// owners, two concurrent demotions must not both commit. Exactly one must win
// and the other must see ErrOwnerProtected, leaving one owner behind.
func TestOwnerProtectionConcurrentDemote(t *testing.T) {
	r := newSecRepo(t)
	member := "member"
	for i := 0; i < 25; i++ {
		org := fmt.Sprintf("o-dem-%d", i)
		secMustOrg(t, r, org, fmt.Sprintf("Org %d", i), fmt.Sprintf("slug-dem-%d", i))
		secMustUser(t, r, fmt.Sprintf("u-dem-%d-a", i), fmt.Sprintf("a-dem-%d@example.com", i))
		secMustUser(t, r, fmt.Sprintf("u-dem-%d-b", i), fmt.Sprintf("b-dem-%d@example.com", i))
		secMustOwner(t, r, fmt.Sprintf("m-dem-%d-a", i), org, fmt.Sprintf("u-dem-%d-a", i))
		secMustOwner(t, r, fmt.Sprintf("m-dem-%d-b", i), org, fmt.Sprintf("u-dem-%d-b", i))

		mkDemote := func(mid string) func() error {
			return func() error {
				_, err := r.UpdateMembership(secCtx(), mid, domain.UpdateMembership{Role: &member})
				return err
			}
		}
		e1, e2 := runPair(
			mkDemote(fmt.Sprintf("m-dem-%d-a", i)),
			mkDemote(fmt.Sprintf("m-dem-%d-b", i)),
		)
		if e1 == nil && e2 == nil {
			t.Fatalf("iteration %d: TOCTOU — both owner demotions committed, org %s now has zero owners", i, org)
		}
		if !((e1 == nil && errors.Is(e2, yautherr.ErrOwnerProtected)) ||
			(e2 == nil && errors.Is(e1, yautherr.ErrOwnerProtected))) {
			t.Fatalf("iteration %d: want (nil, ErrOwnerProtected) in some order, got (%v, %v)", i, e1, e2)
		}
		ms, err := r.ListMembershipsByOrg(secCtx(), org)
		if err != nil {
			t.Fatalf("iteration %d: ListMembershipsByOrg: %v", i, err)
		}
		owners := 0
		for _, m := range ms {
			if m.Role == "owner" {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("iteration %d: want exactly 1 surviving owner, got %d", i, owners)
		}
	}
}

// TestOwnerProtectionConcurrentDelete is the delete-side twin: two concurrent
// removals of the two owners must not both succeed.
func TestOwnerProtectionConcurrentDelete(t *testing.T) {
	r := newSecRepo(t)
	for i := 0; i < 25; i++ {
		org := fmt.Sprintf("o-del-%d", i)
		secMustOrg(t, r, org, fmt.Sprintf("Org %d", i), fmt.Sprintf("slug-del-%d", i))
		secMustUser(t, r, fmt.Sprintf("u-del-%d-a", i), fmt.Sprintf("a-del-%d@example.com", i))
		secMustUser(t, r, fmt.Sprintf("u-del-%d-b", i), fmt.Sprintf("b-del-%d@example.com", i))
		secMustOwner(t, r, fmt.Sprintf("m-del-%d-a", i), org, fmt.Sprintf("u-del-%d-a", i))
		secMustOwner(t, r, fmt.Sprintf("m-del-%d-b", i), org, fmt.Sprintf("u-del-%d-b", i))

		e1, e2 := runPair(
			func() error { return r.DeleteMembership(secCtx(), fmt.Sprintf("m-del-%d-a", i)) },
			func() error { return r.DeleteMembership(secCtx(), fmt.Sprintf("m-del-%d-b", i)) },
		)
		if e1 == nil && e2 == nil {
			t.Fatalf("iteration %d: TOCTOU — both owner deletions committed, org %s now has zero owners", i, org)
		}
		if !((e1 == nil && errors.Is(e2, yautherr.ErrOwnerProtected)) ||
			(e2 == nil && errors.Is(e1, yautherr.ErrOwnerProtected))) {
			t.Fatalf("iteration %d: want (nil, ErrOwnerProtected) in some order, got (%v, %v)", i, e1, e2)
		}
	}
}

// TestDeviceCodeConcurrentApprove proves the guardless-transition race: two
// concurrent approvals by different users must not both succeed with
// last-writer-wins on user_id. Exactly one wins; the loser gets ErrNotFound.
func TestDeviceCodeConcurrentApprove(t *testing.T) {
	r := newSecRepo(t)
	now := secNow()
	for i := 0; i < 10; i++ {
		tag := fmt.Sprintf("dc-%d", i)
		secMustUser(t, r, "u-"+tag+"-a", "a-"+tag+"@example.com")
		secMustUser(t, r, "u-"+tag+"-b", "b-"+tag+"@example.com")
		if err := r.CreateOAuth2Client(secCtx(), domain.NewOAuth2Client{
			ID: "c-" + tag, ClientID: "cli-" + tag,
			RedirectURIs: jsonRaw(`[]`), GrantTypes: jsonRaw(`[]`), Scopes: jsonRaw(`[]`),
			CreatedAt: now,
		}); err != nil {
			t.Fatalf("iteration %d: CreateOAuth2Client: %v", i, err)
		}
		if err := r.CreateDeviceCode(secCtx(), domain.NewDeviceCode{
			ID: "d-" + tag, DeviceCodeHash: "dh-" + tag, UserCode: "UC-" + tag,
			ClientID: "cli-" + tag, Scopes: jsonRaw(`[]`),
			Status: "pending", Interval: 5,
			ExpiresAt: now.AddDate(1, 0, 0), CreatedAt: now,
		}); err != nil {
			t.Fatalf("iteration %d: CreateDeviceCode: %v", i, err)
		}
		ua, ub := "u-"+tag+"-a", "u-"+tag+"-b"
		e1, e2 := runPair(
			func() error { return r.UpdateDeviceCodeStatus(secCtx(), "d-"+tag, "approved", &ua) },
			func() error { return r.UpdateDeviceCodeStatus(secCtx(), "d-"+tag, "approved", &ub) },
		)
		if e1 == nil && e2 == nil {
			got, _ := r.GetDeviceCodeByDeviceCodeHash(secCtx(), "dh-"+tag)
			t.Fatalf("iteration %d: both approvals committed (last-writer-wins on user_id=%v)", i, got.UserID)
		}
		if !((e1 == nil && errors.Is(e2, yautherr.ErrNotFound)) ||
			(e2 == nil && errors.Is(e1, yautherr.ErrNotFound))) {
			t.Fatalf("iteration %d: want (nil, ErrNotFound) in some order, got (%v, %v)", i, e1, e2)
		}
	}
}

// TestSearchEscapesLikeWildcards proves LIKE injection in the pgx search
// path: "%" must not match every user.
func TestSearchEscapesLikeWildcards(t *testing.T) {
	r := newSecRepo(t)
	secMustUser(t, r, "u1", "alice@example.com")
	secMustUser(t, r, "u2", "bob@example.com")
	for _, term := range []string{"%", "_", "%_%", "\\", "%%"} {
		got, total, err := r.ListUsers(secCtx(), term, 0, 0)
		if err != nil {
			t.Fatalf("ListUsers(%q): %v", term, err)
		}
		if total != 0 || len(got) != 0 {
			t.Fatalf("ListUsers(%q) matched %d rows; want 0", term, total)
		}
	}
	secMustOrg(t, r, "o1", "Acme", "acme")
	secMustOrg(t, r, "o2", "Globex", "globex")
	for _, term := range []string{"%", "_", "%%"} {
		got, total, err := r.ListOrganizations(secCtx(), term, 0, 0)
		if err != nil {
			t.Fatalf("ListOrganizations(%q): %v", term, err)
		}
		if total != 0 || len(got) != 0 {
			t.Fatalf("ListOrganizations(%q) matched %d rows; want 0", term, total)
		}
	}
}

// TestUpdateGroupConcurrentMerge proves the read-modify-write lost update:
// two concurrent PATCHes touching different fields must not clobber each
// other.
func TestUpdateGroupConcurrentMerge(t *testing.T) {
	r := newSecRepo(t)
	for i := 0; i < 30; i++ {
		tag := fmt.Sprintf("g-%d", i)
		secMustOrg(t, r, "o-"+tag, "Org "+tag, "slug-"+tag)
		now := secNow()
		if _, err := r.CreateGroup(secCtx(), domain.NewGroup{
			ID: "g-" + tag, OrganizationID: "o-" + tag,
			Name: "name-" + tag, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("iteration %d: CreateGroup: %v", i, err)
		}
		newName := "renamed-" + tag
		newDesc := "desc-" + tag
		e1, e2 := runPair(
			func() error {
				_, err := r.UpdateGroup(secCtx(), "g-"+tag, domain.UpdateGroup{Name: &newName})
				return err
			},
			func() error {
				_, err := r.UpdateGroup(secCtx(), "g-"+tag, domain.UpdateGroup{Description: &newDesc})
				return err
			},
		)
		if e1 != nil || e2 != nil {
			t.Fatalf("iteration %d: unexpected errors (%v, %v)", i, e1, e2)
		}
		got, err := r.GetGroupByID(secCtx(), "g-"+tag)
		if err != nil {
			t.Fatalf("iteration %d: GetGroupByID: %v", i, err)
		}
		if got.Name != newName {
			t.Fatalf("iteration %d: lost update — Name=%q, want %q", i, got.Name, newName)
		}
		if got.Description == nil || *got.Description != newDesc {
			t.Fatalf("iteration %d: lost update — Description=%v, want %q", i, got.Description, newDesc)
		}
	}
}

// TestDeleteUserConcurrentCoOwnersNoDeadlock: two users co-own orgs X and Y,
// and their memberships were created in opposite orders, so each user's
// membership list names the orgs in opposite order. DeleteUser must lock
// owners in a fixed (org id) order; locking in membership order deadlocks
// (Postgres aborts one side with 40P01). Exactly one delete may win; the
// other leaves the survivor as last owner and must see ErrOwnerProtected.
func TestDeleteUserConcurrentCoOwnersNoDeadlock(t *testing.T) {
	r := newSecRepo(t)
	mkOwner := func(id, orgID, userID string, at time.Time) {
		t.Helper()
		if _, err := r.CreateMembership(secCtx(), domain.NewMembership{
			ID: id, OrganizationID: orgID, UserID: userID,
			Role: "owner", Status: domain.MembershipActive,
			CreatedAt: at, UpdatedAt: at, OwnerRoleAuthorized: true,
		}); err != nil {
			t.Fatalf("CreateMembership(%s): %v", id, err)
		}
	}
	base := secNow()
	for i := 0; i < 25; i++ {
		x, y := fmt.Sprintf("o-dl-%d-x", i), fmt.Sprintf("o-dl-%d-y", i)
		u1, u2 := fmt.Sprintf("u-dl-%d-1", i), fmt.Sprintf("u-dl-%d-2", i)
		secMustOrg(t, r, x, "X "+x, "slug-"+x)
		secMustOrg(t, r, y, "Y "+y, "slug-"+y)
		secMustUser(t, r, u1, u1+"@example.com")
		secMustUser(t, r, u2, u2+"@example.com")
		// u1 joins Y first, then X; u2 joins X first, then Y.
		mkOwner("m-"+u1+"-y", y, u1, base)
		mkOwner("m-"+u1+"-x", x, u1, base.Add(time.Second))
		mkOwner("m-"+u2+"-x", x, u2, base)
		mkOwner("m-"+u2+"-y", y, u2, base.Add(time.Second))

		e1, e2 := runPair(
			func() error { return r.DeleteUser(secCtx(), u1) },
			func() error { return r.DeleteUser(secCtx(), u2) },
		)
		if !((e1 == nil && errors.Is(e2, yautherr.ErrOwnerProtected)) ||
			(e2 == nil && errors.Is(e1, yautherr.ErrOwnerProtected))) {
			t.Fatalf("iteration %d: want (nil, ErrOwnerProtected) in some order, got (%v, %v)", i, e1, e2)
		}
	}
}
