// list_fanout_test.go — Item-3: GET /Users must not fan out unbounded.
//
// handleListUsers used to ListMembershipsByOrg and then issue 2 queries per
// member (GetUserByID + ListExternalIdentitiesByUser) BEFORE applying
// startIndex/count in process — every poll of a 50k-seat org cost 100k+
// queries for a 100-row page. The fix windows the membership list BEFORE the
// fan-out when no filter is present (the pagination applies to the membership
// list itself, so this is exact), keeps the full scan for filtered queries
// (the filter reads user/ext attributes that don't exist on membership rows —
// slicing first would break filter+pagination correctness), and 400s filtered
// queries past scimListScanCap instead of storming the database.
package scim

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// countingRepo wraps a repo.Repository and counts the per-member fan-out
// queries handleListUsers issues, so a test can prove the windowed path.
type countingRepo struct {
	repo.Repository
	userReads int
	extReads  int
}

func (c *countingRepo) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	c.userReads++
	return c.Repository.GetUserByID(ctx, id)
}

func (c *countingRepo) ListExternalIdentitiesByUser(ctx context.Context, userID string) ([]*domain.ExternalIdentity, error) {
	c.extReads++
	return c.Repository.ListExternalIdentitiesByUser(ctx, userID)
}

func newCountingApp(t *testing.T) (*testApp, *countingRepo) {
	t.Helper()
	r := memrepo.New()
	c := &countingRepo{Repository: r}
	mux := http.NewServeMux()
	host := newFakeHost(c, "")
	p := New(Config{}).(*scimPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return &testApp{srv: srv, repo: c, orgA: seedTenant(t, c, "alpha"), orgB: seedTenant(t, c, "beta")}, c
}

// seedDirectMember inserts a user + active membership without going through
// SCIM (fast bulk seeding for fan-out tests).
func seedDirectMember(t *testing.T, r repo.Repository, orgID, email string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	u, err := r.CreateUser(ctx, domain.NewUser{
		ID: uID(), Email: email, EmailVerified: true,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		OwnerRoleAuthorized: true,
		ID:                  uID(),
		OrganizationID:      orgID,
		UserID:              u.ID,
		Role:                "member",
		Status:              domain.MembershipActive,
		CreatedAt:           now,
		UpdatedAt:           now,
	}); err != nil {
		t.Fatalf("create membership %s: %v", email, err)
	}
}

func uID() string { return uuid.NewString() }

// TestScim_ListNoFilter_BoundedFanOut is the core Item-3 claim: a no-filter
// page over a 30-member org must cost 5 user reads (the window), not 30 —
// and totalResults must still count the whole org.
func TestScim_ListNoFilter_BoundedFanOut(t *testing.T) {
	app, c := newCountingApp(t)
	for i := 0; i < 30; i++ {
		seedDirectMember(t, app.repo, app.orgA.orgID, fmt.Sprintf("seat%02d@example.com", i))
	}

	resp := app.do(t, "GET", usersPath(app.orgA.orgID)+"?startIndex=1&count=5", app.orgA.apiKey, nil)
	doc := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", resp.StatusCode, doc)
	}
	if got := int(doc["totalResults"].(float64)); got != 31 { // 30 seats + the tenant admin
		t.Fatalf("totalResults = %d, want 31", got)
	}
	res, _ := doc["Resources"].([]any)
	if len(res) != 5 {
		t.Fatalf("Resources len = %d, want 5", len(res))
	}
	if c.userReads != 5 {
		t.Fatalf("GetUserByID calls = %d, want 5 (page window only, not all 31 members)", c.userReads)
	}
	if c.extReads != 5 {
		t.Fatalf("ListExternalIdentitiesByUser calls = %d, want 5", c.extReads)
	}

	// Page 2 draws the NEXT window, not the same five rows.
	before := c.userReads
	resp = app.do(t, "GET", usersPath(app.orgA.orgID)+"?startIndex=6&count=5", app.orgA.apiKey, nil)
	doc2 := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page 2 status = %d, want 200", resp.StatusCode)
	}
	if c.userReads-before != 5 {
		t.Fatalf("page 2 GetUserByID calls = %d, want 5", c.userReads-before)
	}
	res2, _ := doc2["Resources"].([]any)
	if len(res2) != 5 {
		t.Fatalf("page 2 Resources len = %d, want 5", len(res2))
	}
	first := func(d map[string]any) string {
		r, _ := d["Resources"].([]any)
		m, _ := r[0].(map[string]any)
		id, _ := m["id"].(string)
		return id
	}
	if first(doc) == first(doc2) {
		t.Fatalf("page 2 repeats page 1's first row — windowing is not advancing")
	}
}

// TestScim_ListFilter_StillCorrect proves the filtered path keeps full
// filter+pagination semantics: the filter is evaluated over every member and
// the page is drawn from the FILTERED set.
func TestScim_ListFilter_StillCorrect(t *testing.T) {
	app, _ := newCountingApp(t)
	for i := 0; i < 5; i++ {
		seedDirectMember(t, app.repo, app.orgA.orgID, fmt.Sprintf("fseat%02d@example.com", i))
	}

	// One exact match.
	resp := app.do(t, "GET", usersPath(app.orgA.orgID)+`?filter=userName%20eq%20%22fseat03%40example.com%22`, app.orgA.apiKey, nil)
	doc := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", resp.StatusCode, doc)
	}
	if got := int(doc["totalResults"].(float64)); got != 1 {
		t.Fatalf("filtered totalResults = %d, want 1", got)
	}

	// No match → total 0, empty Resources (not null, not 500).
	resp = app.do(t, "GET", usersPath(app.orgA.orgID)+`?filter=userName%20eq%20%22nobody%40example.com%22`, app.orgA.apiKey, nil)
	doc = decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := int(doc["totalResults"].(float64)); got != 0 {
		t.Fatalf("empty-filter totalResults = %d, want 0", got)
	}
}

// hugeOrgRepo presents an org with more memberships than scimListScanCap
// without materializing any users: the cap check must fire BEFORE the
// fan-out, so zero user reads happen on the refused path.
type hugeOrgRepo struct {
	repo.Repository
	memberships []*domain.Membership
	userReads   int
}

func (h *hugeOrgRepo) ListMembershipsByOrg(_ context.Context, _ string) ([]*domain.Membership, error) {
	return h.memberships, nil
}

func (h *hugeOrgRepo) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	h.userReads++
	return h.Repository.GetUserByID(ctx, id)
}

// TestScim_ListFilter_CapRefusesHugeScan pins the defensive cap: a filtered
// query over an org past scimListScanCap gets a loud 400 with NO fan-out,
// while the unfiltered page still serves (windowed before resolution).
func TestScim_ListFilter_CapRefusesHugeScan(t *testing.T) {
	r := memrepo.New()
	tnt := seedTenant(t, r, "huge")
	members := make([]*domain.Membership, 0, scimListScanCap+1)
	for i := 0; i < scimListScanCap+1; i++ {
		members = append(members, &domain.Membership{
			ID: uID(), OrganizationID: tnt.orgID, UserID: uID(),
			Role: "member", Status: domain.MembershipActive,
		})
	}
	h := &hugeOrgRepo{Repository: r, memberships: members}

	mux := http.NewServeMux()
	host := newFakeHost(h, "")
	New(Config{}).(*scimPlugin).Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	app := &testApp{srv: srv, repo: h, orgA: tnt}

	get := func(path string) (int, map[string]any) {
		t.Helper()
		resp := app.do(t, "GET", path, tnt.apiKey, nil)
		return resp.StatusCode, decodeJSON(t, resp)
	}

	status, _ := get(usersPath(tnt.orgID) + `?filter=userName%20eq%20%22x%40example.com%22`)
	if status != http.StatusBadRequest {
		t.Fatalf("filtered list over %d members: status = %d, want 400", len(members), status)
	}
	if h.userReads != 0 {
		t.Fatalf("GetUserByID calls = %d on refused path, want 0 (cap must fire before fan-out)", h.userReads)
	}

	// Unfiltered: the cap does not apply — the window serves from the slice.
	status, doc := get(usersPath(tnt.orgID) + "?startIndex=1&count=5")
	if status != http.StatusOK {
		t.Fatalf("unfiltered list on huge org: status = %d, want 200", status)
	}
	if got := int(doc["totalResults"].(float64)); got != scimListScanCap+1 {
		t.Fatalf("totalResults = %d, want %d (exact, even past the cap)", got, scimListScanCap+1)
	}
}
