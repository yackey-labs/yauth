package organizations

import (
	"github.com/yackey-labs/yauth-go/humaapi"

	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
)

// seedOrgAndMembership creates an organization plus an active
// membership for the caller in a single helper used by the active-org
// switcher tests.
func seedOrgAndMembership(t *testing.T, r repo.Repository, userID, orgID, name, slug, role string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgID, Name: name, Slug: slug, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org %q: %v", slug, err)
	}
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: userID,
		Role: role, Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership %q: %v", slug, err)
	}
}

// newTestServerSessionBound builds a server where the stub resolver
// authenticates as a user with a populated Session row — exercises
// the cookie-flow code path that persists active_org_id on the
// session. Pairs with newTestServer (bearer-style, empty Session).
func newTestServerSessionBound(t *testing.T, user domain.User) (*httptest.Server, repo.Repository, string) {
	t.Helper()
	r := memrepo.New()
	sessionID := uuid.NewString()
	now := time.Now().UTC()
	if err := r.CreateSession(context.Background(), domain.NewSession{
		ID: sessionID, UserID: user.ID, TokenHash: "h-" + sessionID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	host := newFakeHost(r)
	au := &domain.AuthUser{
		User: user,
		Session: domain.Session{
			ID: sessionID, UserID: user.ID, TokenHash: "h-" + sessionID,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		},
		Method: domain.AuthMethodCookie,
	}
	host.mw.AddResolver(&stubResolver{user: au})

	mux := http.NewServeMux()
	p := New(Config{}).(*orgsPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r, sessionID
}

// ---- GET /sessions/active-org ----

func TestGetActiveOrg_NoMemberships(t *testing.T) {
	user := seededUser()
	srv, _ := newTestServer(t, user)
	res := doJSON(t, http.MethodGet, srv.URL+"/sessions/active-org", nil)
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	var got activeOrgResponse
	decode(t, res, &got)
	if got.ActiveOrgID != nil {
		t.Fatalf("expected nil active org; got %v", *got.ActiveOrgID)
	}
	if len(got.Orgs) != 0 {
		t.Fatalf("expected empty memberships; got %d", len(got.Orgs))
	}
}

func TestGetActiveOrg_ListsAllOrgs_Sorted(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	seedOrgAndMembership(t, r, user.ID, "org-a", "Beta", "beta", "member")
	seedOrgAndMembership(t, r, user.ID, "org-b", "Apex", "apex", "owner")

	res := doJSON(t, http.MethodGet, srv.URL+"/sessions/active-org", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", res.StatusCode)
	}
	var got activeOrgResponse
	decode(t, res, &got)
	if len(got.Orgs) != 2 {
		t.Fatalf("expected 2 memberships; got %d", len(got.Orgs))
	}
	// Deterministic sort: by name (case-insensitive).
	if got.Orgs[0].Slug != "apex" || got.Orgs[1].Slug != "beta" {
		t.Fatalf("unexpected order: %+v", got.Orgs)
	}
}

// ---- POST /sessions/active-org ----

func TestSetActiveOrg_ForbidsNonMember(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "stranger", Name: "Stranger", Slug: "stranger", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res := doJSON(t, http.MethodPost, srv.URL+"/sessions/active-org", map[string]string{
		"organization_id": "stranger",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", res.StatusCode)
	}
}

func TestSetActiveOrg_RequiresOrganizationID(t *testing.T) {
	user := seededUser()
	srv, _ := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/sessions/active-org", map[string]string{})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", res.StatusCode)
	}
}

func TestSetActiveOrg_ForbidsSuspendedMembership(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "org-a", Name: "Apex", Slug: "apex", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: "org-a", UserID: user.ID,
		Role: "member", Status: domain.MembershipSuspended,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	res := doJSON(t, http.MethodPost, srv.URL+"/sessions/active-org", map[string]string{
		"organization_id": "org-a",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for suspended membership, got %d", res.StatusCode)
	}
}

func TestSetActiveOrg_HappyPath_Bearer(t *testing.T) {
	// AuthUser has no Session.ID — simulates a bearer-style caller.
	// The endpoint MUST still succeed (returns the new active-org
	// payload) but MUST NOT try to persist to a session row.
	user := seededUser()
	srv, r := newTestServer(t, user)
	seedOrgAndMembership(t, r, user.ID, "org-a", "Apex", "apex", "owner")

	res := doJSON(t, http.MethodPost, srv.URL+"/sessions/active-org", map[string]string{
		"organization_id": "org-a",
	})
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	var got activeOrgResponse
	decode(t, res, &got)
	if got.ActiveOrgID == nil || *got.ActiveOrgID != "org-a" {
		t.Fatalf("expected ActiveOrgID=org-a; got %+v", got)
	}
	if got.Role == nil || *got.Role != "owner" {
		t.Fatalf("expected Role=owner; got %+v", got.Role)
	}
}

func TestSetActiveOrg_HappyPath_Cookie_PersistsToSession(t *testing.T) {
	// Cookie-flow: AuthUser carries a populated Session row, so the
	// switcher MUST persist active_org_id on the session.
	user := seededUser()
	srv, r, sessionID := newTestServerSessionBound(t, user)
	seedOrgAndMembership(t, r, user.ID, "org-a", "Apex", "apex", "admin")

	res := doJSON(t, http.MethodPost, srv.URL+"/sessions/active-org", map[string]string{
		"organization_id": "org-a",
	})
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	// Session row's ActiveOrgID must now be set.
	got, err := r.GetSessionByID(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSessionByID: %v", err)
	}
	if got.ActiveOrgID == nil || *got.ActiveOrgID != "org-a" {
		t.Fatalf("expected session.ActiveOrgID=org-a; got %+v", got.ActiveOrgID)
	}
}

// ---- DELETE /sessions/active-org ----

func TestClearActiveOrg_Bearer(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	seedOrgAndMembership(t, r, user.ID, "org-a", "Apex", "apex", "owner")

	res := doJSON(t, http.MethodDelete, srv.URL+"/sessions/active-org", nil)
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status=%d body=%s", res.StatusCode, body)
	}
	var got activeOrgResponse
	decode(t, res, &got)
	if got.ActiveOrgID != nil {
		t.Fatalf("expected nil active org; got %v", *got.ActiveOrgID)
	}
	if len(got.Orgs) != 1 {
		t.Fatalf("expected memberships unchanged; got %d", len(got.Orgs))
	}
}

func TestClearActiveOrg_Cookie_PersistsNilToSession(t *testing.T) {
	user := seededUser()
	srv, r, sessionID := newTestServerSessionBound(t, user)
	seedOrgAndMembership(t, r, user.ID, "org-a", "Apex", "apex", "member")
	// Pre-set an active org on the session row.
	orgA := "org-a"
	if err := r.SetSessionActiveOrg(context.Background(), sessionID, &orgA); err != nil {
		t.Fatalf("pre-set active org: %v", err)
	}

	res := doJSON(t, http.MethodDelete, srv.URL+"/sessions/active-org", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", res.StatusCode)
	}
	got, err := r.GetSessionByID(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSessionByID: %v", err)
	}
	if got.ActiveOrgID != nil {
		t.Fatalf("expected session.ActiveOrgID=nil; got %v", *got.ActiveOrgID)
	}
}

// ---- Plugin gating ----

func TestPluginGating_RoutesOnlyMountedWithPlugin(t *testing.T) {
	// Without the organizations plugin registered the switcher routes
	// MUST not exist — the mux returns 404 instead of routing into
	// the active-org handlers. Spin up a bare server with only an
	// auth resolver in place.
	r := memrepo.New()
	user := seededUser()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})
	mux := http.NewServeMux()
	// No organizations plugin mounted.
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	res := doJSON(t, http.MethodGet, srv.URL+"/sessions/active-org", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 without plugin; got %d", res.StatusCode)
	}
}
