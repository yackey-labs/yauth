package organizations

import (
	"github.com/yackey-labs/yauth-go/humaapi"

	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
)

// fakeHost mirrors the lightweight test host used elsewhere in
// plugins/. It backs the plugin against an in-memory repo and a stub
// auth resolver that pins every request to a single user.
type fakeHost struct {
	repo repo.Repository
	mw   *middleware.Middleware
}

func newFakeHost(r repo.Repository) *fakeHost {
	return &fakeHost{repo: r, mw: middleware.New(r, middleware.Config{CookieName: "yauth_session"})}
}

func (h *fakeHost) Repo() repo.Repository                      { return h.repo }
func (h *fakeHost) Middleware() *middleware.Middleware         { return h.mw }
func (h *fakeHost) SessionTTL() time.Duration                  { return time.Hour }
func (h *fakeHost) CookieName() string                         { return "yauth_session" }
func (h *fakeHost) CookieDomain() string                       { return "" }
func (h *fakeHost) CookieSecure() bool                         { return false }
func (h *fakeHost) CookiePath() string                         { return "/" }
func (h *fakeHost) CookieSameSite() http.SameSite              { return http.SameSiteLaxMode }
func (h *fakeHost) SessionBinding() (bool, bool)               { return false, false }
func (h *fakeHost) BaseURL() string                            { return "" }
func (h *fakeHost) AllowSignups() bool                         { return true }
func (h *fakeHost) AutoAdminFirstUser() bool                   { return false }
func (h *fakeHost) RegisterEventHandler(_ events.Handler)      {}
func (h *fakeHost) RegisterAuthResolver(r plugin.AuthResolver) { h.mw.AddResolver(r) }
func (h *fakeHost) PluginNames() []string                      { return nil }
func (h *fakeHost) JWTSigner() plugin.JWTSigner                { return nil }
func (h *fakeHost) JWTSecret() []byte                          { return nil }
func (h *fakeHost) Emit(_ context.Context, _ events.AuthEvent) (events.Decision, error) {
	return events.Continue(), nil
}
func (h *fakeHost) RateLimit(name string, max int, window time.Duration) func(http.Handler) http.Handler {
	return middleware.RateLimit(h.repo, name, max, window)
}

var _ plugin.PluginHost = (*fakeHost)(nil)

// stubResolver authenticates every request as the supplied user.
type stubResolver struct{ user *domain.AuthUser }

func (s *stubResolver) Name() string { return "stub" }
func (s *stubResolver) Resolve(_ *http.Request) (*domain.AuthUser, bool, error) {
	return s.user, true, nil
}

var _ middleware.AuthResolver = (*stubResolver)(nil)

// newTestServer wires the organizations plugin onto a fresh in-memory
// repo with the given AuthUser stubbed in. Returns the server, the
// repo, and a cleanup-free close handle.
func newTestServer(t *testing.T, user domain.User) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})

	mux := http.NewServeMux()
	p := New(Config{}).(*orgsPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

func seededUser() domain.User {
	return domain.User{
		ID:        uuid.NewString(),
		Email:     "owner@example.com",
		Role:      "user",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

func doJSON(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return res
}

func decode(t *testing.T, res *http.Response, v any) {
	t.Helper()
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestCreateOrgMakesCallerOwner(t *testing.T) {
	// Post-#88: creator is promoted to "owner" (was "admin" in
	// #87). owner is a strict superset of admin under the default
	// permission catalogue, so any prior admin-gated endpoint still
	// passes for the creator.
	user := seededUser()
	srv, r := newTestServer(t, user)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{
		"name": "Acme", "slug": "acme",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d", res.StatusCode)
	}
	var got organizationJSON
	decode(t, res, &got)
	if got.Slug != "acme" || got.Name != "Acme" {
		t.Fatalf("create response: %+v", got)
	}
	m, err := r.GetMembershipByOrgUser(context.Background(), got.ID, user.ID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m == nil {
		t.Fatal("expected creator membership row")
	}
	if m.Role != RoleOwner {
		t.Fatalf("expected owner role, got %q", m.Role)
	}
}

func TestCreateOrgSlugConflict(t *testing.T) {
	user := seededUser()
	srv, _ := newTestServer(t, user)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "x"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("first create: %d", res.StatusCode)
	}
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "B", "slug": "X"})
	if res.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("want 409, got %d body=%s", res.StatusCode, body)
	}
}

func TestGetOrgRequiresMembership(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	// Create an org with a different owner — caller isn't a member.
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "other-org", Name: "Other", Slug: "other", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	res := doJSON(t, http.MethodGet, srv.URL+"/organizations/other-org", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", res.StatusCode)
	}
}

func TestListOrgsReturnsOnlyCallerOrgs(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	// One org owned by caller.
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Mine", "slug": "mine"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", res.StatusCode)
	}
	// One org caller isn't a member of.
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "stranger-org", Name: "Stranger", Slug: "stranger", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed other: %v", err)
	}
	res = doJSON(t, http.MethodGet, srv.URL+"/organizations", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: %d", res.StatusCode)
	}
	var out struct {
		Organizations []organizationJSON `json:"organizations"`
	}
	decode(t, res, &out)
	if len(out.Organizations) != 1 || out.Organizations[0].Slug != "mine" {
		t.Fatalf("unexpected list: %+v", out)
	}
}

func TestUpdateOrgRequiresAdmin(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	// Create org via API; caller is owner.
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)
	// Seed a second owner so we can demote the original owner —
	// the repo enforces owner-protection on the last owner.
	now := time.Now().UTC()
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		ID: "co-owner-mem", OrganizationID: org.ID, UserID: "co-owner",
		Role: RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed co-owner: %v", err)
	}
	mem, _ := r.GetMembershipByOrgUser(context.Background(), org.ID, user.ID)
	memberRole := RoleMember
	if _, err := r.UpdateMembership(context.Background(), mem.ID, domain.UpdateMembership{Role: &memberRole}); err != nil {
		t.Fatalf("demote: %v", err)
	}
	newName := "B"
	res = doJSON(t, http.MethodPatch, srv.URL+"/organizations/"+org.ID, map[string]string{"name": newName})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", res.StatusCode)
	}
}

func TestDeleteOrgCascades(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)

	// Add a second member directly.
	now := time.Now().UTC()
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		ID: "m2", OrganizationID: org.ID, UserID: "other-user", Role: "member",
		Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed second member: %v", err)
	}
	res = doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+org.ID, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", res.StatusCode)
	}
	got, _ := r.GetOrganizationByID(context.Background(), org.ID)
	if got != nil {
		t.Fatal("org should be gone")
	}
	m, _ := r.GetMembershipByOrgUser(context.Background(), org.ID, "other-user")
	if m != nil {
		t.Fatal("memberships should be cascaded")
	}
}

func TestInvitationAcceptFlow(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/invitations", map[string]string{
		"email": "invitee@example.com",
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create invitation: %d body=%s", res.StatusCode, body)
	}
	var created createInvitationResponse
	decode(t, res, &created)
	if created.Token == "" {
		t.Fatal("token must be non-empty in create response")
	}
	if created.Invitation.Role != RoleMember {
		t.Fatalf("default role: %q", created.Invitation.Role)
	}

	// Switch to the invitee user and accept.
	inviteeUser := domain.User{
		ID: uuid.NewString(), Email: "invitee@example.com", Role: "user",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	srv2 := newTestServerWithSharedRepo(t, inviteeUser, r)
	res = doJSON(t, http.MethodPost, srv2.URL+"/invitations/accept", map[string]string{"token": created.Token})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("accept: %d body=%s", res.StatusCode, body)
	}
	var mem membershipJSON
	decode(t, res, &mem)
	if mem.OrganizationID != org.ID || mem.UserID != inviteeUser.ID || mem.Role != RoleMember {
		t.Fatalf("membership shape: %+v", mem)
	}

	// Single-shot: second accept rejects.
	res = doJSON(t, http.MethodPost, srv2.URL+"/invitations/accept", map[string]string{"token": created.Token})
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 on second accept, got %d", res.StatusCode)
	}
}

func TestInvitationEmailMismatch(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/invitations", map[string]string{"email": "invitee@example.com"})
	var created createInvitationResponse
	decode(t, res, &created)

	wrong := domain.User{
		ID: uuid.NewString(), Email: "intruder@example.com", Role: "user",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	srv2 := newTestServerWithSharedRepo(t, wrong, r)
	res = doJSON(t, http.MethodPost, srv2.URL+"/invitations/accept", map[string]string{"token": created.Token})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", res.StatusCode)
	}
}

func TestInvitationEmailMatchIsCaseInsensitive(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/invitations", map[string]string{"email": "Invitee@Example.com"})
	var created createInvitationResponse
	decode(t, res, &created)

	invitee := domain.User{
		ID: uuid.NewString(), Email: "invitee@example.COM", Role: "user",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	srv2 := newTestServerWithSharedRepo(t, invitee, r)
	res = doJSON(t, http.MethodPost, srv2.URL+"/invitations/accept", map[string]string{"token": created.Token})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("want 201, got %d body=%s", res.StatusCode, body)
	}
}

func TestUnauthenticatedReturns401(t *testing.T) {
	// Bypass the stub resolver — point at a fresh server without any
	// resolver registered.
	r := memrepo.New()
	host := newFakeHost(r)
	mux := http.NewServeMux()
	New(Config{}).(*orgsPlugin).Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	res := doJSON(t, http.MethodGet, srv.URL+"/organizations", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

func TestCreateOrgValidatesPayload(t *testing.T) {
	srv, _ := newTestServer(t, seededUser())
	for _, tc := range []struct {
		name string
		body map[string]string
	}{
		{"missing name", map[string]string{"slug": "x"}},
		{"missing slug", map[string]string{"name": "x"}},
		{"blank name", map[string]string{"name": "   ", "slug": "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := doJSON(t, http.MethodPost, srv.URL+"/organizations", tc.body)
			if res.StatusCode != http.StatusBadRequest {
				body, _ := io.ReadAll(res.Body)
				t.Fatalf("want 400, got %d body=%s", res.StatusCode, body)
			}
		})
	}
}

// newTestServerWithSharedRepo binds a second server to an existing repo
// — used to switch the "authenticated user" between requests in the
// invitation-accept flow.
func newTestServerWithSharedRepo(t *testing.T, user domain.User, r repo.Repository) *httptest.Server {
	t.Helper()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})
	mux := http.NewServeMux()
	New(Config{}).(*orgsPlugin).Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
