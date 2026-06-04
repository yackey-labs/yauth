// scim_test.go — integration coverage for the SCIM plugin.
//
// Mirrors yauth Rust feat/95-scim's crates/yauth/tests/scim.rs. Spins
// up an httptest server with memrepo, seeds an org-scoped API key, and
// drives the full Users + Groups + meta surface end-to-end.
package scim

import (
	"github.com/yackey-labs/yauth/humaapi"

	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- fakeHost -----------------------------------------------------------

type fakeHost struct {
	repo repo.Repository
	mw   *middleware.Middleware
	base string
}

func newFakeHost(r repo.Repository, base string) *fakeHost {
	return &fakeHost{repo: r, mw: middleware.New(r, middleware.Config{CookieName: "yauth_session"}), base: base}
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
func (h *fakeHost) BaseURL() string                            { return h.base }
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

// --- tenant fixture -----------------------------------------------------

type tenant struct {
	orgID    string
	adminID  string
	apiKey   string // full plaintext bearer
	apiKeyID string // row id (for revoke tests)
}

func seedTenant(t *testing.T, r repo.Repository, label string) tenant {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	admin, err := r.CreateUser(ctx, domain.NewUser{
		ID:            uuid.NewString(),
		Email:         "admin-" + label + "@example.com",
		Role:          "admin",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	org, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: label + " org", Slug: label + "-" + uuid.NewString()[:6],
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID:             uuid.NewString(),
		OrganizationID: org.ID,
		UserID:         admin.ID,
		Role:           auth.RoleOwner,
		Status:         domain.MembershipActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("create membership: %v", err)
	}

	// Mint an org-scoped API key. The shape is "yak_<8hex>_<32hex>";
	// we don't need real entropy for the test — fixed hex is fine.
	prefix := "abcd" + label[:1] + "ef0"
	if len(prefix) < 8 {
		prefix = prefix + "0000"
	}
	prefix = prefix[:8]
	secret := "0123456789abcdef" + label[:1] + "23456789abcdef0" // 32 hex chars approx
	for len(secret) < 32 {
		secret += "0"
	}
	secret = secret[:32]
	// Ensure hex correctness — fall back to a guaranteed hex string.
	if !isHexLower(prefix) || !isHexLower(secret) {
		prefix = "deadbeef"
		secret = "0123456789abcdef0123456789abcdef"
	}
	hash := hashSecret(secret)
	full := "yak_" + prefix + "_" + secret
	orgIDStr := org.ID
	roleStr := "admin"
	keyID := uuid.NewString()
	if err := r.CreateAPIKey(ctx, domain.NewAPIKey{
		ID:              keyID,
		OrganizationID:  &orgIDStr,
		KeyPrefix:       prefix,
		KeyHash:         hash,
		Name:            "SCIM connector " + label,
		Role:            &roleStr,
		CreatedAt:       now,
		CreatedByUserID: admin.ID,
	}); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	return tenant{orgID: org.ID, adminID: admin.ID, apiKey: full, apiKeyID: keyID}
}

// --- HTTP helper --------------------------------------------------------

type testApp struct {
	srv  *httptest.Server
	repo repo.Repository
	orgA tenant
	orgB tenant
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	r := memrepo.New()
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	p := New(Config{}).(*scimPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return &testApp{srv: srv, repo: r, orgA: seedTenant(t, r, "alpha"), orgB: seedTenant(t, r, "beta")}
}

func (a *testApp) do(t *testing.T, method, path, bearer string, body any) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		switch v := body.(type) {
		case []byte:
			rdr = bytes.NewReader(v)
		case string:
			rdr = bytes.NewReader([]byte(v))
		default:
			buf, _ := json.Marshal(body)
			rdr = bytes.NewReader(buf)
		}
	}
	req, err := http.NewRequest(method, a.srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return m
}

func usersPath(orgID string) string { return "/api/scim/v2/organizations/" + orgID + "/Users" }
func userPath(orgID, uid string) string {
	return usersPath(orgID) + "/" + uid
}
func groupsPath(orgID string) string { return "/api/scim/v2/organizations/" + orgID + "/Groups" }
func metaPath(orgID, leaf string) string {
	return "/api/scim/v2/organizations/" + orgID + "/" + leaf
}

// --- Happy-path tests --------------------------------------------------

func TestCreateUser_CreatesUserAndMembership(t *testing.T) {
	app := newTestApp(t)
	body := map[string]any{
		"schemas":    []string{CoreUserSchema},
		"userName":   "alice@example.com",
		"externalId": "okta-alice",
		"emails": []map[string]any{
			{"value": "alice@example.com", "primary": true},
		},
		"displayName": "Alice Wonderland",
	}
	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d want 201", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != ScimContentType {
		t.Fatalf("content-type: got %q want %q", ct, ScimContentType)
	}
	m := decodeJSON(t, resp)
	if m["id"] == nil {
		t.Fatal("response missing id")
	}
	if m["userName"] != "alice@example.com" {
		t.Fatalf("userName: got %v", m["userName"])
	}
}

func TestGetUser_Returns404ForUnknown(t *testing.T) {
	app := newTestApp(t)
	resp := app.do(t, "GET", userPath(app.orgA.orgID, uuid.NewString()), app.orgA.apiKey, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", resp.StatusCode)
	}
}

func TestListUsers_FiltersOnUserName(t *testing.T) {
	app := newTestApp(t)
	for _, u := range []string{"alice@x.com", "bob@x.com", "carol@x.com"} {
		body := map[string]any{
			"schemas":  []string{CoreUserSchema},
			"userName": u,
			"emails":   []map[string]any{{"value": u, "primary": true}},
		}
		resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("seed %s: %d", u, resp.StatusCode)
		}
		resp.Body.Close()
	}
	resp := app.do(t, "GET", usersPath(app.orgA.orgID)+`?filter=userName%20eq%20%22alice@x.com%22`, app.orgA.apiKey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if got, want := m["totalResults"], float64(1); got != want {
		t.Fatalf("totalResults: got %v want %v", got, want)
	}
}

func TestPutUser_UpdatesDisplayName(t *testing.T) {
	app := newTestApp(t)
	create := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": "donna@x.com",
		"emails":   []map[string]any{{"value": "donna@x.com", "primary": true}},
	})
	cm := decodeJSON(t, create)
	uid := cm["id"].(string)

	put := app.do(t, "PUT", userPath(app.orgA.orgID, uid), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreUserSchema},
		"userName":    "donna@x.com",
		"emails":      []map[string]any{{"value": "donna@x.com", "primary": true}},
		"displayName": "Donna PUT",
	})
	if put.StatusCode != http.StatusOK {
		t.Fatalf("put status: got %d want 200", put.StatusCode)
	}
	pm := decodeJSON(t, put)
	if pm["displayName"] != "Donna PUT" {
		t.Fatalf("displayName: got %v want %q", pm["displayName"], "Donna PUT")
	}
}

func TestPatchUser_DisplayName(t *testing.T) {
	app := newTestApp(t)
	create := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": "edward@x.com",
		"emails":   []map[string]any{{"value": "edward@x.com", "primary": true}},
	})
	cm := decodeJSON(t, create)
	uid := cm["id"].(string)

	patch := app.do(t, "PATCH", userPath(app.orgA.orgID, uid), app.orgA.apiKey, map[string]any{
		"schemas": []string{PatchOpSchema},
		"Operations": []map[string]any{
			{"op": "replace", "path": "displayName", "value": "Eddy"},
		},
	})
	if patch.StatusCode != http.StatusOK {
		t.Fatalf("patch status: got %d want 200", patch.StatusCode)
	}
	pm := decodeJSON(t, patch)
	if pm["displayName"] != "Eddy" {
		t.Fatalf("displayName: got %v want %q", pm["displayName"], "Eddy")
	}
}

func TestPatchUser_ActiveFalseSuspends(t *testing.T) {
	app := newTestApp(t)
	create := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": "fox@x.com",
		"emails":   []map[string]any{{"value": "fox@x.com", "primary": true}},
	})
	cm := decodeJSON(t, create)
	uid := cm["id"].(string)

	patch := app.do(t, "PATCH", userPath(app.orgA.orgID, uid), app.orgA.apiKey, map[string]any{
		"schemas": []string{PatchOpSchema},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": false},
		},
	})
	if patch.StatusCode != http.StatusOK {
		t.Fatalf("patch status: %d", patch.StatusCode)
	}
	pm := decodeJSON(t, patch)
	if pm["active"] != false {
		t.Fatalf("active: got %v want false", pm["active"])
	}
}

func TestDeleteUser_RemovesMembership(t *testing.T) {
	app := newTestApp(t)
	create := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": "george@x.com",
		"emails":   []map[string]any{{"value": "george@x.com", "primary": true}},
	})
	cm := decodeJSON(t, create)
	uid := cm["id"].(string)
	del := app.do(t, "DELETE", userPath(app.orgA.orgID, uid), app.orgA.apiKey, nil)
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status: got %d want 204", del.StatusCode)
	}
	// User row should still exist but the membership is gone.
	get := app.do(t, "GET", userPath(app.orgA.orgID, uid), app.orgA.apiKey, nil)
	if get.StatusCode != http.StatusNotFound {
		t.Fatalf("get-after-delete: got %d want 404", get.StatusCode)
	}
}

func TestCreateGroup_AddMember_List(t *testing.T) {
	app := newTestApp(t)
	// Provision a user (org member by default).
	create := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": "g1@x.com",
		"emails":   []map[string]any{{"value": "g1@x.com", "primary": true}},
	})
	uid := decodeJSON(t, create)["id"].(string)

	// Create a real, named group.
	gresp := app.do(t, "POST", groupsPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreGroupSchema},
		"displayName": "Engineering",
		"externalId":  "ext-eng",
	})
	if gresp.StatusCode != http.StatusCreated {
		t.Fatalf("create group status: %d", gresp.StatusCode)
	}
	gid := decodeJSON(t, gresp)["id"].(string)

	// Add the user via PATCH members.
	patch := app.do(t, "PATCH", groupsPath(app.orgA.orgID)+"/"+gid, app.orgA.apiKey, map[string]any{
		"schemas": []string{PatchOpSchema},
		"Operations": []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{{"value": uid}}},
		},
	})
	if patch.StatusCode != http.StatusOK {
		t.Fatalf("patch status: %d", patch.StatusCode)
	}

	// GET the group → the user is a member.
	got := app.do(t, "GET", groupsPath(app.orgA.orgID)+"/"+gid, app.orgA.apiKey, nil)
	members, _ := decodeJSON(t, got)["members"].([]any)
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}

	// Group membership must NOT change the org role (decoupled).
	mem, err := app.repo.GetMembershipByOrgUser(context.Background(), app.orgA.orgID, uid)
	if err != nil || mem == nil {
		t.Fatal(err)
	}
	if mem.Role != auth.RoleMember {
		t.Fatalf("group membership must not change org role: got %q", mem.Role)
	}
}

func TestDeleteGroup(t *testing.T) {
	app := newTestApp(t)
	gresp := app.do(t, "POST", groupsPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreGroupSchema},
		"displayName": "Temp",
	})
	gid := decodeJSON(t, gresp)["id"].(string)

	del := app.do(t, "DELETE", groupsPath(app.orgA.orgID)+"/"+gid, app.orgA.apiKey, nil)
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status: %d", del.StatusCode)
	}
	got := app.do(t, "GET", groupsPath(app.orgA.orgID)+"/"+gid, app.orgA.apiKey, nil)
	if got.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", got.StatusCode)
	}
}

func TestMeta_ServiceProviderConfig(t *testing.T) {
	app := newTestApp(t)
	resp := app.do(t, "GET", metaPath(app.orgA.orgID, "ServiceProviderConfig"), app.orgA.apiKey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["filter"] == nil {
		t.Fatal("expected filter capability")
	}
}

// --- Unit tests for clamp + parser ---------------------------------------

func TestClampPagination_Defaults(t *testing.T) {
	start, count := clampPagination(nil, nil)
	if start != 1 || count != defaultItemsPerPage {
		t.Fatalf("got (%d,%d)", start, count)
	}
}

func TestClampPagination_LowStartClampsToOne(t *testing.T) {
	for _, v := range []int64{0, -5, -99} {
		v := v
		start, _ := clampPagination(&v, nil)
		if start != 1 {
			t.Fatalf("start[%d]: got %d want 1", v, start)
		}
	}
}

func TestClampPagination_CountCappedAtMax(t *testing.T) {
	huge := int64(99_999_999)
	_, count := clampPagination(nil, &huge)
	if count != maxItemsPerPage {
		t.Fatalf("count: got %d want %d", count, maxItemsPerPage)
	}
}

func TestClampPagination_LargeStartNoOverflow(t *testing.T) {
	v := int64(9_007_199_254_740_992)
	start, _ := clampPagination(&v, nil)
	if start < 1 {
		t.Fatalf("start: got %d, expected >= 1", start)
	}
}

func TestParseFilter_RejectsOr(t *testing.T) {
	_, e := ParseFilter(`a eq "x" or b eq "y"`)
	if e == nil || e.ScimType != "invalidFilter" {
		t.Fatalf("expected invalidFilter, got %+v", e)
	}
}

func TestParseFilter_AcceptsAnd(t *testing.T) {
	f, e := ParseFilter(`userName sw "al" and active eq true`)
	if e != nil {
		t.Fatalf("unexpected err: %+v", e)
	}
	if len(f.Atoms) != 2 {
		t.Fatalf("atoms: %d", len(f.Atoms))
	}
}

func TestParseFilter_RejectsBacktick(t *testing.T) {
	_, e := ParseFilter("userName eq `alice`")
	if e == nil {
		t.Fatal("backtick must be rejected")
	}
}

func TestValidateSchemas_RejectsUnknown(t *testing.T) {
	_, ok := ValidateSchemas([]string{CoreUserSchema, "urn:custom:made-up:1.0"}, CoreUserSchema)
	if ok {
		t.Fatal("unknown URN must be rejected")
	}
}

func TestValidateSchemas_RejectsMissingPrimary(t *testing.T) {
	_, ok := ValidateSchemas([]string{EnterpriseUserSchema}, CoreUserSchema)
	if ok {
		t.Fatal("missing primary must be rejected")
	}
}

func TestCanonicalEmail_PrefersPrimary(t *testing.T) {
	p1 := false
	p2 := true
	u := &ScimUser{
		Emails: []ScimEmail{
			{Value: "first@x.com", Primary: &p1},
			{Value: "primary@x.com", Primary: &p2},
		},
	}
	if u.CanonicalEmail() != "primary@x.com" {
		t.Fatalf("got %q", u.CanonicalEmail())
	}
}

func TestPickDisplayName_PrefersDisplayName(t *testing.T) {
	u := &ScimUser{
		DisplayName: "Alice Wonderland",
		Name:        &ScimName{GivenName: "Alice", FamilyName: "Other"},
	}
	if u.PickDisplayName() != "Alice Wonderland" {
		t.Fatalf("got %q", u.PickDisplayName())
	}
}

func TestScimError_RoundTrip(t *testing.T) {
	e := NewScimErrorBody(404, "noTarget", "not found")
	buf, _ := json.Marshal(e)
	got := string(buf)
	for _, want := range []string{ErrorSchema, `"status":"404"`, `"scimType":"noTarget"`} {
		if !bytes.Contains(buf, []byte(want)) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
}

func TestListResponse_CarriesURN(t *testing.T) {
	lr := NewListResponse(0, 1, 100, []ScimUser{})
	buf, _ := json.Marshal(lr)
	if !bytes.Contains(buf, []byte(ListResponseSchema)) {
		t.Fatalf("missing list response URN: %s", buf)
	}
}

// Belt-and-braces: clientside sanity that 2*hex prefix shape compiles.
func TestParseAPIKeyToken_AcceptsCanonicalShape(t *testing.T) {
	p, s, ok := parseAPIKeyToken("yak_deadbeef_0123456789abcdef0123456789abcdef", "yak")
	if !ok || p != "deadbeef" || s != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("got (%q,%q,%v)", p, s, ok)
	}
}

func TestParseAPIKeyToken_RejectsTwoParts(t *testing.T) {
	if _, _, ok := parseAPIKeyToken("yak_deadbeef", "yak"); ok {
		t.Fatal("two-part token must be rejected")
	}
}

func TestParseAPIKeyToken_RejectsWrongPrefix(t *testing.T) {
	if _, _, ok := parseAPIKeyToken("badtag_deadbeef_0123456789abcdef0123456789abcdef", "yak"); ok {
		t.Fatal("wrong tag must be rejected")
	}
}

// Touch a few signatures we want to keep compiling without referencing
// them above; avoids dead-imports breaking the build.
var _ = fmt.Sprintf
