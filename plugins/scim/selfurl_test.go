// selfurl_test.go — locks the self-referential SCIM URL contract: the
// Location header and members[].$ref must be absolute and carry the mount
// prefix (Config.BasePath), i.e. <origin><BasePath>/scim/v2/... — NOT the
// old bare-origin /api/scim/v2 form that pointed at a non-existent path.
package scim

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func TestSelfBaseURL(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		basePath string
		want     string
	}{
		{"prefix", "https://idp.example.com", "/api/auth", "https://idp.example.com/api/auth"},
		{"root mount (empty BasePath)", "https://idp.example.com", "", "https://idp.example.com"},
		{"trailing slash on base trimmed", "https://idp.example.com/", "/api/auth", "https://idp.example.com/api/auth"},
		{"custom prefix", "https://idp.example.com", "/auth", "https://idp.example.com/auth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Config{BasePath: tc.basePath}).(*scimPlugin)
			h := newFakeHost(memrepo.New(), tc.base)
			if got := p.selfBaseURL(h); got != tc.want {
				t.Fatalf("selfBaseURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// newTestAppWithBasePath mirrors newTestApp but sets Config.BasePath so the
// self-ref URLs in responses are exercised against a real mount prefix.
func newTestAppWithBasePath(t *testing.T, basePath string) *testApp {
	t.Helper()
	r := memrepo.New()
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	p := New(Config{BasePath: basePath}).(*scimPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return &testApp{srv: srv, repo: r, orgA: seedTenant(t, r, "alpha"), orgB: seedTenant(t, r, "beta")}
}

func TestCreateUser_LocationCarriesMountPrefix(t *testing.T) {
	app := newTestAppWithBasePath(t, "/api/auth")
	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":    []string{CoreUserSchema},
		"userName":   "alice@example.com",
		"externalId": "okta-alice",
		"emails":     []map[string]any{{"value": "alice@example.com", "primary": true}},
	})
	if resp.StatusCode != 201 {
		t.Fatalf("create user: %d", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("no id in response: %v", body)
	}
	meta, _ := body["meta"].(map[string]any)
	loc, _ := meta["location"].(string)

	want := app.srv.URL + "/api/auth/scim/v2/organizations/" + app.orgA.orgID + "/Users/" + id
	if loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
	// Regression guard: the old bare-origin /api/scim/v2 form must be gone.
	if strings.Contains(loc, "/api/scim/v2") || !strings.Contains(loc, "/api/auth/scim/v2") {
		t.Fatalf("Location has wrong shape: %q", loc)
	}
}

func TestGroupMemberRef_IsAbsoluteWithMountPrefix(t *testing.T) {
	app := newTestAppWithBasePath(t, "/api/auth")

	// Seed a user to be a group member.
	uresp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":    []string{CoreUserSchema},
		"userName":   "bob@example.com",
		"externalId": "okta-bob",
		"emails":     []map[string]any{{"value": "bob@example.com", "primary": true}},
	})
	if uresp.StatusCode != 201 {
		t.Fatalf("create user: %d", uresp.StatusCode)
	}
	uid, _ := decodeJSON(t, uresp)["id"].(string)

	gresp := app.do(t, "POST", groupsPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreGroupSchema},
		"displayName": "Engineering",
		"members":     []map[string]any{{"value": uid}},
	})
	if gresp.StatusCode != 201 {
		t.Fatalf("create group: %d", gresp.StatusCode)
	}
	body := decodeJSON(t, gresp)
	members, _ := body["members"].([]any)
	if len(members) != 1 {
		t.Fatalf("want 1 member, got %v", body["members"])
	}
	m0, _ := members[0].(map[string]any)
	ref, _ := m0["$ref"].(string)

	want := app.srv.URL + "/api/auth/scim/v2/organizations/" + app.orgA.orgID + "/Users/" + uid
	if ref != want {
		t.Fatalf("$ref = %q, want %q", ref, want)
	}
}
