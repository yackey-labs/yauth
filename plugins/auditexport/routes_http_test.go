package auditexport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/auditexport"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// routeEnv stands up the auditexport plugin behind the full yauth router so the
// huma operations are exercised end-to-end (auth gate, path-param validation,
// status codes). This is the coverage the unit-level pentest tests lack: it
// proves every migrated route actually serves and that the global variants do
// NOT 422 on a missing {org_id} path param.
type routeEnv struct {
	srv  *httptest.Server
	repo *memrepo.Repo
	stop func()
}

func newRouteEnv(t *testing.T) *routeEnv {
	t.Helper()
	r := memrepo.New()

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(auditexport.New(auditexport.Config{})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return &routeEnv{srv: srv, repo: r, stop: func() { srv.Close() }}
}

// seedAdmin creates an admin user + session and returns (cookie, adminID).
// The ID lets tests assert actor attribution on audit-log rows (the migration
// moved actorID from the stashed request to the operation ctx — this is how we
// prove the resolved admin still reaches auditEvent).
func (e *routeEnv) seedAdmin(t *testing.T) (cookie, adminID string) {
	t.Helper()
	now := time.Now().UTC()
	u, err := e.repo.CreateUser(context.Background(), domain.NewUser{
		ID:        uuid.NewString(),
		Email:     "admin@example.com",
		Role:      "admin",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	raw, _, err := auth.IssueSession(context.Background(), e.repo, u.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return raw, u.ID
}

func (e *routeEnv) do(t *testing.T, method, path, cookie string, body any) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func bodyOf(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

// TestRoutes_GlobalLifecycle drives the deployment-wide routes through their
// full CRUD lifecycle. Critically it asserts the global create/list/update/
// delete return their real status codes (201/200/200/204) and NOT a 422 from
// a stray org_id path param.
func TestRoutes_GlobalLifecycle(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, adminID := env.seedAdmin(t)

	// create → 201
	res := env.do(t, http.MethodPost, "/api/auth/audit/destinations", tok, map[string]any{
		"name":   "global-1",
		"kind":   "webhook",
		"config": map[string]string{"url": "http://example.invalid/h"},
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: want 201, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	res.Body.Close()
	if created.ID == "" {
		t.Fatal("create returned empty id")
	}

	// Actor attribution: the create wrote an audit-log row whose UserID is the
	// acting admin, resolved from the operation ctx (NOT the stashed request).
	entries, err := env.repo.ListAuditLog(context.Background(), domain.ListAuditFilters{Limit: 100})
	if err != nil {
		t.Fatalf("list audit log: %v", err)
	}
	var createdRow *domain.AuditLog
	for _, e := range entries {
		if e.EventType == "audit_export.destination.created" {
			createdRow = e
			break
		}
	}
	if createdRow == nil {
		t.Fatal("no audit_export.destination.created row written")
	}
	if createdRow.UserID == nil || *createdRow.UserID != adminID {
		t.Fatalf("actor attribution lost: want UserID=%q, got %v", adminID, createdRow.UserID)
	}

	// list (bare JSON array) → 200
	res = env.do(t, http.MethodGet, "/api/auth/audit/destinations", tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	var list []map[string]any
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatalf("list must be a JSON array: %v", err)
	}
	res.Body.Close()
	if len(list) != 1 {
		t.Fatalf("list: want 1, got %d", len(list))
	}

	// get → 200
	res = env.do(t, http.MethodGet, "/api/auth/audit/destinations/"+created.ID, tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	// outbox → 200 (bare array)
	res = env.do(t, http.MethodGet, "/api/auth/audit/destinations/"+created.ID+"/outbox", tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("outbox: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	// PATCH → 200
	res = env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+created.ID, tok, map[string]any{"status": "disabled"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	// PUT (alias) → 200
	res = env.do(t, http.MethodPut, "/api/auth/audit/destinations/"+created.ID, tok, map[string]any{"name": "global-1b"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("put: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	// replay → 200
	res = env.do(t, http.MethodPost, "/api/auth/audit/replay", tok, map[string]any{
		"audit_log_ids":   []string{uuid.NewString()},
		"destination_ids": []string{created.ID},
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("replay: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	// DELETE → 204
	res = env.do(t, http.MethodDelete, "/api/auth/audit/destinations/"+created.ID, tok, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()
}

// TestRoutes_OrgScopedLifecycle drives the org-scoped subtree: create, list,
// PATCH/PUT, DELETE under /organizations/{org_id}/...
func TestRoutes_OrgScopedLifecycle(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, _ := env.seedAdmin(t)
	org := uuid.NewString()
	base := "/api/auth/organizations/" + org + "/audit/destinations"

	res := env.do(t, http.MethodPost, base, tok, map[string]any{
		"name":   "org-1",
		"kind":   "webhook",
		"config": map[string]string{"url": "http://example.invalid/o"},
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("org create: want 201, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	var created struct {
		ID             string  `json:"id"`
		OrganizationID *string `json:"organization_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	// The org_id path param must scope the destination.
	if created.OrganizationID == nil || *created.OrganizationID != org {
		t.Fatalf("org create: expected org scope %q, got %v", org, created.OrganizationID)
	}

	res = env.do(t, http.MethodGet, base, tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("org list: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	res = env.do(t, http.MethodPatch, base+"/"+created.ID, tok, map[string]any{"status": "disabled"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("org patch: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	res = env.do(t, http.MethodPut, base+"/"+created.ID, tok, map[string]any{"name": "org-1b"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("org put: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	res = env.do(t, http.MethodDelete, base+"/"+created.ID, tok, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("org delete: want 204, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()
}

// TestRoutes_AuthGate confirms the admin gate is intact: no auth → 401,
// non-admin → 403, on both a global and an org-scoped route.
func TestRoutes_AuthGate(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()

	// seed a non-admin user
	now := time.Now().UTC()
	u, err := env.repo.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: "user@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	userTok, _, err := auth.IssueSession(context.Background(), env.repo, u.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	paths := []struct{ method, path string }{
		{http.MethodGet, "/api/auth/audit/destinations"},
		{http.MethodGet, "/api/auth/organizations/" + uuid.NewString() + "/audit/destinations"},
	}
	for _, pc := range paths {
		// no auth → 401
		res := env.do(t, pc.method, pc.path, "", nil)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s no-auth: want 401, got %d (%s)", pc.method, pc.path, res.StatusCode, bodyOf(res))
		}
		res.Body.Close()
		// non-admin → 403
		res = env.do(t, pc.method, pc.path, userTok, nil)
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s non-admin: want 403, got %d (%s)", pc.method, pc.path, res.StatusCode, bodyOf(res))
		}
		res.Body.Close()
	}
}
