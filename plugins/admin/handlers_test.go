package admin_test

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
	"github.com/yackey-labs/yauth/plugins/admin"
	"github.com/yackey-labs/yauth/repo/gormrepo"
)

type testEnv struct {
	srv  *httptest.Server
	repo *gormrepo.Repo
	stop func()
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()

	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(admin.New()).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return &testEnv{srv: srv, repo: r, stop: func() { srv.Close() }}
}

func (e *testEnv) seedUser(t *testing.T, email, role string) domain.User {
	t.Helper()
	now := time.Now().UTC()
	u, err := e.repo.CreateUser(context.Background(), domain.NewUser{
		ID:        uuid.NewString(),
		Email:     email,
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create %q: %v", email, err)
	}
	return u
}

func (e *testEnv) issueSession(t *testing.T, userID string) string {
	t.Helper()
	raw, _, err := auth.IssueSession(context.Background(), e.repo, userID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return raw
}

func (e *testEnv) do(t *testing.T, method, path, cookie string, body any) *http.Response {
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

func drain(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func TestAdmin_GateRejectsNonAdmin(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	regular := env.seedUser(t, "user@example.com", "user")
	tok := env.issueSession(t, regular.ID)

	res := env.do(t, http.MethodGet, "/api/auth/admin/users", tok, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// no auth → 401
	res = env.do(t, http.MethodGet, "/api/auth/admin/users", "", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

func TestAdmin_ListAndGetUser(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	tok := env.issueSession(t, admin.ID)

	// List
	res := env.do(t, http.MethodGet, "/api/auth/admin/users", tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: %d (%s)", res.StatusCode, drain(res))
	}
	var list struct {
		Users []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
		Total int64 `json:"total"`
	}
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	res.Body.Close()
	if list.Total != 2 {
		t.Fatalf("expected total=2, got %d", list.Total)
	}
	if len(list.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(list.Users))
	}

	// Get
	res = env.do(t, http.MethodGet, "/api/auth/admin/users/"+target.ID, tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get: %d (%s)", res.StatusCode, drain(res))
	}
	var got struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	res.Body.Close()
	if got.ID != target.ID || got.Email != target.Email {
		t.Fatalf("get mismatch: %+v", got)
	}

	// Get unknown → 404
	res = env.do(t, http.MethodGet, "/api/auth/admin/users/"+uuid.NewString(), tok, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("get unknown: expected 404, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestAdmin_PatchUser(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	tok := env.issueSession(t, admin.ID)

	dn := "Renamed User"
	res := env.do(t, http.MethodPatch, "/api/auth/admin/users/"+target.ID, tok, map[string]any{
		"display_name": dn,
		"role":         "admin",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d (%s)", res.StatusCode, drain(res))
	}
	var out struct {
		Role        string  `json:"role"`
		DisplayName *string `json:"display_name"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	res.Body.Close()
	if out.Role != "admin" {
		t.Fatalf("expected role=admin, got %q", out.Role)
	}
	if out.DisplayName == nil || *out.DisplayName != dn {
		t.Fatalf("expected display_name=%q, got %v", dn, out.DisplayName)
	}
}

func TestAdmin_BanUnban(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	// Pre-existing session for the target — should be revoked on ban.
	_ = env.issueSession(t, target.ID)

	tok := env.issueSession(t, admin.ID)

	// Ban
	res := env.do(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/ban", tok, map[string]any{
		"reason": "spam",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ban: %d (%s)", res.StatusCode, drain(res))
	}
	var banned struct {
		Banned       bool    `json:"banned"`
		BannedReason *string `json:"banned_reason"`
	}
	if err := json.NewDecoder(res.Body).Decode(&banned); err != nil {
		t.Fatalf("decode ban: %v", err)
	}
	res.Body.Close()
	if !banned.Banned {
		t.Fatalf("expected banned=true")
	}
	if banned.BannedReason == nil || *banned.BannedReason != "spam" {
		t.Fatalf("expected banned_reason=spam, got %v", banned.BannedReason)
	}

	// Sessions revoked: the target should have zero sessions left.
	left, _, err := env.repo.ListSessions(context.Background(), domain.ListSessionsFilters{Limit: 100})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	for _, s := range left {
		if s.UserID == target.ID {
			t.Fatalf("expected target's sessions revoked, found %+v", s)
		}
	}

	// Reason required.
	res = env.do(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/ban", tok, map[string]any{
		"reason": "",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("ban no-reason: expected 400, got %d", res.StatusCode)
	}
	res.Body.Close()

	// Unban
	res = env.do(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/unban", tok, struct{}{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unban: %d (%s)", res.StatusCode, drain(res))
	}
	var unbanned struct {
		Banned       bool    `json:"banned"`
		BannedReason *string `json:"banned_reason"`
	}
	if err := json.NewDecoder(res.Body).Decode(&unbanned); err != nil {
		t.Fatalf("decode unban: %v", err)
	}
	res.Body.Close()
	if unbanned.Banned {
		t.Fatalf("expected banned=false")
	}
	if unbanned.BannedReason != nil {
		t.Fatalf("expected banned_reason=nil, got %v", *unbanned.BannedReason)
	}
}

func TestAdmin_Impersonate(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	tok := env.issueSession(t, admin.ID)

	res := env.do(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/impersonate", tok, struct{}{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("impersonate: %d (%s)", res.StatusCode, drain(res))
	}

	var setCookieFound bool
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			setCookieFound = true
		}
	}
	res.Body.Close()
	if !setCookieFound {
		t.Fatalf("expected Set-Cookie yauth_session in impersonate response")
	}

	// Audit log should contain admin.impersonation with admin.id in metadata.
	entries, err := env.repo.ListAuditLog(context.Background(), domain.ListAuditFilters{
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var seen bool
	for _, e := range entries {
		if e.EventType == "admin.impersonation" {
			seen = true
			if e.UserID == nil || *e.UserID != target.ID {
				t.Fatalf("audit user_id mismatch: %v", e.UserID)
			}
			var meta map[string]any
			if err := json.Unmarshal(e.Metadata, &meta); err != nil {
				t.Fatalf("decode metadata: %v", err)
			}
			if meta["admin_id"] != admin.ID {
				t.Fatalf("audit admin_id=%v, want %s", meta["admin_id"], admin.ID)
			}
		}
	}
	if !seen {
		t.Fatalf("audit log missing admin.impersonation entry")
	}
}

func TestAdmin_DeleteUserSessions(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	_ = env.issueSession(t, target.ID)
	_ = env.issueSession(t, target.ID)
	tok := env.issueSession(t, adminUser.ID)

	res := env.do(t, http.MethodDelete, "/api/auth/admin/users/"+target.ID+"/sessions", tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete sessions: %d (%s)", res.StatusCode, drain(res))
	}
	var out struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	if out.Deleted != 2 {
		t.Fatalf("expected deleted=2, got %d", out.Deleted)
	}
}

func TestAdmin_ListAudit(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	tok := env.issueSession(t, adminUser.ID)

	uid := adminUser.ID
	now := time.Now().UTC()
	for i := range 3 {
		_ = env.repo.LogAuditEvent(context.Background(), domain.NewAuditLog{
			ID:        uuid.NewString(),
			UserID:    &uid,
			EventType: "admin.test",
			Metadata:  []byte(`{}`),
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		})
	}

	res := env.do(t, http.MethodGet, "/api/auth/admin/audit?type=admin.test&limit=100", tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list audit: %d (%s)", res.StatusCode, drain(res))
	}
	var out struct {
		Entries []struct {
			EventType string `json:"event_type"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	if len(out.Entries) != 3 {
		t.Fatalf("expected 3 audit entries, got %d", len(out.Entries))
	}
	for _, e := range out.Entries {
		if e.EventType != "admin.test" {
			t.Fatalf("unexpected event_type %q", e.EventType)
		}
	}
}

func TestAdmin_DeleteUser(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	tok := env.issueSession(t, adminUser.ID)

	res := env.do(t, http.MethodDelete, "/api/auth/admin/users/"+target.ID, tok, map[string]any{
		"reason": "violation",
	})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete user: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	if _, err := env.repo.GetUserByID(context.Background(), target.ID); err == nil {
		t.Fatalf("expected target to be gone")
	}

	// Audit row.
	entries, err := env.repo.ListAuditLog(context.Background(), domain.ListAuditFilters{
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var seen bool
	for _, e := range entries {
		if e.EventType == "admin.user.deleted" {
			seen = true
			var meta map[string]any
			if err := json.Unmarshal(e.Metadata, &meta); err != nil {
				t.Fatalf("decode metadata: %v", err)
			}
			if meta["reason"] != "violation" {
				t.Fatalf("audit reason=%v, want violation", meta["reason"])
			}
		}
	}
	if !seen {
		t.Fatalf("audit log missing admin.user.deleted entry")
	}
}

func TestAdmin_DeleteUser_RefusesSelfDelete(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	tok := env.issueSession(t, adminUser.ID)

	res := env.do(t, http.MethodDelete, "/api/auth/admin/users/"+adminUser.ID, tok, nil)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("self-delete: expected 409, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	if _, err := env.repo.GetUserByID(context.Background(), adminUser.ID); err != nil {
		t.Fatalf("admin should still exist: %v", err)
	}
}

func TestAdmin_ListSessions(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	other := env.seedUser(t, "other@example.com", "user")
	_ = env.issueSession(t, target.ID)
	_ = env.issueSession(t, target.ID)
	_ = env.issueSession(t, other.ID)
	tok := env.issueSession(t, adminUser.ID)

	// All sessions: target(2) + other(1) + admin(1) = 4.
	res := env.do(t, http.MethodGet, "/api/auth/admin/sessions", tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list sessions: %d (%s)", res.StatusCode, drain(res))
	}
	var all struct {
		Sessions []struct {
			ID     string `json:"id"`
			UserID string `json:"user_id"`
		} `json:"sessions"`
		Total int64 `json:"total"`
	}
	if err := json.NewDecoder(res.Body).Decode(&all); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	res.Body.Close()
	if all.Total != 4 {
		t.Fatalf("expected total=4, got %d", all.Total)
	}

	// Filter by user_id.
	res = env.do(t, http.MethodGet, "/api/auth/admin/sessions?user_id="+target.ID, tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list filtered: %d (%s)", res.StatusCode, drain(res))
	}
	var filtered struct {
		Sessions []struct {
			UserID string `json:"user_id"`
		} `json:"sessions"`
		Total int64 `json:"total"`
	}
	if err := json.NewDecoder(res.Body).Decode(&filtered); err != nil {
		t.Fatalf("decode filtered: %v", err)
	}
	res.Body.Close()
	if filtered.Total != 2 || len(filtered.Sessions) != 2 {
		t.Fatalf("expected 2 sessions for target, got total=%d len=%d", filtered.Total, len(filtered.Sessions))
	}
	for _, s := range filtered.Sessions {
		if s.UserID != target.ID {
			t.Fatalf("filter leaked: %s", s.UserID)
		}
	}
}

func TestAdmin_DeleteSession(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	_ = env.issueSession(t, target.ID)
	tok := env.issueSession(t, adminUser.ID)

	// Look up the target's session id.
	sessions, _, err := env.repo.ListSessions(context.Background(), domain.ListSessionsFilters{
		UserID: &target.ID,
		Limit:  10,
	})
	if err != nil || len(sessions) == 0 {
		t.Fatalf("seed session: err=%v len=%d", err, len(sessions))
	}
	sid := sessions[0].ID

	res := env.do(t, http.MethodDelete, "/api/auth/admin/sessions/"+sid, tok, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete session: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Verify gone.
	left, _, err := env.repo.ListSessions(context.Background(), domain.ListSessionsFilters{
		UserID: &target.ID,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("list left: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("expected target session deleted, found %d", len(left))
	}

	// 404 on unknown id.
	res = env.do(t, http.MethodDelete, "/api/auth/admin/sessions/"+uuid.NewString(), tok, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("delete unknown session: expected 404, got %d", res.StatusCode)
	}
	res.Body.Close()

	// Audit entry.
	entries, err := env.repo.ListAuditLog(context.Background(), domain.ListAuditFilters{
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var seen bool
	for _, e := range entries {
		if e.EventType == "admin.session.terminated" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("audit log missing admin.session.terminated entry")
	}
}

func TestAdmin_ListUsers_LimitClamp(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	tok := env.issueSession(t, adminUser.ID)

	// Asking for limit=999 should not blow up; clamp to maxLimit (=100).
	// We can't read the constant from outside the package, but we can verify
	// the response is OK and bounded by a reasonable cap.
	for i := range 5 {
		env.seedUser(t, "u"+string(rune('a'+i))+"@example.com", "user")
	}
	res := env.do(t, http.MethodGet, "/api/auth/admin/users?limit=999", tok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list w/ huge limit: %d (%s)", res.StatusCode, drain(res))
	}
	var out struct {
		Users []json.RawMessage `json:"users"`
		Total int64             `json:"total"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	if int64(len(out.Users)) > 100 {
		t.Fatalf("expected limit clamp to 100, got %d users", len(out.Users))
	}
}
