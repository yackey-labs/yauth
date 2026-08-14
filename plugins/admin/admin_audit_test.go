package admin_test

// admin_audit_test.go — the holes in the admin audit trail, and the
// impersonation session that opts itself out of User-Agent binding.
//
// (1) MISSING ROWS. Eight of the twelve admin mutations write an audit row
// through host.Repo().LogAuditEvent: ban, unban, suspend, unsuspend,
// impersonate, delete-user, delete-session. Four do not:
//
//	POST   /admin/users                     (registerCreateUser)
//	PATCH  /admin/users/{id}   + PUT alias  (registerPatchUser)
//	POST   /admin/users/{id}/schedule-start (registerScheduleStart)
//	DELETE /admin/users/{id}/sessions       (registerDeleteUserSessions)
//
// The PATCH gap is the one that matters: handlers.go passes req.Role
// straight into domain.UpdateUser, so `PATCH {"role":"admin"}` is a
// privilege grant — and because its eight neighbours DO write rows, an
// investigator reading GET /admin/audit sees a log that looks complete and
// concludes no role change happened. Provisioning an account and revoking
// every session are the same shape of silence.
//
// (2) IMPERSONATION IS NOT UA-BOUND. registerImpersonate calls
// auth.IssueSession(..., middleware.RequestIP(r), nil, ...) — a literal nil
// User-Agent, where every other session-issuing site in the tree passes the
// request's UA. middleware.enforceBinding is guarded on
// `m.cfg.BindUA && sess.UserAgent != nil`, so a NULL ua column silently
// disables UA binding for that session's whole life. On a deployment running
// bind_ua with ua_mismatch_action: invalidate, the session type that most
// deserves binding — a live credential for someone else's account — is the
// only one exempt.
//
// Every refusal below is paired with a positive control so a "fix" that
// simply breaks the admin API cannot pass.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/admin"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- harness extensions ----------------------------------------------------

// newEnvWithBinding is newEnv with a session-binding policy applied. The
// stock newEnv builds with NewDefaultConfig, which binds nothing, so the
// binding half of the impersonation defect is unreachable through it.
func newEnvWithBinding(t *testing.T, binding yauth.SessionBindingConfig) *testEnv {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.SessionBinding = binding
	ya, err := yauth.New(r, cfg).WithPlugin(admin.New()).Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return &testEnv{srv: srv, repo: r, stop: func() { srv.Close() }}
}

// doUA is do() with an explicit User-Agent, which is the input the
// impersonation handler drops on the floor.
func (e *testEnv) doUA(t *testing.T, method, path, cookie, ua string, body any) *http.Response {
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
	req.Header.Set("User-Agent", ua)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

// auditRows returns every audit row currently in the repo.
func (e *testEnv) auditRows(t *testing.T) []*domain.AuditLog {
	t.Helper()
	rows, err := e.repo.ListAuditLog(context.Background(), domain.ListAuditFilters{Limit: 1000})
	if err != nil {
		t.Fatalf("list audit log: %v", err)
	}
	return rows
}

// auditTypes summarises the event types of a row set, for failure messages.
func auditTypes(rows []*domain.AuditLog) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.EventType)
	}
	return out
}

// sessionsFor returns the session rows belonging to userID.
func (e *testEnv) sessionsFor(t *testing.T, userID string) []*domain.Session {
	t.Helper()
	all, _, err := e.repo.ListSessions(context.Background(), domain.ListSessionsFilters{Limit: 500})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	var out []*domain.Session
	for _, s := range all {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out
}

// --- (1) the four silent mutations -----------------------------------------

// TestAdminAudit_RoleChangeIsRecorded is the headline of the missing-row
// half: PATCH /admin/users/{id} {"role":"admin"} is a privilege grant and it
// writes nothing at all.
func TestAdminAudit_RoleChangeIsRecorded(t *testing.T) {
	env := newEnvWithBinding(t, yauth.SessionBindingConfig{})
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "victim@example.com", "user")
	tok := env.issueSession(t, adminUser.ID)

	// POSITIVE CONTROL: ban — a neighbouring mutation on the same guard
	// chain — does write a row. This is what makes the log look complete.
	res := env.do(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/ban", tok,
		map[string]any{"reason": "control"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ban (positive control): %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	var sawBan bool
	for _, row := range env.auditRows(t) {
		if row.EventType == "admin.ban" {
			sawBan = true
		}
	}
	if !sawBan {
		t.Fatalf("positive control broken: admin.ban wrote no audit row (%v) — "+
			"the admin audit trail is broken outright, not merely incomplete",
			auditTypes(env.auditRows(t)))
	}

	before := len(env.auditRows(t))

	// THE DEFECT: grant admin.
	res = env.do(t, http.MethodPatch, "/api/auth/admin/users/"+target.ID, tok,
		map[string]any{"role": "admin"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch role: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// The grant really happened...
	updated, err := env.repo.GetUserByID(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("reload target: %v", err)
	}
	if updated.Role != "admin" {
		t.Fatalf("precondition: target role = %q, want admin", updated.Role)
	}

	// ...and left no trace.
	after := env.auditRows(t)
	if len(after) == before {
		t.Fatalf("PATCH /admin/users/%s {\"role\":\"admin\"} promoted a user to admin and wrote "+
			"NO audit row (log still holds %d rows: %v). ban/unban/suspend/unsuspend/impersonate/"+
			"delete all write one, so the trail reads as complete while a privilege grant is missing.",
			target.ID, before, auditTypes(after))
	}

	// The row must name the change, not merely exist: an auditor has to see
	// user -> admin without diffing two snapshots of the users table.
	var found *domain.AuditLog
	for _, row := range after[:len(after)-before] {
		if row.EventType == "admin.user_updated" {
			found = row
		}
	}
	if found == nil {
		t.Fatalf("no admin.user_updated row among the new rows: %v", auditTypes(after))
	}
	var m map[string]any
	if len(found.Metadata) > 0 {
		if err := json.Unmarshal(found.Metadata, &m); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
	}
	if m["role_from"] != "user" || m["role_to"] != "admin" {
		t.Errorf("admin.user_updated metadata must make the grant legible, got %v", m)
	}
	if m["admin_id"] != adminUser.ID {
		t.Errorf("admin.user_updated must name the acting admin, got %v", m["admin_id"])
	}
}

// TestAdminAudit_SilentMutations covers the other three ops that leave no
// trace. Each subtest drives one mutation and asserts the audit table grew.
func TestAdminAudit_SilentMutations(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   func(targetID string) string
		body   any
		want   int
	}{
		{
			name:   "create_user",
			method: http.MethodPost,
			path:   func(string) string { return "/api/auth/admin/users" },
			body:   map[string]any{"email": "provisioned@example.com", "role": "admin"},
			want:   http.StatusCreated,
		},
		{
			name:   "schedule_start",
			method: http.MethodPost,
			path:   func(id string) string { return "/api/auth/admin/users/" + id + "/schedule-start" },
			body:   map[string]any{"activates_at": time.Now().UTC().Add(48 * time.Hour)},
			want:   http.StatusOK,
		},
		{
			name:   "revoke_all_sessions",
			method: http.MethodDelete,
			path:   func(id string) string { return "/api/auth/admin/users/" + id + "/sessions" },
			body:   nil,
			want:   http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnvWithBinding(t, yauth.SessionBindingConfig{})
			defer env.stop()
			adminUser := env.seedUser(t, "admin@example.com", "admin")
			target := env.seedUser(t, "target@example.com", "user")
			_ = env.issueSession(t, target.ID) // something for revoke-all to kill
			tok := env.issueSession(t, adminUser.ID)

			before := len(env.auditRows(t))
			res := env.doUA(t, tc.method, tc.path(target.ID), tok, "admin-console/1.0", tc.body)
			if res.StatusCode != tc.want {
				t.Fatalf("%s: %d, want %d (%s)", tc.name, res.StatusCode, tc.want, drain(res))
			}
			res.Body.Close()

			after := env.auditRows(t)
			if len(after) == before {
				t.Fatalf("%s %s wrote no audit row (%d rows before and after: %v)",
					tc.method, tc.path(target.ID), before, auditTypes(after))
			}
		})
	}
}

// --- (2) impersonation and User-Agent binding ------------------------------

// TestImpersonate_RecordsUserAgent asserts the persisted session row, not a
// status code: a NULL user_agent column is precisely what makes
// middleware.enforceBinding skip the UA check for the rest of that session's
// life.
func TestImpersonate_RecordsUserAgent(t *testing.T) {
	env := newEnvWithBinding(t, yauth.SessionBindingConfig{})
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	target := env.seedUser(t, "target@example.com", "user")
	tok := env.issueSession(t, adminUser.ID)

	res := env.doUA(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/impersonate",
		tok, "probe/1.0", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("impersonate: %d (%s)", res.StatusCode, drain(res))
	}
	// POSITIVE CONTROL: the feature works — a session cookie really is issued.
	var issued *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			issued = c
		}
	}
	res.Body.Close()
	if issued == nil {
		t.Fatalf("impersonate set no session cookie — the feature must keep working")
	}

	sessions := env.sessionsFor(t, target.ID)
	if len(sessions) != 1 {
		t.Fatalf("want exactly 1 impersonation session for the target, got %d", len(sessions))
	}
	s := sessions[0]
	if s.UserAgent == nil {
		t.Fatalf("the impersonation session row has a NULL user_agent: auth.IssueSession is "+
			"called with a literal nil UA (handlers.go registerImpersonate) while the request "+
			"carried %q. middleware.enforceBinding is guarded on sess.UserAgent != nil, so this "+
			"session is exempt from UA binding for its whole life.", "probe/1.0")
	}
	if *s.UserAgent != "probe/1.0" {
		t.Fatalf("impersonation session user_agent = %q, want %q", *s.UserAgent, "probe/1.0")
	}
}

// TestImpersonate_SessionIsUABound is the consequence, on a deployment that
// actually turns binding on: the impersonation cookie replayed from another
// client must be refused, exactly as a password-login cookie would be.
func TestImpersonate_SessionIsUABound(t *testing.T) {
	env := newEnvWithBinding(t, yauth.SessionBindingConfig{
		BindUA:           true,
		UAMismatchAction: "invalidate",
	})
	defer env.stop()

	adminUser := env.seedUser(t, "admin@example.com", "admin")
	// The impersonation target is itself an admin so the stolen cookie can be
	// replayed against an admin route — the route set this plugin exposes.
	target := env.seedUser(t, "target-admin@example.com", "admin")
	tok := env.issueSession(t, adminUser.ID)

	res := env.doUA(t, http.MethodPost, "/api/auth/admin/users/"+target.ID+"/impersonate",
		tok, "admin-console/1.0", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("impersonate: %d (%s)", res.StatusCode, drain(res))
	}
	var issued *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			issued = c
		}
	}
	res.Body.Close()
	if issued == nil {
		t.Fatalf("impersonate set no session cookie")
	}

	// POSITIVE CONTROL: the same client (same UA) keeps working. A "fix"
	// that binds so hard the cookie is useless must fail here.
	res = env.doUA(t, http.MethodGet, "/api/auth/admin/users", issued.Value, "admin-console/1.0", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("impersonation cookie from the SAME client: %d, want 200 (%s)",
			res.StatusCode, drain(res))
	}
	res.Body.Close()

	// THE DEFECT: replayed from a different client it is still accepted.
	res = env.doUA(t, http.MethodGet, "/api/auth/admin/users", issued.Value, "stolen-by/9.9", nil)
	code := res.StatusCode
	res.Body.Close()
	if code != http.StatusUnauthorized {
		t.Fatalf("impersonation cookie replayed with a different User-Agent under "+
			"bind_ua + ua_mismatch_action=invalidate returned %d, want 401. Every password-login "+
			"cookie on this deployment is refused here; the impersonation session is exempt "+
			"because its user_agent column is NULL.", code)
	}
}
