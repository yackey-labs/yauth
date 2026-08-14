package yauth_test

// security_audit_chokepoint_test.go — the audit-export outbox hole.
//
// yauth has TWO ways an audit row gets written, and only one of them is
// visible to anything downstream.
//
//   - YAuth.recordAuthAudit (audit_events.go) writes the row for every
//     event that reaches Emit and THEN fans the row id out to every
//     registered plugin.AuditRecorder. plugins/auditexport registers exactly
//     one such recorder (plugins/auditexport/plugin.go:182), and that
//     recorder is the only thing that ever enqueues a row into the export
//     outbox. Logins, logouts, password changes — all covered.
//
//   - Thirteen call sites instead invoke host.Repo().LogAuditEvent
//     directly: plugins/admin (ban, unban, suspend, unsuspend, impersonate,
//     delete user, delete session), plugins/oauth2server (client admin,
//     client auth, DCR, DCR sweep), plugins/scim (user deprovision) and
//     middleware's session-binding mismatch. Those rows land in
//     yauth_audit_log and stop there. No recorder is notified, so no outbox
//     row is enqueued, so a SIEM streaming yauth receives every login event
//     and not one admin.ban, admin.impersonation or SCIM deprovision.
//     (plugins/auditexport's own destination routes also call LogAuditEvent
//     directly, but they are NOT part of the hole: routes.go's auditEvent
//     calls p.store.EnqueueForAudit on the very next line, reaching the
//     outbox without going through a recorder.)
//
// This test drives the real HTTP path for the most security-relevant of the
// eleven — POST /admin/users/{id}/ban — with a fake plugin.AuditRecorder
// attached, and asserts that the row the ban writes is handed to the
// recorder the same way a login's row is. The login half is the POSITIVE
// CONTROL: it proves the recorder is wired and firing, so a failure on the
// ban half can only mean the admin write bypassed the choke point.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/plugins/admin"
)

// seedAdmin creates an admin-role user directly in the repo and returns it.
func (e *auditEnv) seedAdmin(t *testing.T, email string) domain.User {
	t.Helper()
	now := time.Now().UTC()
	u, err := e.repo.CreateUser(context.Background(), domain.NewUser{
		ID:            uuid.NewString(),
		Email:         email,
		Role:          "admin",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatalf("seed admin %q: %v", email, err)
	}
	return u
}

// sessionCookie issues a session for userID and returns it as a cookie the
// postWithCookie helper can replay.
func (e *auditEnv) sessionCookie(t *testing.T, userID string) *http.Cookie {
	t.Helper()
	raw, _, err := auth.IssueSession(context.Background(), e.repo, userID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return &http.Cookie{Name: "yauth_session", Value: raw}
}

// TestAudit_AdminBan_ReachesTheExportRecorder is the outbox hole.
//
// A recorder registered through plugin.AuditRecorderRegistrar is the ONLY
// hand-off point between the audit table and the audit-export outbox. If an
// admin action's row never reaches it, that action is absent from every
// exported stream — the row exists in the database and the SIEM never
// learns of it.
func TestAudit_AdminBan_ReachesTheExportRecorder(t *testing.T) {
	rec := &recorderPlugin{}
	env := newAuditEnv(t, admin.New(), rec)

	// --- POSITIVE CONTROL: a login row DOES reach the recorder ----------
	env.register(t, "hana@example.test")
	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "hana@example.test", "password": auditTestPassword,
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", res.StatusCode)
	}
	loginRows := env.rows(t, string(events.EventLoginSucceeded))
	if len(loginRows) != 1 {
		t.Fatalf("want 1 login.succeeded row, got %d", len(loginRows))
	}
	if !containsID(rec.ids, loginRows[0].ID) {
		t.Fatalf("positive control broken: the login.succeeded row %s never reached the "+
			"AuditRecorder (saw %v) — the recorder is not wired, so nothing below proves anything",
			loginRows[0].ID, rec.ids)
	}
	beforeBan := len(rec.ids)

	// --- THE DEFECT: an admin ban row does not ---------------------------
	adminUser := env.seedAdmin(t, "root@example.test")
	target := env.rows(t, string(events.EventUserRegistered))
	if len(target) != 1 || target[0].UserID == nil {
		t.Fatalf("expected the registered user's audit row to name them: %+v", target)
	}
	targetID := *target[0].UserID

	res = env.postWithCookie(t, "/api/auth/admin/users/"+targetID+"/ban",
		map[string]any{"reason": "policy violation"}, env.sessionCookie(t, adminUser.ID))
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ban: %d, want 200 — the admin path must work for this test to mean anything",
			res.StatusCode)
	}

	banRows := env.rows(t, "admin.ban")
	if len(banRows) != 1 {
		t.Fatalf("want exactly 1 admin.ban row in the audit table, got %d", len(banRows))
	}
	if !containsID(rec.ids, banRows[0].ID) {
		t.Fatalf("admin.ban row %s was written to the audit table but never handed to the "+
			"plugin.AuditRecorder (recorder saw %d ids before the ban and %d after: %v).\n"+
			"That recorder is audit-export's only enqueue point, so every ban, unban, suspend, "+
			"impersonation, SCIM deprovision and OAuth2 client mutation is invisible to a SIEM. "+
			"(The recorder did gain an id here — that is the user.banned row Emit wrote through "+
			"recordAuthAudit. The admin-authored admin.ban row, the one carrying the acting "+
			"admin_id and the reason, is the one that never arrives.)",
			banRows[0].ID, beforeBan, len(rec.ids), rec.ids)
	}
}

// TestAudit_UnbanEmitsTheInverseEvent — events.EventUserUnbanned and
// events.EventUserUnsuspended are declared in events/events.go and emitted
// by nothing in the tree. Ban and suspend emit; their inverses do not, so a
// webhook subscriber or a back-channel-logout consumer watching account
// lifecycle sees accounts go down and never come back up.
func TestAudit_UnbanEmitsTheInverseEvent(t *testing.T) {
	obs := &eventObserverPlugin{}
	env := newAuditEnv(t, admin.New(), obs)

	adminUser := env.seedAdmin(t, "root@example.test")
	target := env.seedAdmin(t, "victim@example.test") // role is irrelevant here
	cookie := env.sessionCookie(t, adminUser.ID)

	res := env.postWithCookie(t, "/api/auth/admin/users/"+target.ID+"/ban",
		map[string]any{"reason": "policy violation"}, cookie)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ban: %d", res.StatusCode)
	}
	// POSITIVE CONTROL: the ban half of the pair does reach the pipeline.
	if !obs.saw(events.EventUserBanned) {
		t.Fatalf("positive control broken: no %s event observed (%v)",
			events.EventUserBanned, obs.types())
	}

	res = env.postWithCookie(t, "/api/auth/admin/users/"+target.ID+"/unban", nil, cookie)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unban: %d", res.StatusCode)
	}
	if !obs.saw(events.EventUserUnbanned) {
		t.Fatalf("unban emitted no %s event (pipeline saw %v). The event type exists in "+
			"events/events.go and nothing in the tree emits it, so a subscriber that reacted to "+
			"user.banned has no signal that the account came back.",
			events.EventUserUnbanned, obs.types())
	}
}

// eventObserverPlugin records every event type that reaches the pipeline.
type eventObserverPlugin struct {
	seen []events.EventType
}

func (o *eventObserverPlugin) Name() string { return "test-event-observer" }

func (o *eventObserverPlugin) Routes(host plugin.PluginHost, _ plugin.Router, _ huma.API, _ string) {
	host.RegisterEventHandler(o)
}

func (o *eventObserverPlugin) Handle(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
	o.seen = append(o.seen, ev.Type)
	return events.Continue(), nil
}

func (o *eventObserverPlugin) saw(t events.EventType) bool {
	for _, e := range o.seen {
		if e == t {
			return true
		}
	}
	return false
}

func (o *eventObserverPlugin) types() []events.EventType { return o.seen }

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
