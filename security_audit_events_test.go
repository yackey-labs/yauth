package yauth_test

// security_audit_events_test.go — the authentication audit trail.
//
// Before the audit sink in audit_events.go, the complete set of
// LogAuditEvent call sites outside admin/oauth2server/scim was ONE
// (middleware's session-binding mismatch). Every login, every failed login,
// every logout and every password change happened without leaving a durable
// row, so the admin audit-log API and the whole audit-export pipeline could
// never carry them and a brute-force attack left no trace at all.
//
// These tests drive real HTTP through the email-password plugin and then
// read the audit log back out of the repository.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- harness ---------------------------------------------------------------

// auditEnv is a running yauth instance plus the repo its audit rows land in.
type auditEnv struct {
	ya   *yauth.YAuth
	repo *memrepo.Repo
	mux  http.Handler
}

// newAuditEnv builds a yauth with the email-password plugin plus any extra
// plugins the test supplies (a gate, a recorder probe).
func newAuditEnv(t *testing.T, extra ...plugin.Plugin) *auditEnv {
	t.Helper()
	r := memrepo.New()
	b := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		}))
	for _, p := range extra {
		b = b.WithPlugin(p)
	}
	ya, err := b.Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	return &auditEnv{ya: ya, repo: r, mux: mux}
}

// rows returns every audit row of the given event type, newest first.
func (e *auditEnv) rows(t *testing.T, eventType string) []*domain.AuditLog {
	t.Helper()
	filters := domain.ListAuditFilters{Limit: 1000}
	if eventType != "" {
		filters.EventType = &eventType
	}
	got, err := e.repo.ListAuditLog(context.Background(), filters)
	if err != nil {
		t.Fatalf("list audit log: %v", err)
	}
	return got
}

// meta decodes a row's metadata blob.
func meta(t *testing.T, row *domain.AuditLog) map[string]any {
	t.Helper()
	if len(row.Metadata) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(row.Metadata, &m); err != nil {
		t.Fatalf("decode metadata %q: %v", string(row.Metadata), err)
	}
	return m
}

// post drives a JSON request straight at the mux — no server, no cookie jar
// needed for the paths these tests exercise.
func (e *auditEnv) post(t *testing.T, path string, body map[string]any) *http.Response {
	t.Helper()
	return e.postWithCookie(t, path, body, nil)
}

func (e *auditEnv) postWithCookie(t *testing.T, path string, body map[string]any, cookie *http.Cookie) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://example.test"+path, strings.NewReader(string(buf)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:51234"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec.Result()
}

const auditTestPassword = "correct-horse-battery-staple-42"

func (e *auditEnv) register(t *testing.T, email string) {
	t.Helper()
	res := e.post(t, "/api/auth/register", map[string]any{"email": email, "password": auditTestPassword})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", res.StatusCode)
	}
}

// --- tests -----------------------------------------------------------------

func TestAudit_LoginSucceeded_IsRecorded(t *testing.T) {
	env := newAuditEnv(t)
	env.register(t, "cara@example.test")

	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "cara@example.test", "password": auditTestPassword,
	})
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", res.StatusCode)
	}

	rows := env.rows(t, string(events.EventLoginSucceeded))
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 login.succeeded row, got %d", len(rows))
	}
	row := rows[0]
	if row.UserID == nil || *row.UserID == "" {
		t.Fatalf("login.succeeded row has no actor user id")
	}
	if row.IPAddress == nil || *row.IPAddress != "203.0.113.7" {
		t.Fatalf("login.succeeded ip = %v, want 203.0.113.7", row.IPAddress)
	}
	m := meta(t, row)
	if m["email"] != "cara@example.test" {
		t.Fatalf("metadata email = %v", m["email"])
	}
	if m["method"] != "email-password" {
		t.Fatalf("metadata method = %v", m["method"])
	}
	if _, ok := m["decision"]; ok {
		t.Fatalf("a Continue decision should write no decision key, got %v", m["decision"])
	}
}

// A failed login must be recorded AS A FAILURE. Dropping it is what made
// brute force invisible: lockout counts in process only, so a restart erases
// the evidence entirely.
func TestAudit_LoginFailed_IsRecordedAsFailure(t *testing.T) {
	env := newAuditEnv(t)
	env.register(t, "dev@example.test")

	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "dev@example.test", "password": "not-the-password",
	})
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad-password login: %d, want 401", res.StatusCode)
	}

	if got := env.rows(t, string(events.EventLoginSucceeded)); len(got) != 0 {
		t.Fatalf("a rejected login must not be recorded as a success (%d rows)", len(got))
	}
	rows := env.rows(t, string(events.EventLoginFailed))
	if len(rows) != 1 {
		t.Fatalf("want 1 login.failed row, got %d", len(rows))
	}
	m := meta(t, rows[0])
	if m["reason"] != "bad-password" {
		t.Fatalf("login.failed reason = %v, want bad-password", m["reason"])
	}
	if rows[0].UserID == nil {
		t.Fatalf("login.failed against a known account should carry the user id")
	}
}

// An unknown address still produces a failure row — attributed by email,
// with no user id, because there is no user.
func TestAudit_LoginFailed_UnknownAccount_IsRecorded(t *testing.T) {
	env := newAuditEnv(t)

	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "ghost@example.test", "password": auditTestPassword,
	})
	res.Body.Close()

	rows := env.rows(t, string(events.EventLoginFailed))
	if len(rows) != 1 {
		t.Fatalf("want 1 login.failed row for the unknown account, got %d", len(rows))
	}
	if rows[0].UserID != nil {
		t.Fatalf("unknown account should have a nil user id, got %v", *rows[0].UserID)
	}
	m := meta(t, rows[0])
	if m["email"] != "ghost@example.test" {
		t.Fatalf("metadata email = %v", m["email"])
	}
	if m["reason"] != "user-not-found" {
		t.Fatalf("metadata reason = %v", m["reason"])
	}
}

func TestAudit_RegistrationAndLogout_AreRecorded(t *testing.T) {
	env := newAuditEnv(t)
	env.register(t, "eli@example.test")

	if got := env.rows(t, string(events.EventUserRegistered)); len(got) != 1 {
		t.Fatalf("want 1 user.registered row, got %d", len(got))
	}

	login := env.post(t, "/api/auth/login", map[string]any{
		"email": "eli@example.test", "password": auditTestPassword,
	})
	login.Body.Close()
	var session *http.Cookie
	for _, c := range login.Cookies() {
		if c.Value != "" {
			session = c
		}
	}
	if session == nil {
		t.Fatalf("login set no session cookie")
	}

	res := env.postWithCookie(t, "/api/auth/logout", map[string]any{}, session)
	res.Body.Close()
	rows := env.rows(t, string(events.EventLogout))
	if len(rows) != 1 {
		t.Fatalf("want 1 logout row, got %d", len(rows))
	}
	if rows[0].UserID == nil {
		t.Fatalf("logout row has no actor")
	}
	if m := meta(t, rows[0]); m["session_id"] == nil {
		t.Fatalf("logout row should name the session that ended: %v", m)
	}
}

// login.attempt fires once per login and is always followed by
// succeeded/failed, so an unblocked attempt is dropped as pure volume. A
// BLOCKED attempt — lockout, IP block — is the one case with nothing else to
// record it, so it must land.
func TestAudit_LoginAttempt_RecordedOnlyWhenBlocked(t *testing.T) {
	env := newAuditEnv(t)
	env.register(t, "fin@example.test")
	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "fin@example.test", "password": auditTestPassword,
	})
	res.Body.Close()
	if got := env.rows(t, string(events.EventLoginAttempt)); len(got) != 0 {
		t.Fatalf("an unblocked login.attempt should write no row, got %d", len(got))
	}

	blocked := newAuditEnv(t, &gatePlugin{
		on:     events.EventLoginAttempt,
		status: http.StatusTooManyRequests,
		msg:    "too many attempts",
	})
	blocked.register(t, "gus@example.test")
	res = blocked.post(t, "/api/auth/login", map[string]any{
		"email": "gus@example.test", "password": auditTestPassword,
	})
	res.Body.Close()

	rows := blocked.rows(t, string(events.EventLoginAttempt))
	if len(rows) != 1 {
		t.Fatalf("a blocked login.attempt must be recorded, got %d rows", len(rows))
	}
	m := meta(t, rows[0])
	if m["decision"] != "block" {
		t.Fatalf("blocked attempt decision = %v, want block", m["decision"])
	}
	if m["block_status"] != float64(http.StatusTooManyRequests) {
		t.Fatalf("blocked attempt block_status = %v", m["block_status"])
	}
}

// A gate that refuses a password-verified login must not leave a row that
// reads like a successful login with no qualification.
func TestAudit_BlockedLoginSucceeded_RecordsTheBlock(t *testing.T) {
	env := newAuditEnv(t, &gatePlugin{
		on:     events.EventLoginSucceeded,
		status: http.StatusForbidden,
		msg:    "account locked",
	})
	env.register(t, "hana@example.test")
	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "hana@example.test", "password": auditTestPassword,
	})
	res.Body.Close()

	rows := env.rows(t, string(events.EventLoginSucceeded))
	if len(rows) != 1 {
		t.Fatalf("want 1 login.succeeded row, got %d", len(rows))
	}
	if m := meta(t, rows[0]); m["decision"] != "block" {
		t.Fatalf("a refused login must record the refusal, decision = %v", m["decision"])
	}
}

// Nothing that could authenticate anyone may reach the audit table. The
// audit log is read by admins, shipped to webhooks, syslog and S3, and kept
// for years; a credential in it is a credential leaked to all of those.
func TestAudit_NeverRecordsSecrets(t *testing.T) {
	env := newAuditEnv(t)
	env.register(t, "iris@example.test")
	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "iris@example.test", "password": auditTestPassword,
	})
	res.Body.Close()
	res = env.post(t, "/api/auth/login", map[string]any{
		"email": "iris@example.test", "password": "wrong-" + auditTestPassword,
	})
	res.Body.Close()

	// Plus a hostile event straight down the pipeline: a caller (or a
	// plugin) stuffing credentials into the free-form metadata map.
	uid := "user-1"
	email := "iris@example.test"
	_, _ = env.ya.Emit(context.Background(), events.AuthEvent{
		Type:   events.EventLoginSucceeded,
		UserID: &uid,
		Email:  &email,
		Metadata: map[string]any{
			"password":        auditTestPassword,
			"totp_code":       "123456",
			"refresh_token":   "rt_" + auditTestPassword,
			"api_key":         "sk_live_" + auditTestPassword,
			"nested":          map[string]any{"session_secret": auditTestPassword},
			"organization_id": "org-1",
		},
	})

	rows := env.rows(t, "")
	if len(rows) == 0 {
		t.Fatalf("no audit rows written at all")
	}
	for _, row := range rows {
		blob := string(row.Metadata)
		if strings.Contains(blob, auditTestPassword) {
			t.Fatalf("audit row %s (%s) leaks a credential: %s", row.ID, row.EventType, blob)
		}
		if strings.Contains(blob, "123456") {
			t.Fatalf("audit row %s leaks a TOTP code: %s", row.ID, blob)
		}
	}

	// And the redaction is positive, not just an accident of the value
	// never being copied: the keys are present and marked.
	last := env.rows(t, string(events.EventLoginSucceeded))
	var hostile map[string]any
	for _, row := range last {
		m := meta(t, row)
		if _, ok := m["password"]; ok {
			hostile = m
		}
	}
	if hostile == nil {
		t.Fatalf("hostile metadata keys were dropped rather than redacted; want them visible as [redacted]")
	}
	for _, k := range []string{"password", "totp_code", "refresh_token", "api_key"} {
		if hostile[k] != "[redacted]" {
			t.Fatalf("metadata[%q] = %v, want [redacted]", k, hostile[k])
		}
	}
	if hostile["organization_id"] != "org-1" {
		t.Fatalf("a non-sensitive key must survive scrubbing, got %v", hostile["organization_id"])
	}
}

// Email and IP arrive from the request. An embedded newline in either would
// let a login form forge a record in the syslog export; an unparseable IP
// would poison the ip_address column.
func TestAudit_SanitizesAttackerControlledFields(t *testing.T) {
	env := newAuditEnv(t)
	nasty := "victim@example.test\n<13>Aug 12 00:00:00 forged: admin login"
	bogusIP := "not-an-ip\nmore"
	_, _ = env.ya.Emit(context.Background(), events.AuthEvent{
		Type:      events.EventLoginFailed,
		Email:     &nasty,
		IPAddress: &bogusIP,
	})

	rows := env.rows(t, string(events.EventLoginFailed))
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].IPAddress != nil {
		t.Fatalf("an unparseable IP must be dropped, got %q", *rows[0].IPAddress)
	}
	m := meta(t, rows[0])
	got, _ := m["email"].(string)
	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("control characters survived into the audit row: %q", got)
	}
	if !strings.HasPrefix(got, "victim@example.test") {
		t.Fatalf("email = %q", got)
	}
}

// The export pipeline is fed by outbox rows keyed to an audit-log id. If the
// host does not hand that id to a recorder, a login can be in the audit table
// and still never reach a webhook / syslog / S3 destination.
func TestAudit_RecorderReceivesTheRowID(t *testing.T) {
	probe := &recorderPlugin{}
	env := newAuditEnv(t, probe)
	env.register(t, "jo@example.test")
	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "jo@example.test", "password": auditTestPassword,
	})
	res.Body.Close()

	if len(probe.ids) == 0 {
		t.Fatalf("no audit rows were handed to the recorder")
	}
	known := map[string]bool{}
	for _, row := range env.rows(t, "") {
		known[row.ID] = true
	}
	for _, id := range probe.ids {
		if !known[id] {
			t.Fatalf("recorder got id %q which matches no audit row", id)
		}
	}
}

// A blocked event is precisely the one an auditor wants exported, and the
// events.Handler stage never sees it — a gate's Block short-circuits the
// chain. Recorders must be invoked anyway.
func TestAudit_RecorderRunsEvenWhenAGateBlocks(t *testing.T) {
	probe := &recorderPlugin{}
	env := newAuditEnv(t, probe, &gatePlugin{
		on:     events.EventLoginAttempt,
		status: http.StatusTooManyRequests,
		msg:    "too many attempts",
	})
	env.register(t, "kit@example.test")
	before := len(probe.ids)
	res := env.post(t, "/api/auth/login", map[string]any{
		"email": "kit@example.test", "password": auditTestPassword,
	})
	res.Body.Close()

	if len(probe.ids) <= before {
		t.Fatalf("a blocked login.attempt reached no recorder")
	}
}

// --- test plugins ----------------------------------------------------------

// gatePlugin blocks one event type, standing in for lockout / IP blocking.
type gatePlugin struct {
	on     events.EventType
	status int
	msg    string
}

func (g *gatePlugin) Name() string { return "test-gate" }

func (g *gatePlugin) Routes(host plugin.PluginHost, _ plugin.Router, _ huma.API, _ string) {
	host.RegisterEventGate(g)
}

func (g *gatePlugin) Handle(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
	if ev.Type == g.on {
		return events.Block(g.status, g.msg), nil
	}
	return events.Continue(), nil
}

// recorderPlugin captures the audit-log ids the host hands to recorders.
type recorderPlugin struct {
	ids []string
}

func (r *recorderPlugin) Name() string { return "test-recorder" }

func (r *recorderPlugin) Routes(host plugin.PluginHost, _ plugin.Router, _ huma.API, _ string) {
	reg, ok := host.(plugin.AuditRecorderRegistrar)
	if !ok {
		return
	}
	reg.RegisterAuditRecorder(func(_ context.Context, auditLogID string, _ *string) {
		r.ids = append(r.ids, auditLogID)
	})
}
