package apikey

// apikey_audit_test.go — minting and revoking a long-lived credential
// leaves no trace, and a huge expires_in_days mints one that is already
// dead.
//
// (1) NO AUDIT TRAIL AT ALL. `grep -rn 'host.Emit|LogAuditEvent|events\.'
// plugins/apikey/` returns zero non-test hits. POST /api-keys mints a
// bearer credential that authenticates as its owner on every route and
// never expires by default; DELETE /api-keys/{id} takes one away. Both
// leave exactly the same footprint as GET /api-keys — none. An attacker who
// has a session for five minutes and mints a key for persistence is
// invisible in the audit log, and the owner revoking a key later has no
// record of when. Every OTHER credential-bearing lifecycle in the tree
// (login, password change, admin ban, SCIM deprovision) writes a row.
//
// (2) EXPIRY OVERFLOW. handlers.go computes
// `time.Duration(*req.ExpiresInDays) * 24 * time.Hour`. Above ~106,751 days
// that int64 multiplication overflows, so expires_in_days=200000 wraps
// NEGATIVE and the handler answers 201 with a plaintext secret whose
// ExpiresAt is in the PAST — a credential the resolver refuses on first use.
//
// Both refusals are paired with positive controls: the key must still be
// created, stored and returned exactly as before.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
)

// --- harness extension -----------------------------------------------------

// auditingRepo is fakeRepo with a recording LogAuditEvent. The stock
// fakeRepo swallows audit writes (returns nil, keeps nothing), so the
// existing apikey harness cannot observe an audit row at all; this is the
// smallest extension that lets it.
type auditingRepo struct {
	*fakeRepo
	mu   sync.Mutex
	rows []domain.NewAuditLog
}

func newAuditingRepo() *auditingRepo {
	return &auditingRepo{fakeRepo: newFakeRepo()}
}

func (a *auditingRepo) LogAuditEvent(_ context.Context, in domain.NewAuditLog) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, in)
	return nil
}

func (a *auditingRepo) audit() []domain.NewAuditLog {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]domain.NewAuditLog, len(a.rows))
	copy(out, a.rows)
	return out
}

func auditEventTypes(rows []domain.NewAuditLog) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.EventType)
	}
	return out
}

// newAuditServer mirrors newServer but wires the recording repo.
func newAuditServer(t *testing.T, cfg Config, user domain.User, repo *auditingRepo) *httptest.Server {
	t.Helper()
	host := newFakeHost(repo)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})

	mux := http.NewServeMux()
	p := New(cfg).(*apiKeyPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")

	return httptest.NewServer(mux)
}

func seedAuditUser(t *testing.T, r *auditingRepo) domain.User {
	t.Helper()
	u := domain.User{
		ID:        "11111111-1111-4111-8111-111111111111",
		Email:     "owner@example.com",
		Role:      "user",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	r.putUser(u)
	return u
}

// --- (1) the missing audit trail -------------------------------------------

func TestAPIKeyCreate_IsAudited(t *testing.T) {
	repo := newAuditingRepo()
	user := seedAuditUser(t, repo)
	srv := newAuditServer(t, Config{}, user, repo)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"name": "persistence-bot"})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d, want 201", res.StatusCode)
	}
	var out createResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// POSITIVE CONTROL: the credential really was minted and stored.
	if out.Secret == "" || out.APIKey.ID == "" {
		t.Fatalf("create must keep returning a usable key: %+v", out)
	}
	if _, ok := repo.keyByID(out.APIKey.ID); !ok {
		t.Fatalf("key %s not persisted", out.APIKey.ID)
	}

	rows := repo.audit()
	if len(rows) == 0 {
		t.Fatalf("POST /api-keys minted a long-lived bearer credential for %s and wrote NO "+
			"audit row. Minting a key is a persistence primitive; it must leave the same kind "+
			"of trace as an admin ban or a password change.", user.ID)
	}

	var created *domain.NewAuditLog
	for i, r := range rows {
		if r.EventType == "apikey.created" {
			created = &rows[i]
		}
	}
	if created == nil {
		t.Fatalf("no apikey.created row, got %v", auditEventTypes(rows))
	}
	if created.UserID == nil || *created.UserID != user.ID {
		t.Errorf("apikey.created must name the actor, got %v", created.UserID)
	}

	// The row must identify WHICH key, and must never carry the secret.
	m := map[string]any{}
	if len(created.Metadata) > 0 {
		if err := json.Unmarshal(created.Metadata, &m); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
	}
	if m["credential_id"] != out.APIKey.ID {
		t.Errorf("apikey.created metadata must carry credential_id=%s (a `key_id` key would be "+
			"redacted by the audit scrubber's 'key' fragment), got %v", out.APIKey.ID, m)
	}
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if s == out.Secret || (out.Secret != "" && strings.Contains(s, out.Secret)) {
			t.Fatalf("metadata key %q leaks the plaintext secret into the audit log", k)
		}
	}
}

func TestAPIKeyDelete_IsAudited(t *testing.T) {
	repo := newAuditingRepo()
	user := seedAuditUser(t, repo)
	srv := newAuditServer(t, Config{}, user, repo)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"name": "to-be-revoked"})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var out createResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()

	before := len(repo.audit())

	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/api-keys/"+out.APIKey.ID, nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	del, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d, want 204", del.StatusCode)
	}
	// POSITIVE CONTROL: revocation still happens.
	if _, ok := repo.keyByID(out.APIKey.ID); ok {
		t.Fatalf("key %s survived DELETE", out.APIKey.ID)
	}

	rows := repo.audit()
	if len(rows) == before {
		t.Fatalf("DELETE /api-keys/%s revoked a credential and wrote no audit row (%d rows "+
			"before and after: %v)", out.APIKey.ID, before, auditEventTypes(rows))
	}
}

// --- (2) the expiry overflow -----------------------------------------------

// TestAPIKeyCreate_HugeExpiryDoesNotWrapNegative asserts on the PERSISTED
// row, not the status code: the failure mode is a 201 handing back a
// plaintext secret whose stored expires_at is already in the past.
func TestAPIKeyCreate_HugeExpiryDoesNotWrapNegative(t *testing.T) {
	repo := newAuditingRepo()
	user := seedAuditUser(t, repo)
	srv := newAuditServer(t, Config{}, user, repo)
	defer srv.Close()

	// POSITIVE CONTROL: a sane expiry still works and lands in the future.
	body, _ := json.Marshal(map[string]any{"name": "ten-years", "expires_in_days": 3650})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var ok createResponse
	if err := json.NewDecoder(res.Body).Decode(&ok); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expires_in_days=3650: %d, want 201", res.StatusCode)
	}
	stored, found := repo.keyByID(ok.APIKey.ID)
	if !found {
		t.Fatalf("key not persisted")
	}
	if stored.ExpiresAt == nil || !stored.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("expires_in_days=3650 must store a future expiry, got %v", stored.ExpiresAt)
	}

	// THE DEFECT.
	body, _ = json.Marshal(map[string]any{"name": "overflow", "expires_in_days": 200000})
	res, err = http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var over createResponse
	_ = json.NewDecoder(res.Body).Decode(&over)
	code := res.StatusCode
	res.Body.Close()

	if code == http.StatusCreated {
		k, found := repo.keyByID(over.APIKey.ID)
		if !found {
			t.Fatalf("201 but no stored key")
		}
		if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now().UTC()) {
			t.Fatalf("expires_in_days=200000 answered 201 with a plaintext secret whose stored "+
				"expires_at is %s — in the PAST. time.Duration(days)*24*time.Hour overflows "+
				"int64 above ~106751 days; the caller is handed a credential that is dead on "+
				"arrival. Want a 400.", k.ExpiresAt.UTC())
		}
	}
	if code != http.StatusBadRequest {
		t.Fatalf("expires_in_days=200000: %d, want 400", code)
	}
}
