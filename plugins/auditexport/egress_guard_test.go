// egress_guard_test.go — regression suite for "audit-export turns a
// destination row into an internal read primitive, and its receiver-side
// verifier fails open on an empty secret".
//
// Two defects, both on the export path:
//
//   - Dispatcher.sendWebhook (dispatcher.go) POSTs to dest.Config["url"]
//     verbatim. On any non-2xx it reads 512 bytes of the REMOTE body into the
//     error it returns. drainOnce (worker.go) hands that error string to
//     store.MarkFailed, which persists it as AuditOutboxEntry.LastError, and
//     registerOutbox (routes.go) serialises LastError back out on
//     GET /audit/destinations/{id}/outbox. So an admin who points a
//     destination at an internal service reads that service's error bodies
//     through the audit-export API — the same blind-SSRF-to-read-primitive
//     shape as the webhooks plugin, one layer down.
//
//   - VerifyHMACSignature is the helper downstream receivers use to
//     authenticate an export delivery. It never checks that secret is
//     non-empty, so a consumer whose YAUTH_AUDIT_HMAC_SECRET env var is unset
//     verifies every payload against the empty key — and an attacker who
//     knows the recipe (it is documented) can compute a signature over any
//     body that the receiver will accept. Failing open on missing key
//     material is worse than not verifying at all, because the receiver
//     believes it verified.
//
// Both refusals are paired with positive controls: a healthy 2xx export still
// succeeds and still carries a verifiable signature, a real secret still
// verifies, and a wrong secret is still rejected with the existing sentinel.
package auditexport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
)

// bodyReceiver answers with a fixed status and a fixed body, and counts the
// requests it saw. The body is the sentinel a leak would carry.
type bodyReceiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	hits   int
	status int
	body   string
}

func newBodyReceiver(status int, body string) *bodyReceiver {
	r := &bodyReceiver{status: status, body: body}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		r.hits++
		r.mu.Unlock()
		w.WriteHeader(r.status)
		_, _ = w.Write([]byte(r.body))
	}))
	return r
}

func (r *bodyReceiver) Hits() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

func (r *bodyReceiver) Close() { r.srv.Close() }

func auditRow() *domain.AuditLog {
	return &domain.AuditLog{
		ID:        uuid.NewString(),
		EventType: "user.login",
		CreatedAt: time.Now().UTC(),
	}
}

// --- auditexport-5: the remote body ends up in last_error ----------------

// TestSendWebhook_FailureErrorCarriesNoRemoteBody asserts at the source: the
// error sendWebhook returns is the string that becomes last_error, so if the
// receiver's bytes are not in the error they cannot reach the outbox route.
func TestSendWebhook_FailureErrorCarriesNoRemoteBody(t *testing.T) {
	const sentinel = "SENTINEL-INTERNAL-cluster-health-token"

	recv := newBodyReceiver(http.StatusInternalServerError, sentinel)
	defer recv.Close()

	p, _ := newAuditExport(t)
	dest := &domain.AuditExportDestination{
		ID:     uuid.NewString(),
		Name:   "internal",
		Kind:   domain.DestinationKindWebhook,
		Format: domain.AuditExportFormatJSON,
		Config: map[string]string{"url": recv.srv.URL + "/_cluster/health"},
		Status: domain.DestinationStatusActive,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := p.Dispatcher().SendOne(ctx, dest, auditRow())
	if err == nil {
		t.Fatalf("expected a dispatch error on 500")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("the dispatch error carries the remote body back to the operator: %v", err)
	}
	// POSITIVE CONTROL: the operator must still learn WHY it failed — the
	// status code stays in the message. Suppressing the body must not mean
	// suppressing the diagnosis.
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("the dispatch error no longer names the status code: %v", err)
	}
}

// TestOutbox_LastErrorCarriesNoRemoteBody drives the real drain loop so the
// assertion lands on the persisted, operator-readable field that
// GET /audit/destinations/{id}/outbox serialises.
func TestOutbox_LastErrorCarriesNoRemoteBody(t *testing.T) {
	const sentinel = "SENTINEL-INTERNAL-cluster-health-token"

	recv := newBodyReceiver(http.StatusInternalServerError, sentinel)
	defer recv.Close()

	p, r := newAuditExport(t)
	dest := makeWebhookDest(t, p, nil, recv.srv.URL+"/_cluster/health", "")
	writeAudit(t, p, r, nil)

	cfg := WorkerConfig{
		DestinationID:    dest.ID,
		BatchSize:        10,
		BatchInterval:    20 * time.Millisecond,
		MaxInflight:      1,
		RetryMaxAttempts: 5,
	}
	var inflight sync.WaitGroup
	sem := make(chan struct{}, 1)
	drainOnce(cfg, p.store, p.auditRepo, p.Dispatcher(), NewMetrics(), sem, &inflight)
	inflight.Wait()

	entries := p.store.ListOutboxForDestination(dest.ID, 10)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one outbox entry, got %d", len(entries))
	}
	e := entries[0]
	if e.LastError == nil {
		t.Fatalf("the failed delivery recorded no last_error at all — operators lose the failure")
	}
	if strings.Contains(*e.LastError, sentinel) {
		t.Errorf("outbox last_error stores the remote service's response body: %q", *e.LastError)
	}
	// POSITIVE CONTROL: the failure is still visible and still attributable.
	if !strings.Contains(*e.LastError, "500") {
		t.Errorf("outbox last_error no longer names the status code: %q", *e.LastError)
	}
	if recv.Hits() != 1 {
		t.Fatalf("expected the drain to attempt exactly one delivery, got %d", recv.Hits())
	}
}

// TestSendWebhook_HealthyDestinationStillExports is the standing positive
// control for the pair above: a 2xx receiver still gets the rendered event
// and SendOne still reports success.
func TestSendWebhook_HealthyDestinationStillExports(t *testing.T) {
	recv := newBodyReceiver(http.StatusOK, "")
	defer recv.Close()

	p, _ := newAuditExport(t)
	dest := &domain.AuditExportDestination{
		ID:     uuid.NewString(),
		Name:   "siem",
		Kind:   domain.DestinationKindWebhook,
		Format: domain.AuditExportFormatJSON,
		Config: map[string]string{"url": recv.srv.URL + "/ingest"},
		Status: domain.DestinationStatusActive,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Dispatcher().SendOne(ctx, dest, auditRow()); err != nil {
		t.Fatalf("healthy export failed: %v", err)
	}
	if recv.Hits() != 1 {
		t.Fatalf("receiver saw %d requests, want 1", recv.Hits())
	}
}

// --- auditexport-11: the verifier fails open on an empty secret ----------

// TestVerifyHMACSignature_RefusesEmptySecret is the rider. The helper is
// exported for downstream receivers; with an unset secret it currently
// happily verifies a signature that anyone can compute, and returns nil —
// which the receiver reads as "authenticated".
func TestVerifyHMACSignature_RefusesEmptySecret(t *testing.T) {
	body := []byte(`{"event_type":"user.login"}`)
	now := int64(1_700_000_000)

	// The attacker computes the signature with the same empty key the
	// misconfigured receiver holds.
	forged := fmt.Sprintf("t=%d,v1=%s", now, ComputeHMACSignature("", now, body))

	err := VerifyHMACSignature("", forged, body, time.Unix(now, 0), 300*time.Second)
	if err == nil {
		t.Errorf("VerifyHMACSignature accepted a payload signed with an EMPTY secret — " +
			"a receiver with an unset secret authenticates anything")
	}

	// POSITIVE CONTROL 1: a real secret still verifies.
	const secret = "a-real-shared-secret-for-the-receiver"
	good := fmt.Sprintf("t=%d,v1=%s", now, ComputeHMACSignature(secret, now, body))
	if err := VerifyHMACSignature(secret, good, body, time.Unix(now, 0), 300*time.Second); err != nil {
		t.Fatalf("a correctly signed payload must still verify: %v", err)
	}

	// POSITIVE CONTROL 2: the existing mismatch path is unchanged.
	if err := VerifyHMACSignature(secret, forged, body, time.Unix(now, 0), 300*time.Second); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("a wrong-key signature must still be ErrSignatureMismatch, got %v", err)
	}
}
