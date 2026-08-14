// security_export_drain_test.go — the two drain-loop halves of the
// audit-export delivery finding: an audit row that was never delivered is
// recorded as delivered, and the documented retry backoff does not exist.
//
// 1. drainOnce (worker.go) claims an outbox row, calls loadAudit, and on
//    `err != nil || audit == nil` does `_ = st.MarkSent(e.ID)` with the comment
//    "Audit row missing — treat as sent so we don't loop." loadAudit is a linear
//    scan over ListAuditLog(Limit: 10000), newest-first on both backends, so
//    any audit row past the 10 000 most recent — or any transient repo error —
//    takes that branch. Nothing was ever POSTed to the receiver, no metric was
//    recorded, no LastError was written, and GET /audit/destinations/{id}/outbox
//    reports the row as sent. For a compliance export that is the worst possible
//    failure mode: a silent hole in the SIEM feed that the admin panel swears
//    is complete.
//
// 2. BackoffSchedule (worker.go:16, 1s/5s/30s/5m/1h) is referenced nowhere
//    outside its own declaration. store.MarkFailed puts the row straight back to
//    `pending` and ClaimPending re-claims it on the very next BatchInterval tick,
//    so the RetryMaxAttempts=5 ladder is burned through in 5 ticks. docs/
//    audit-export/README.md advertises "backoff, dead-letter after 5 attempts";
//    what actually happens is that a receiver that blips for a few seconds
//    dead-letters the entire backlog, and dead_letter is terminal — those rows
//    are never delivered.
//
// Both tests carry a POSITIVE CONTROL: the audit row that IS present must still
// be delivered and marked sent, and a receiver that fails once and then recovers
// must still get its delivery. A "fix" that stops marking anything sent, or that
// stops retrying altogether, fails those.
package auditexport

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
)

// runDrainPass runs exactly one drainOnce pass for the destination and waits
// for every dispatch goroutine it spawned to finish. The worker loop
// (SpawnWorker) is the same call with a ticker around it; driving drainOnce
// directly keeps the assertion on one pass instead of on wall-clock luck.
func runDrainPass(p *plugin, destID string) {
	sem := make(chan struct{}, 4)
	var inflight sync.WaitGroup
	drainOnce(WorkerConfig{
		DestinationID:    destID,
		BatchSize:        100,
		BatchInterval:    20 * time.Millisecond,
		MaxInflight:      4,
		RetryMaxAttempts: 5,
	}, p.store, p.auditRepo, p.dispatcher, p.metrics, sem, &inflight)
	inflight.Wait()
}

func outboxRow(t *testing.T, p *plugin, destID, entryID string) *domain.AuditOutboxEntry {
	t.Helper()
	for _, e := range p.store.ListOutboxForDestination(destID, 1000) {
		if e.ID == entryID {
			return e
		}
	}
	t.Fatalf("outbox row %s not found for destination %s", entryID, destID)
	return nil
}

// TestAuditExport_MissingAuditRowIsNeverMarkedSent is the finding: the drain
// worker reports an undelivered row as delivered.
func TestAuditExport_MissingAuditRowIsNeverMarkedSent(t *testing.T) {
	p, repo := newAuditExport(t)
	recv := newFakeReceiver()
	defer recv.Close()
	dest := makeWebhookDest(t, p, nil, recv.URL(), "")

	// An outbox row whose audit id the repo does not hold — exactly what
	// loadAudit's 10 000-row scan window produces on a busy deployment.
	missingAuditID := uuid.NewString()
	ids := p.store.EnqueueForAudit(missingAuditID, nil)
	if len(ids) != 1 {
		t.Fatalf("expected 1 outbox row for the active destination, got %d", len(ids))
	}
	entryID := ids[0]

	runDrainPass(p, dest.ID)

	// STATE: nothing was ever sent to the receiver...
	if got := recv.Count(); got != 0 {
		t.Fatalf("receiver got %d deliveries for an audit row that does not exist", got)
	}
	row := outboxRow(t, p, dest.ID, entryID)
	// ...so the row must NOT read as delivered.
	if row.Status == domain.OutboxStatusSent {
		t.Errorf("undelivered outbox row marked %q: the SIEM feed has a silent hole the admin panel reports as complete",
			row.Status)
	}
	if row.Attempts != 1 {
		t.Errorf("failed lookup must count as an attempt: attempts=%d, want 1", row.Attempts)
	}
	if row.LastError == nil || *row.LastError == "" {
		t.Errorf("failed lookup must record a last_error, got %v", row.LastError)
	}
	sawOutcome := false
	for k, v := range p.Metrics().EventsByOutcome() {
		if v > 0 {
			sawOutcome = true
			t.Logf("outcome recorded: %s=%d", k, v)
		}
	}
	if !sawOutcome {
		t.Errorf("a dropped audit row recorded no outcome metric at all: %v", p.Metrics().EventsByOutcome())
	}

	// POSITIVE CONTROL: the ordinary path still delivers and still marks sent.
	// A fix that simply never calls MarkSent breaks the exporter outright.
	goodAuditID := writeAudit(t, p, repo, nil)
	var goodEntryID string
	for _, e := range p.store.ListOutboxForDestination(dest.ID, 1000) {
		if e.AuditLogID == goodAuditID {
			goodEntryID = e.ID
		}
	}
	if goodEntryID == "" {
		t.Fatal("no outbox row enqueued for the real audit row")
	}
	runDrainPass(p, dest.ID)
	if got := recv.Count(); got < 1 {
		t.Fatalf("POSITIVE CONTROL: a real audit row was not delivered (receiver count %d)", got)
	}
	if good := outboxRow(t, p, dest.ID, goodEntryID); good.Status != domain.OutboxStatusSent {
		t.Fatalf("POSITIVE CONTROL: a delivered row must be marked sent, got %q", good.Status)
	}
}

// TestAuditExport_TransientReceiverFailureDoesNotDeadLetterTheBacklog is the
// backoff finding, driven through the real worker: a receiver that 500s for a
// moment must not burn the whole retry ladder, because dead_letter is terminal.
func TestAuditExport_TransientReceiverFailureDoesNotDeadLetterTheBacklog(t *testing.T) {
	p, repo := newAuditExport(t) // BatchInterval 20ms, RetryMaxAttempts 5
	recv := newFakeReceiver()
	defer recv.Close()
	recv.SetStatus(500)
	dest := makeWebhookDest(t, p, nil, recv.URL(), "")
	writeAudit(t, p, repo, nil)

	if got := p.Refresh(); got.Forced != 0 {
		t.Fatalf("unexpected forced shutdown while spawning: %+v", got)
	}
	if got := p.WorkerCount(); got != 1 {
		t.Fatalf("expected 1 drain worker after Refresh, got %d", got)
	}
	defer func() { _ = p.Shutdown(t.Context()) }()

	// 300ms is 15 BatchIntervals. With the documented 1s/5s/30s/5m/1h backoff
	// the row is on attempt 1 and still pending; with the retry loop as written
	// it has been re-claimed every 20ms and is already terminal.
	time.Sleep(300 * time.Millisecond)

	rows := p.store.ListOutboxForDestination(dest.ID, 1000)
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 outbox row, got %d", len(rows))
	}
	row := rows[0]
	if row.Status == domain.OutboxStatusDeadLetter {
		t.Errorf("receiver down for 300ms dead-lettered the row (attempts=%d): dead_letter is terminal, so this audit event is lost forever",
			row.Attempts)
	}
	if row.Attempts >= 5 {
		t.Errorf("retry ladder burned through in 300ms: attempts=%d after 15 batch intervals — BackoffSchedule (1s, 5s, 30s, 5m, 1h) is never consulted",
			row.Attempts)
	}
	if dl := p.store.DeadLetterCount(dest.ID); dl != 0 {
		t.Errorf("dead_letter_count=%d after a 300ms receiver outage, want 0", dl)
	}
}

// TestAuditExport_RecoveredReceiverStillGetsTheDelivery is the POSITIVE CONTROL
// for the backoff change: retries must still happen and still succeed. A "fix"
// that spaces retries by never retrying fails here.
func TestAuditExport_RecoveredReceiverStillGetsTheDelivery(t *testing.T) {
	p, repo := newAuditExport(t)

	// Fails the first attempt, succeeds on every attempt after it.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dest := makeWebhookDest(t, p, nil, srv.URL+"/hook", "")
	writeAudit(t, p, repo, nil)
	p.Refresh()
	defer func() { _ = p.Shutdown(t.Context()) }()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		rows := p.store.ListOutboxForDestination(dest.ID, 10)
		if len(rows) == 1 && rows[0].Status == domain.OutboxStatusSent {
			if hits.Load() < 2 {
				t.Fatalf("POSITIVE CONTROL: delivery recorded sent after %d attempt(s); the failing attempt was not retried", hits.Load())
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	rows := p.store.ListOutboxForDestination(dest.ID, 10)
	status := "<none>"
	if len(rows) == 1 {
		status = string(rows[0].Status)
	}
	t.Fatalf("POSITIVE CONTROL: a receiver that recovered after one failure never got its delivery (attempts seen by receiver: %d, outbox status %q)",
		hits.Load(), status)
}
