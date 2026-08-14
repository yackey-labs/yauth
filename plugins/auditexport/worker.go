package auditexport

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// BackoffSchedule is the per-attempt next-delay; index = attempts so far.
// After the schedule is exhausted the worker transitions the row to
// dead_letter. Mirrors the Rust PR: 1s, 5s, 30s, 5m, 1h.
var BackoffSchedule = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
	1 * time.Hour,
}

// backoffFor returns the delay before the attempts'th failure may be retried.
// attempts is 1-based (the attempt that just failed), and the last entry is
// the clamp, so an over-long ladder settles at the 1h tail rather than
// panicking on an out-of-range index.
//
// This is the only reader BackoffSchedule has ever had. Until it existed the
// schedule was documentation-only: MarkFailed re-armed the row as pending and
// the next tick claimed it, so at the defaults (BatchInterval 5s,
// RetryMaxAttempts 5) a receiver down for 25 seconds dead-lettered every
// pending row — permanently, since dead_letter is terminal.
func backoffFor(attempts int32) time.Duration {
	idx := int(attempts) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(BackoffSchedule) {
		idx = len(BackoffSchedule) - 1
	}
	return BackoffSchedule[idx]
}

// WorkerConfig is the per-destination drain worker config.
type WorkerConfig struct {
	DestinationID    string
	BatchSize        int
	BatchInterval    time.Duration
	MaxInflight      int
	RetryMaxAttempts int32
}

// WorkerHandle controls a running drain worker.
type WorkerHandle struct {
	shutdown chan struct{}
	done     chan struct{}
	once     sync.Once
}

// Shutdown signals the worker to drain and waits up to timeout. Returns
// true if the worker exited cleanly, false if the timeout fired and we
// abandoned in-flight goroutines (they continue running until they
// finish their current HTTP call but are no longer attached).
func (h *WorkerHandle) Shutdown(timeout time.Duration) bool {
	h.once.Do(func() {
		close(h.shutdown)
	})
	select {
	case <-h.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// SpawnWorker starts a drain goroutine for one destination. The worker
// loops: claim_pending -> dispatch -> mark_sent / mark_failed /
// mark_dead_letter -> sleep(BatchInterval) until shutdown.
//
// The dispatcher and audit repo are passed in directly so the worker
// does not hold a reference to the YAuth root (no import cycle).
func SpawnWorker(
	cfg WorkerConfig,
	st *store,
	auditRepo repo.AuditLogRepository,
	dispatcher *Dispatcher,
	metrics *Metrics,
) *WorkerHandle {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchInterval <= 0 {
		cfg.BatchInterval = 5 * time.Second
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 4
	}
	if cfg.RetryMaxAttempts <= 0 {
		cfg.RetryMaxAttempts = 5
	}
	h := &WorkerHandle{
		shutdown: make(chan struct{}),
		done:     make(chan struct{}),
	}
	go func() {
		defer close(h.done)
		// Tracks in-flight dispatch goroutines so the final drain after
		// shutdown waits for them.
		var inflight sync.WaitGroup
		sem := make(chan struct{}, cfg.MaxInflight)
		ticker := time.NewTicker(cfg.BatchInterval)
		defer ticker.Stop()
		// Run one drain immediately so tests that don't sleep still
		// see at least one pass.
		drainOnce(cfg, st, auditRepo, dispatcher, metrics, sem, &inflight)
		for {
			select {
			case <-h.shutdown:
				// Final drain: pick up anything pending then wait for
				// in-flight goroutines to settle.
				drainOnce(cfg, st, auditRepo, dispatcher, metrics, sem, &inflight)
				inflight.Wait()
				return
			case <-ticker.C:
				drainOnce(cfg, st, auditRepo, dispatcher, metrics, sem, &inflight)
				// Best-effort lag gauge.
				if oldest := st.OldestPending(cfg.DestinationID); oldest != nil {
					lag := time.Since(*oldest).Seconds()
					if lag < 0 {
						lag = 0
					}
					metrics.RecordLag(cfg.DestinationID, lag)
				} else {
					metrics.RecordLag(cfg.DestinationID, 0)
				}
			}
		}
	}()
	return h
}

func drainOnce(
	cfg WorkerConfig,
	st *store,
	auditRepo repo.AuditLogRepository,
	dispatcher *Dispatcher,
	metrics *Metrics,
	sem chan struct{},
	inflight *sync.WaitGroup,
) {
	claimed := st.ClaimPending(cfg.DestinationID, cfg.BatchSize)
	if len(claimed) == 0 {
		return
	}
	dest, err := st.GetDestination(cfg.DestinationID)
	if err != nil {
		return
	}
	if dest.Status != domain.DestinationStatusActive {
		return
	}
	// One audit-log read per drain PASS, not one per outbox row. loadAudit used
	// to run inside each dispatch goroutine, so a full batch cost up to
	// BatchSize (100) ten-thousand-row queries per pass and each row's lookup
	// happened at an arbitrary distance from its claim. Indexing once keeps the
	// claim-to-lookup window tight and the query count at one.
	//
	// A read error aborts the pass without touching any row: the entries stay
	// pending and are re-claimed on the next tick. That is deliberate — a
	// transient repo blip is not the outbox row's fault and must not spend one
	// of its five attempts, and it certainly must not be mistaken for
	// "delivered" the way it was below.
	lookupCtx, cancelLookup := context.WithTimeout(context.Background(), 30*time.Second)
	index, err := loadAuditIndex(lookupCtx, auditRepo)
	cancelLookup()
	if err != nil {
		metrics.RecordOutcome(dest.ID, string(dest.Kind), "audit_lookup_error")
		return
	}
	for _, entry := range claimed {
		// Bound inflight via semaphore.
		sem <- struct{}{}
		inflight.Add(1)
		go func(e *domain.AuditOutboxEntry) {
			defer func() {
				<-sem
				inflight.Done()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			attempt := e.Attempts + 1
			kindTag := string(dest.Kind)
			destIDStr := dest.ID
			audit, found := index[e.AuditLogID]
			if !found || audit == nil {
				// This branch used to do `_ = st.MarkSent(e.ID)` — "audit row
				// missing, treat as sent so we don't loop". Nothing had been
				// sent. The row was never POSTed anywhere, no metric moved, no
				// LastError was written, and GET /audit/destinations/{id}/outbox
				// reported it delivered: a silent hole in a compliance feed that
				// the admin panel swore was complete. And the branch was
				// reachable in ordinary operation, because the lookup only sees
				// the 10 000 most recent audit rows (newest-first on both
				// backends) while the replay route validates ids against a
				// 100 000-row window.
				//
				// So it takes the same ladder a dispatch failure takes: retry
				// with backoff, dead-letter at RetryMaxAttempts, and say so in
				// last_error. A row we cannot deliver must never read as
				// delivered — dead_letter is loud, and being loud is the point.
				const missingMsg = "audit row not found within the drain scan window"
				if attempt >= cfg.RetryMaxAttempts {
					_ = st.MarkDeadLetter(e.ID, attempt, missingMsg)
					metrics.RecordDeadLetter(destIDStr)
				} else {
					_ = st.MarkFailed(e.ID, attempt, missingMsg, time.Now().UTC().Add(backoffFor(attempt)))
				}
				metrics.RecordOutcome(destIDStr, kindTag, "audit_missing")
				return
			}
			err := dispatcher.SendOne(ctx, dest, audit)
			switch {
			case err == nil:
				_ = st.MarkSent(e.ID)
				metrics.RecordOutcome(destIDStr, kindTag, "success")
				now := time.Now().UTC()
				ptr := &now
				_, _ = st.UpdateDestination(dest.ID, domain.UpdateAuditExportDestination{
					LastSuccessAt: &ptr,
				})
			case errors.Is(err, ErrNotImplemented):
				_ = st.MarkDeadLetter(e.ID, attempt, "destination not implemented: "+err.Error())
				metrics.RecordDeadLetter(destIDStr)
				metrics.RecordOutcome(destIDStr, kindTag, "not_implemented")
			default:
				if attempt >= cfg.RetryMaxAttempts {
					_ = st.MarkDeadLetter(e.ID, attempt, err.Error())
					metrics.RecordDeadLetter(destIDStr)
					metrics.RecordOutcome(destIDStr, kindTag, "dead_letter")
				} else {
					// Spaced by BackoffSchedule, which nothing consulted before
					// this: the row went straight back to pending and the next
					// tick spent another of its five attempts on a receiver that
					// had been down for one BatchInterval.
					_ = st.MarkFailed(e.ID, attempt, err.Error(), time.Now().UTC().Add(backoffFor(attempt)))
					metrics.RecordOutcome(destIDStr, kindTag, "retry")
				}
				now := time.Now().UTC()
				ptr := &now
				_, _ = st.UpdateDestination(dest.ID, domain.UpdateAuditExportDestination{
					LastFailureAt: &ptr,
				})
			}
		}(entry)
	}
}

// loadAuditIndex reads the recent audit rows once and indexes them by ID. The
// current AuditLogRepository only exposes a list filter, so this still sees
// only the 10k most recent rows (both backends order newest-first) — an outbox
// row older than that window is no longer silently "delivered", it retries and
// then dead-letters with an explicit last_error. A real GetAuditLogByID on
// repo.AuditLogRepository is the proper fix and is deliberately out of scope
// here; the callers of this function must keep treating a miss as a failure,
// not as a success.
//
// The returned map is read-only from the moment it is returned, which is what
// makes it safe to share across the per-entry dispatch goroutines.
func loadAuditIndex(ctx context.Context, auditRepo repo.AuditLogRepository) (map[string]*domain.AuditLog, error) {
	rows, err := auditRepo.ListAuditLog(ctx, domain.ListAuditFilters{Limit: 10000})
	if err != nil {
		return nil, err
	}
	index := make(map[string]*domain.AuditLog, len(rows))
	for _, r := range rows {
		index[r.ID] = r
	}
	return index, nil
}
