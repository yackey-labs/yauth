package auditexport

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
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
			audit, err := loadAudit(ctx, auditRepo, e.AuditLogID)
			if err != nil || audit == nil {
				// Audit row missing — treat as sent so we don't loop.
				_ = st.MarkSent(e.ID)
				return
			}
			attempt := e.Attempts + 1
			err = dispatcher.SendOne(ctx, dest, audit)
			kindTag := string(dest.Kind)
			destIDStr := dest.ID
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
					_ = st.MarkFailed(e.ID, attempt, err.Error())
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

// loadAudit looks up the audit log row by ID. The current AuditLogRepository
// only exposes a list filter, so we scan up to 10k recent rows. A follow-up
// issue will add GetAuditLogByID; for now this matches the Rust PR's
// approach for the memory backend.
func loadAudit(ctx context.Context, auditRepo repo.AuditLogRepository, id string) (*domain.AuditLog, error) {
	rows, err := auditRepo.ListAuditLog(ctx, domain.ListAuditFilters{Limit: 10000})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, nil
}
