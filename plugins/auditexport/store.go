// Package auditexport implements the audit-log SIEM/syslog/object-store
// export plugin for yauth-go (issue #96, port of yauth Rust PR #106).
//
// The plugin owns an in-memory store of destinations + outbox entries.
// Memory-backend semantics are canonical; SQL persistence is deferred to
// follow-up issues, the same precedent as Phase A/B / SAML / SCIM and
// matching the Rust PR's durability cut.
//
// Lifecycle:
//
//   - New() returns a plugin.Plugin that yauth.YAuth assembles.
//   - On Routes() the plugin registers admin CRUD endpoints, spawns one
//     drain worker per active destination, and exposes its EnqueueForAudit
//     hook via the package-level Hook(host) helper.
//   - On Shutdown(ctx) the plugin signals every worker to drain and waits
//     up to ctx.Deadline() for clean exit.
package auditexport

import (
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// store holds destinations + outbox entries in memory. All operations
// take the same mutex so audit→outbox enqueues and worker claims are
// linearisable — this is what makes the "outbox transactional" and
// "concurrent drain" pentests hold.
type store struct {
	mu               sync.Mutex
	destinations     map[string]*domain.AuditExportDestination
	outbox           map[string]*domain.AuditOutboxEntry
	deadLetterTotals map[string]uint64 // destinationID -> count
}

func newStore() *store {
	return &store{
		destinations:     make(map[string]*domain.AuditExportDestination),
		outbox:           make(map[string]*domain.AuditOutboxEntry),
		deadLetterTotals: make(map[string]uint64),
	}
}

// CreateDestination inserts a new destination row.
func (s *store) CreateDestination(input domain.NewAuditExportDestination) (*domain.AuditExportDestination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.destinations[input.ID]; exists {
		return nil, yautherr.ErrConflict
	}
	row := &domain.AuditExportDestination{
		ID:             input.ID,
		OrganizationID: input.OrganizationID,
		Name:           input.Name,
		Kind:           input.Kind,
		Format:         input.Format,
		Config:         copyConfig(input.Config),
		Status:         input.Status,
		CreatedAt:      input.CreatedAt,
		UpdatedAt:      input.UpdatedAt,
	}
	s.destinations[row.ID] = row
	// Return a defensive copy so callers can't mutate the stored row.
	return cloneDestination(row), nil
}

// GetDestination looks up a destination by id, returning yautherr.ErrNotFound
// when the row does not exist.
func (s *store) GetDestination(id string) (*domain.AuditExportDestination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.destinations[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneDestination(row), nil
}

// ListDestinationFilter is the filter passed to ListDestinations.
//
//	OrgScope == nil          -> return every row (default)
//	OrgScope == &"":         -> return only deployment-wide rows (OrgID nil)
//	OrgScope == &"<uuid>":   -> return only rows matching that org
type ListDestinationFilter struct {
	OrgScope *string
	Status   *domain.DestinationStatus
}

// ListDestinations returns all destinations matching the filter, sorted by
// CreatedAt ascending so order is deterministic for clients.
func (s *store) ListDestinations(filter ListDestinationFilter) []*domain.AuditExportDestination {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*domain.AuditExportDestination, 0, len(s.destinations))
	for _, d := range s.destinations {
		if filter.OrgScope != nil {
			want := *filter.OrgScope
			if want == "" {
				if d.OrganizationID != nil {
					continue
				}
			} else {
				if d.OrganizationID == nil || *d.OrganizationID != want {
					continue
				}
			}
		}
		if filter.Status != nil && d.Status != *filter.Status {
			continue
		}
		out = append(out, cloneDestination(d))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// UpdateDestination applies a partial update.
func (s *store) UpdateDestination(id string, changes domain.UpdateAuditExportDestination) (*domain.AuditExportDestination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.destinations[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	if changes.Name != nil {
		row.Name = *changes.Name
	}
	if changes.Format != nil {
		row.Format = *changes.Format
	}
	if changes.Config != nil {
		row.Config = copyConfig(changes.Config)
	}
	if changes.Status != nil {
		row.Status = *changes.Status
	}
	if changes.LastSuccessAt != nil {
		row.LastSuccessAt = *changes.LastSuccessAt
	}
	if changes.LastFailureAt != nil {
		row.LastFailureAt = *changes.LastFailureAt
	}
	if changes.UpdatedAt != nil {
		row.UpdatedAt = *changes.UpdatedAt
	} else {
		row.UpdatedAt = time.Now().UTC()
	}
	return cloneDestination(row), nil
}

// DeleteDestination removes a destination. Returns yautherr.ErrNotFound when
// the row does not exist.
func (s *store) DeleteDestination(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.destinations[id]; !ok {
		return yautherr.ErrNotFound
	}
	delete(s.destinations, id)
	return nil
}

// EnqueueForAudit inserts one outbox row per active destination whose
// OrganizationID matches the audit's org_id (deployment-wide rows always
// match; per-org rows only match if OrgIDs are equal). The same lock
// guards the matching scan and the inserts, so the "outbox transactional"
// invariant holds for memory-backend semantics.
//
// Returns the IDs of newly-created outbox rows.
func (s *store) EnqueueForAudit(auditLogID string, organizationID *string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	created := make([]string, 0, 4)
	for _, d := range s.destinations {
		if d.Status != domain.DestinationStatusActive {
			continue
		}
		if d.OrganizationID != nil {
			if organizationID == nil || *d.OrganizationID != *organizationID {
				continue
			}
		}
		id := uuid.NewString()
		s.outbox[id] = &domain.AuditOutboxEntry{
			ID:            id,
			AuditLogID:    auditLogID,
			DestinationID: d.ID,
			Status:        domain.OutboxStatusPending,
			Attempts:      0,
			CreatedAt:     now,
		}
		created = append(created, id)
	}
	return created
}

// ClaimPending atomically returns up to limit pending entries for the
// given destination, oldest first. Each claimed row's LastAttemptAt is
// bumped under the same lock to discourage concurrent workers from
// double-claiming (best-effort — at-least-once delivery, see pentest 5).
//
// A row whose NextAttemptAt is still in the future is skipped: that is the
// only thing standing between a failed row and an immediate re-claim on the
// next BatchInterval tick, which is how the documented backoff schedule used
// to get burned through in five ticks.
func (s *store) ClaimPending(destinationID string, limit int) []*domain.AuditOutboxEntry {
	if limit <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	claimAt := time.Now().UTC()
	candidates := make([]*domain.AuditOutboxEntry, 0)
	for _, e := range s.outbox {
		if e.DestinationID == destinationID && e.Status == domain.OutboxStatusPending {
			if e.NextAttemptAt != nil && e.NextAttemptAt.After(claimAt) {
				continue
			}
			candidates = append(candidates, e)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	now := time.Now().UTC()
	out := make([]*domain.AuditOutboxEntry, 0, len(candidates))
	for _, e := range candidates {
		e.LastAttemptAt = &now
		out = append(out, cloneEntry(e))
	}
	return out
}

// MarkSent transitions an outbox row to "sent".
func (s *store) MarkSent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.outbox[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	row.Status = domain.OutboxStatusSent
	now := time.Now().UTC()
	row.LastAttemptAt = &now
	row.LastError = nil
	return nil
}

// MarkFailed transitions an outbox row back to "pending" with an attempts
// counter bump, the latest error message, and the earliest time a worker may
// re-claim it. The drain worker picks it up again on the first tick at or
// after nextAttemptAt.
//
// nextAttemptAt is an explicit parameter rather than something computed in
// here on purpose: every caller has to state the spacing it wants, so a call
// site that means "retry immediately" (a test pinning the dead-letter ladder,
// say) has to say so instead of silently getting the old behaviour, where the
// row came back pending with no delay and the next 5s tick spent another
// attempt on a receiver that had been down for five seconds.
func (s *store) MarkFailed(id string, attempts int32, errMsg string, nextAttemptAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.outbox[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	row.Status = domain.OutboxStatusPending
	row.Attempts = attempts
	now := time.Now().UTC()
	row.LastAttemptAt = &now
	next := nextAttemptAt.UTC()
	row.NextAttemptAt = &next
	msg := errMsg
	row.LastError = &msg
	return nil
}

// MarkDeadLetter transitions an outbox row to terminal "dead_letter" and
// increments the per-destination dead-letter counter exposed by
// DeadLetterCount.
func (s *store) MarkDeadLetter(id string, attempts int32, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.outbox[id]
	if !ok {
		return yautherr.ErrNotFound
	}
	row.Status = domain.OutboxStatusDeadLetter
	row.Attempts = attempts
	now := time.Now().UTC()
	row.LastAttemptAt = &now
	msg := errMsg
	row.LastError = &msg
	s.deadLetterTotals[row.DestinationID]++
	return nil
}

// OldestPending returns the CreatedAt of the oldest pending outbox row for
// destinationID, or nil if none exists. Used for the lag-seconds metric.
func (s *store) OldestPending(destinationID string) *time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldest *time.Time
	for _, e := range s.outbox {
		if e.DestinationID != destinationID || e.Status != domain.OutboxStatusPending {
			continue
		}
		c := e.CreatedAt
		if oldest == nil || c.Before(*oldest) {
			oldest = &c
		}
	}
	return oldest
}

// DeadLetterCount returns the cumulative dead-letter total for the
// destination since process start.
func (s *store) DeadLetterCount(destinationID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadLetterTotals[destinationID]
}

// Replay inserts new pending outbox rows for the given (auditLogID,
// destinationIDs) pairs. Returns the IDs of newly-created rows.
func (s *store) Replay(auditLogID string, destinationIDs []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	out := make([]string, 0, len(destinationIDs))
	for _, dID := range destinationIDs {
		id := uuid.NewString()
		s.outbox[id] = &domain.AuditOutboxEntry{
			ID:            id,
			AuditLogID:    auditLogID,
			DestinationID: dID,
			Status:        domain.OutboxStatusPending,
			Attempts:      0,
			CreatedAt:     now,
		}
		out = append(out, id)
	}
	return out
}

// ListOutboxForDestination returns up to limit outbox rows for the
// destination, newest-first. Used by the admin outbox panel.
func (s *store) ListOutboxForDestination(destinationID string, limit int) []*domain.AuditOutboxEntry {
	if limit <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]*domain.AuditOutboxEntry, 0)
	for _, e := range s.outbox {
		if e.DestinationID == destinationID {
			rows = append(rows, cloneEntry(e))
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// --- helpers ---

func copyConfig(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneDestination(d *domain.AuditExportDestination) *domain.AuditExportDestination {
	cp := *d
	cp.Config = copyConfig(d.Config)
	if d.OrganizationID != nil {
		v := *d.OrganizationID
		cp.OrganizationID = &v
	}
	if d.LastSuccessAt != nil {
		v := *d.LastSuccessAt
		cp.LastSuccessAt = &v
	}
	if d.LastFailureAt != nil {
		v := *d.LastFailureAt
		cp.LastFailureAt = &v
	}
	return &cp
}

func cloneEntry(e *domain.AuditOutboxEntry) *domain.AuditOutboxEntry {
	cp := *e
	if e.LastAttemptAt != nil {
		v := *e.LastAttemptAt
		cp.LastAttemptAt = &v
	}
	if e.LastError != nil {
		v := *e.LastError
		cp.LastError = &v
	}
	if e.NextAttemptAt != nil {
		v := *e.NextAttemptAt
		cp.NextAttemptAt = &v
	}
	return &cp
}
