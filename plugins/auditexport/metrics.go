package auditexport

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics wraps the three audit-export OTel instruments. When the OTel
// SDK is not configured the calls fan into no-ops (the default global
// meter provider returns no-op instruments). Tests can pass nil to
// SpawnWorker which yields a no-op Metrics instance.
type Metrics struct {
	mu sync.Mutex

	eventsTotal     metric.Int64Counter
	lagSeconds      metric.Float64Gauge
	deadLetterTotal metric.Int64Counter

	// In-process counters for assertion in tests / status panels. We track
	// these regardless of OTel state so the pentest harness doesn't have
	// to spin up a SDK.
	eventsByOutcome map[string]uint64 // "<dest>:<format>:<outcome>" -> count
	deadLetters     map[string]uint64 // destinationID -> count
	lagSamples      map[string]float64
}

// NewMetrics constructs a Metrics instance bound to the global OTel
// meter. Safe to call when no OTel provider is configured — calls become
// no-ops on the underlying instrument.
func NewMetrics() *Metrics {
	m := &Metrics{
		eventsByOutcome: make(map[string]uint64),
		deadLetters:     make(map[string]uint64),
		lagSamples:      make(map[string]float64),
	}
	meter := otel.Meter("yauth-audit-export")
	if c, err := meter.Int64Counter(
		"yauth_audit_export_events_total",
		metric.WithDescription("Audit-export events shipped (or attempted) per destination."),
	); err == nil {
		m.eventsTotal = c
	}
	if g, err := meter.Float64Gauge(
		"yauth_audit_export_lag_seconds",
		metric.WithDescription("Seconds since the oldest pending outbox entry per destination."),
	); err == nil {
		m.lagSeconds = g
	}
	if c, err := meter.Int64Counter(
		"yauth_audit_export_dead_letter_total",
		metric.WithDescription("Outbox entries transitioned to dead_letter."),
	); err == nil {
		m.deadLetterTotal = c
	}
	return m
}

// RecordOutcome bumps the events counter with destination/format/outcome
// attributes.
func (m *Metrics) RecordOutcome(destination, format, outcome string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.eventsByOutcome[destination+":"+format+":"+outcome]++
	m.mu.Unlock()
	if m.eventsTotal != nil {
		m.eventsTotal.Add(context.Background(), 1, metric.WithAttributes(
			attribute.String("destination", destination),
			attribute.String("format", format),
			attribute.String("outcome", outcome),
		))
	}
}

// RecordLag samples the lag-seconds gauge for the destination.
func (m *Metrics) RecordLag(destination string, seconds float64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.lagSamples[destination] = seconds
	m.mu.Unlock()
	if m.lagSeconds != nil {
		m.lagSeconds.Record(context.Background(), seconds, metric.WithAttributes(
			attribute.String("destination", destination),
		))
	}
}

// RecordDeadLetter bumps the dead-letter counter for the destination.
func (m *Metrics) RecordDeadLetter(destination string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.deadLetters[destination]++
	m.mu.Unlock()
	if m.deadLetterTotal != nil {
		m.deadLetterTotal.Add(context.Background(), 1, metric.WithAttributes(
			attribute.String("destination", destination),
		))
	}
}

// DeadLetterCount returns the in-process dead-letter total for the
// destination. Used by tests / admin status panels.
func (m *Metrics) DeadLetterCount(destination string) uint64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deadLetters[destination]
}

// EventsByOutcome returns a snapshot of the per-outcome counter map.
func (m *Metrics) EventsByOutcome() map[string]uint64 {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]uint64, len(m.eventsByOutcome))
	for k, v := range m.eventsByOutcome {
		cp[k] = v
	}
	return cp
}
