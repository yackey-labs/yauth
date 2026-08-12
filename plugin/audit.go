package plugin

import "context"

// AuditRecorder is notified immediately after the host has committed an
// audit-log row for an emitted [github.com/yackey-labs/yauth/events.AuthEvent].
// auditLogID is the primary key of the row that was just written;
// organizationID is the org the event was scoped to, or nil for a
// deployment-wide event.
//
// A recorder MUST NOT block: it runs inline on the authentication path,
// after the audit row is durable but before the emitting handler resumes.
// It also MUST NOT return a decision — recorders observe, they never veto.
// Anything that needs to veto belongs in RegisterEventGate.
type AuditRecorder func(ctx context.Context, auditLogID string, organizationID *string)

// AuditRecorderRegistrar is an OPTIONAL host capability. It is deliberately
// NOT part of [PluginHost]: a plugin discovers it with a type assertion
//
//	if reg, ok := host.(plugin.AuditRecorderRegistrar); ok { ... }
//
// so that adding it breaks no existing PluginHost implementation.
//
// It exists because the audit row is written by the host itself — inside
// Emit, so that every credential plugin is covered by construction — while
// the machinery that fans that row out (audit-export's outbox) lives in a
// plugin. The events.Handler pipeline cannot carry that hand-off: a gate's
// Block decision short-circuits the handler stage, which would mean a
// blocked login — precisely the event an auditor most wants exported —
// never reached the exporter. Recorders are invoked whatever the decision.
type AuditRecorderRegistrar interface {
	// RegisterAuditRecorder appends r to the host's recorder list. Called
	// from a plugin's Routes, where the host handle is available.
	RegisterAuditRecorder(r AuditRecorder)
}
