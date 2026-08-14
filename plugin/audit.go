package plugin

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
)

// AuditRecorder is notified immediately after an audit-log row has been
// committed. auditLogID is the primary key of the row that was just
// written; organizationID is the org the row was scoped to, or nil for a
// deployment-wide row.
//
// It fires for BOTH kinds of audit row:
//
//   - rows the host writes inside Emit for an
//     [github.com/yackey-labs/yauth/events.AuthEvent] (login, logout,
//     password change, account lifecycle), and
//   - rows a handler authors itself and writes through [WriteAudit] — an
//     admin ban, an impersonation, an API-key mint, a SCIM deprovision, an
//     OAuth2 client mutation, the session-binding mismatch row middleware
//     writes, and the DCR stale-client sweep.
//
// A recorder MUST NOT block. On the authentication path it runs inline,
// after the audit row is durable but before the emitting handler resumes;
// on the WriteAudit path the same holds, and one of those callers (the DCR
// sweep) is a background goroutine with no request context. It also MUST
// NOT return a decision — recorders observe, they never veto. Anything
// that needs to veto belongs in RegisterEventGate.
//
// It is a type alias of [middleware.AuditRecorder]: the underlying type has
// to be declared in middleware because package plugin imports middleware,
// so middleware cannot import plugin — the same arrangement AuthResolver
// uses. The two names denote one type.
type AuditRecorder = middleware.AuditRecorder

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

// AuditFanout is the OPTIONAL host capability that delivers one committed
// audit row to every registered [AuditRecorder]. Like
// AuditRecorderRegistrar it is discovered by type assertion rather than
// being part of [PluginHost], so a third-party host that predates it still
// compiles — it simply gets the old behaviour (the row is written, nothing
// downstream hears about it).
type AuditFanout interface {
	FanoutAudit(ctx context.Context, auditLogID string, organizationID *string)
}

// WriteAudit is the choke point for every audit row a PLUGIN authors.
//
// Handlers used to call host.Repo().LogAuditEvent directly. That wrote the
// row and stopped there: audit-export's outbox is fed exclusively by the
// AuditRecorder hook, which only the host's Emit path ever invoked. The
// result was a silent, total split in the product's compliance story — a
// SOC streaming yauth to a SIEM received every login and not one ban,
// impersonation, SCIM deprovision, client-secret rotation or API-key mint.
// The rows were in the database the whole time, which is exactly what made
// it hard to notice.
//
// It fills row.ID and row.CreatedAt when the caller left them zero, writes
// the row, and on success hands it to the host's fan-out.
//
// It deliberately does NOT scrub row.Metadata. Metadata reaching this
// function is assembled in Go by the handler, not unmarshalled from a
// request the way an events.AuthEvent's is, and the host's scrubber is
// tuned for that untrusted case: its key-fragment list matches "key" and
// "credential", so routing plugin metadata through it would redact
// `credential_id` — the very field that says WHICH API key was minted.
// Callers are responsible for never putting a secret in metadata, which is
// the same rule they already followed when they called LogAuditEvent.
//
// It returns the row id, or "" if the write failed, and NEVER returns an
// error: an audit-log failure must not turn a successful admin action into
// a 500 (the same contract as the host's own recordAuthAudit).
func WriteAudit(ctx context.Context, host PluginHost, row domain.NewAuditLog) string {
	if host == nil {
		return ""
	}
	r := host.Repo()
	if r == nil {
		return ""
	}
	if row.ID == "" {
		row.ID = uuid.NewString()
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	if err := r.LogAuditEvent(ctx, row); err != nil {
		if lg := host.Logger(); lg != nil {
			lg.WarnContext(ctx, "yauth: audit-log write failed",
				"event_type", row.EventType, "err", err)
		}
		return ""
	}
	if f, ok := host.(AuditFanout); ok {
		f.FanoutAudit(ctx, row.ID, auditRowOrgID(row.Metadata))
	}
	return row.ID
}

// auditRowOrgID recovers the org scope of a handler-authored row so the
// outbox can route it to per-org destinations as well as deployment-wide
// ones. domain.NewAuditLog has no organization column, so the scope lives
// where the row already carries it: in the metadata blob. Both spellings in
// use are accepted — the host's own event rows use "organization_id", SCIM
// has always written "org_id".
//
// A row with neither key is deployment-wide (nil), which is what every one
// of these rows effectively was before: unroutable, because it never
// reached the outbox at all.
func auditRowOrgID(metadata []byte) *string {
	if len(metadata) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(metadata, &m); err != nil {
		return nil
	}
	for _, key := range []string{"organization_id", "org_id"} {
		if v, ok := m[key].(string); ok && v != "" {
			out := v
			return &out
		}
	}
	return nil
}
