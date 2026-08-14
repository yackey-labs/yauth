// audit_events.go — the durable audit trail for the authentication event
// pipeline.
//
// Every credential plugin already funnels its lifecycle through
// [YAuth.Emit]: login.attempt / login.failed / login.succeeded, logout,
// password.changed, password.reset, email.verified, user.registered and the
// account-lifecycle events. Emit is therefore the ONE place an audit row
// has to be written for every plugin to be covered — including plugins that
// do not exist yet. Per-handler LogAuditEvent calls were the alternative and
// they are exactly how the trail came to be empty: eight credential plugins
// each had to remember, and none did.
//
// What is recorded, and what is not:
//
//   - login.attempt is emitted once per login before the credential is even
//     read, and is always followed by login.succeeded or login.failed. A row
//     per attempt would double the volume of the table to say nothing new,
//     so a plain attempt is dropped. An attempt that a gate BLOCKS is
//     recorded — that is a lockout or an IP block firing, it is the only
//     durable trace of it, and it is not followed by any other event.
//   - Everything else that reaches Emit is recorded, including event types
//     this package has never heard of. A denylist rather than an allowlist
//     is deliberate: a plugin added next year lands in the audit log without
//     anyone remembering to add it here.
//
// What must never be recorded: the credential itself. AuthEvent carries no
// password, token or TOTP field, and the free-form Metadata map is scrubbed
// (see scrubAuditMetadata) so a caller cannot smuggle one in.
package yauth

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugin"
)

const (
	// auditMaxStringLen bounds every attacker-influenced string before it
	// reaches the audit row. 320 is the RFC 3696 maximum email length, and
	// nothing else we record is legitimately longer.
	auditMaxStringLen = 320
	// auditMaxMetadataBytes caps the serialized metadata blob. On overflow
	// the caller-supplied keys are dropped and only yauth's own reserved
	// keys survive, so an oversized event degrades instead of failing.
	auditMaxMetadataBytes = 4096
	// auditRedacted replaces the value of any metadata key that looks like
	// it carries a credential.
	auditRedacted = "[redacted]"
)

// Reserved metadata keys. yauth writes these last so a caller-supplied
// metadata map can never shadow them.
const (
	auditMetaEmail        = "email"
	auditMetaMethod       = "method"
	auditMetaReason       = "reason"
	auditMetaSessionID    = "session_id"
	auditMetaDecision     = "decision"
	auditMetaBlockStatus  = "block_status"
	auditMetaHandlerError = "handler_error"
	auditMetaOrgID        = "organization_id"
)

// Decision values written to auditMetaDecision. A Continue decision writes
// no key at all — the absence is the common case and the cheapest encoding.
const (
	auditDecisionBlock      = "block"
	auditDecisionRequireMFA = "require_mfa"
)

// sensitiveMetaKeyFragments are substrings that mark a metadata key as
// carrying (or plausibly carrying) a credential. Matching is on the
// lowercased key and is deliberately over-broad: redacting "country_code"
// costs an auditor nothing, leaking a recovery code costs them the account.
var sensitiveMetaKeyFragments = []string{
	"assertion",
	"authorization",
	"code",
	"cookie",
	"credential",
	"hash",
	"key",
	"otp",
	"passphrase",
	"password",
	"passwd",
	"private",
	"pin",
	"recovery",
	"secret",
	"signature",
	"token",
}

// auditableEvent reports whether ev should produce an audit row given the
// decision the pipeline reached. See the package comment for the reasoning.
func auditableEvent(ev events.AuthEvent, dec events.Decision) bool {
	if ev.Type != events.EventLoginAttempt {
		return true
	}
	return dec.Kind == events.DecisionKindBlock
}

// recordAuthAudit writes the audit row for an emitted event and notifies
// every registered plugin.AuditRecorder. It never returns an error: an
// audit-log failure must not turn a successful login into a 500. Failures
// are logged at WARN, which is the signal an operator alerts on.
func (y *YAuth) recordAuthAudit(ctx context.Context, ev events.AuthEvent, dec events.Decision, handlerErr error) {
	if y == nil || y.repo == nil || !auditableEvent(ev, dec) {
		return
	}

	created := ev.Timestamp
	if created.IsZero() {
		created = time.Now().UTC()
	}

	orgID := auditOrganizationID(ev)
	row := domain.NewAuditLog{
		ID:        uuid.NewString(),
		UserID:    auditString(ev.UserID),
		EventType: string(ev.Type),
		IPAddress: auditIP(ev.IPAddress),
		Metadata:  auditMetadata(ev, dec, handlerErr),
		CreatedAt: created.UTC(),
	}

	if err := y.repo.LogAuditEvent(ctx, row); err != nil {
		if y.logger != nil {
			y.logger.WarnContext(ctx, "yauth: audit-log write failed",
				"event_type", row.EventType, "err", err)
		}
		return
	}

	y.FanoutAudit(ctx, row.ID, orgID)
}

// FanoutAudit implements [plugin.AuditFanout]: it hands one committed audit
// row to every registered recorder. It used to be an inline loop reachable
// only from recordAuthAudit, which is precisely why the rows plugins wrote
// themselves — bans, impersonations, SCIM deprovisions, API-key mints —
// never reached audit export's outbox. plugin.WriteAudit and the
// middleware's binding-mismatch path now arrive here too.
//
// Recorders are read at call time, so a plugin registering one during
// Routes() is picked up even though the host wired the fan-out earlier in
// Build.
func (y *YAuth) FanoutAudit(ctx context.Context, auditLogID string, organizationID *string) {
	if y == nil || auditLogID == "" {
		return
	}
	for _, rec := range y.auditRecorders {
		if rec == nil {
			continue
		}
		rec(ctx, auditLogID, organizationID)
	}
}

// RegisterAuditRecorder implements [plugin.AuditRecorderRegistrar]. It is
// invoked by plugins that fan audit rows onward (audit-export's outbox)
// from their Routes method.
func (y *YAuth) RegisterAuditRecorder(r plugin.AuditRecorder) {
	if r == nil {
		return
	}
	y.auditRecorders = append(y.auditRecorders, r)
}

// auditMetadata assembles the JSON metadata blob. Caller-supplied metadata
// goes in first and scrubbed; yauth's own reserved keys are written last so
// they cannot be shadowed.
func auditMetadata(ev events.AuthEvent, dec events.Decision, handlerErr error) []byte {
	reserved := map[string]any{}
	if v := auditString(ev.Email); v != nil {
		reserved[auditMetaEmail] = *v
	}
	if v := auditString(ev.Method); v != nil {
		reserved[auditMetaMethod] = *v
	}
	if v := auditString(ev.Reason); v != nil {
		reserved[auditMetaReason] = *v
	}
	if v := auditString(ev.SessionID); v != nil {
		reserved[auditMetaSessionID] = *v
	}
	switch dec.Kind {
	case events.DecisionKindBlock:
		reserved[auditMetaDecision] = auditDecisionBlock
		if dec.BlockStatus != 0 {
			reserved[auditMetaBlockStatus] = dec.BlockStatus
		}
	case events.DecisionKindRequireMfa:
		reserved[auditMetaDecision] = auditDecisionRequireMFA
	case events.DecisionKindContinue:
		// The common case writes no decision key.
	}
	if handlerErr != nil {
		reserved[auditMetaHandlerError] = truncateAudit(sanitizeAuditString(handlerErr.Error()))
	}

	merged := scrubAuditMetadata(ev.Metadata)
	for k, v := range reserved {
		merged[k] = v
	}
	if len(merged) == 0 {
		return nil
	}

	raw, err := json.Marshal(merged)
	if err != nil || len(raw) > auditMaxMetadataBytes {
		// Degrade to yauth's own keys rather than losing the row.
		raw, err = json.Marshal(reserved)
		if err != nil {
			return nil
		}
	}
	return raw
}

// scrubAuditMetadata copies m, redacting values whose key looks like a
// credential and sanitizing every string it keeps. Nested structures are
// serialized through json first so that a struct hiding a secret two levels
// down is still caught by the key match.
func scrubAuditMetadata(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+auditReservedKeyCount)
	for k, v := range m {
		key := truncateAudit(sanitizeAuditString(k))
		if isSensitiveAuditKey(k) {
			out[key] = auditRedacted
			continue
		}
		out[key] = scrubAuditValue(v)
	}
	return out
}

// auditReservedKeyCount only pre-sizes the scrub map; the reserved keys
// themselves are written by auditMetadata.
const auditReservedKeyCount = 7

func scrubAuditValue(v any) any {
	switch t := v.(type) {
	case string:
		return truncateAudit(sanitizeAuditString(t))
	case map[string]any:
		return scrubAuditMetadata(t)
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, scrubAuditValue(item))
		}
		return out
	case nil, bool, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, float32, float64:
		return v
	default:
		// Anything else (a struct, a pointer, a custom type) is
		// re-marshalled and re-scrubbed so a secret in a nested field is
		// still matched by key. Values that will not marshal are dropped.
		// The round trip can only yield nil/bool/float64/string/map/slice,
		// every one of which is handled above, so this recurses once.
		raw, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			return nil
		}
		return scrubAuditValue(generic)
	}
}

func isSensitiveAuditKey(k string) bool {
	lower := strings.ToLower(k)
	for _, frag := range sensitiveMetaKeyFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// auditOrganizationID pulls the org scope out of the event metadata so the
// audit-export outbox can route the row to per-org destinations.
func auditOrganizationID(ev events.AuthEvent) *string {
	v, ok := ev.Metadata[auditMetaOrgID].(string)
	if !ok {
		return nil
	}
	v = truncateAudit(sanitizeAuditString(v))
	if v == "" {
		return nil
	}
	return &v
}

// auditString normalizes an optional event string for storage: nil stays
// nil, control characters are stripped, and the result is length-capped.
//
// Every one of these fields is attacker-influenced — Email is whatever was
// typed into a login form, Method and Reason are plugin-supplied but travel
// through the same path — and the audit row is re-serialized downstream by
// the audit-export syslog formatter, where an embedded newline would let a
// login form forge a syslog record. Stripping controls at the point of
// storage fixes that for every consumer at once.
func auditString(s *string) *string {
	if s == nil {
		return nil
	}
	v := truncateAudit(sanitizeAuditString(*s))
	if v == "" {
		return nil
	}
	return &v
}

// sanitizeAuditString removes ASCII control characters (including CR, LF
// and NUL) and trims surrounding whitespace.
func sanitizeAuditString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func truncateAudit(s string) string {
	if len(s) <= auditMaxStringLen {
		return s
	}
	// Cut back to a rune boundary so the stored value stays valid UTF-8.
	cut := s[:auditMaxStringLen]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// auditIP validates the event's IP before it reaches the audit row. The
// value ultimately derives from a request header on deployments that trust
// a proxy, so it is attacker-controlled: an unparseable value is DROPPED
// rather than stored, which keeps the ip_address column queryable and stops
// a forged string riding into a downstream log.
func auditIP(ip *string) *string {
	if ip == nil {
		return nil
	}
	v := strings.TrimSpace(sanitizeAuditString(*ip))
	if v == "" {
		return nil
	}
	if net.ParseIP(v) != nil {
		return &v
	}
	if host, _, err := net.SplitHostPort(v); err == nil {
		if net.ParseIP(host) != nil {
			return &host
		}
	}
	return nil
}
