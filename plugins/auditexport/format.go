package auditexport

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
)

// RenderedEvent is a wire-ready event body. ContentType is consumed by
// the webhook dispatcher; syslog framing is handled upstream.
type RenderedEvent struct {
	Bytes       []byte
	ContentType string
}

// Render dispatches to the per-format renderer. For Syslog destinations
// callers pass the RFC 5424 facility (0..=23). For non-syslog the
// facility argument is ignored.
func Render(format domain.AuditExportFormat, audit *domain.AuditLog, facility uint8) (*RenderedEvent, error) {
	switch format {
	case "", domain.AuditExportFormatJSON:
		return renderJSON(audit)
	case domain.AuditExportFormatCEF:
		return renderCEF(audit)
	case domain.AuditExportFormatRFC5424:
		return renderRFC5424(audit, facility)
	default:
		return nil, fmt.Errorf("auditexport: unknown format %q", format)
	}
}

// --- JSON ---

type jsonEvent struct {
	ID        string          `json:"id"`
	Timestamp string          `json:"timestamp"`
	EventType string          `json:"event_type"`
	UserID    *string         `json:"user_id,omitempty"`
	IPAddress *string         `json:"ip_address,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

func renderJSON(audit *domain.AuditLog) (*RenderedEvent, error) {
	ev := jsonEvent{
		ID:        audit.ID,
		Timestamp: audit.CreatedAt.UTC().Format(time.RFC3339Nano),
		EventType: audit.EventType,
		UserID:    audit.UserID,
		IPAddress: audit.IPAddress,
	}
	if len(audit.Metadata) > 0 {
		ev.Metadata = json.RawMessage(audit.Metadata)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("auditexport: json marshal: %w", err)
	}
	return &RenderedEvent{Bytes: b, ContentType: "application/json"}, nil
}

// --- CEF ---

// CEFEscapePrefix escapes a CEF prefix field per the ArcSight CEF spec:
//   - `\\` -> `\\\\`
//   - `|`  -> `\\|`
//   - newlines normalised to space (NL inside prefix is undefined)
func CEFEscapePrefix(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '|':
			b.WriteString(`\|`)
		case '\n', '\r':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CEFEscapeExtension escapes a CEF extension value per the ArcSight CEF spec:
//   - `\\` -> `\\\\`
//   - `=`  -> `\\=`
//   - newline -> literal `\n`
//   - CR    -> literal `\r`
func CEFEscapeExtension(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '=':
			b.WriteString(`\=`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// auditExportVersion is embedded in CEF headers; constant so tests are
// deterministic without depending on build metadata.
const auditExportVersion = "1.0"

func renderCEF(audit *domain.AuditLog) (*RenderedEvent, error) {
	name := CEFEscapePrefix(audit.EventType)
	header := fmt.Sprintf(
		"CEF:0|%s|%s|%s|%s|%s|%d",
		CEFEscapePrefix("yauth"),
		CEFEscapePrefix("yauth"),
		CEFEscapePrefix(auditExportVersion),
		name,
		name,
		3, // severity: informational
	)
	var ext strings.Builder
	fmt.Fprintf(&ext, "|rt=%d ", audit.CreatedAt.UnixMilli())
	if audit.UserID != nil {
		fmt.Fprintf(&ext, "suser=%s ", CEFEscapeExtension(*audit.UserID))
	}
	if audit.IPAddress != nil {
		fmt.Fprintf(&ext, "src=%s ", CEFEscapeExtension(*audit.IPAddress))
	}
	// Flatten one level of metadata if it's a JSON object.
	if len(audit.Metadata) > 0 {
		var obj map[string]any
		if err := json.Unmarshal(audit.Metadata, &obj); err == nil {
			for k, v := range obj {
				var sv string
				switch t := v.(type) {
				case string:
					sv = t
				default:
					if b, err := json.Marshal(v); err == nil {
						sv = string(b)
					}
				}
				fmt.Fprintf(&ext, "cs1Label=%s cs1=%s ",
					CEFEscapeExtension(k),
					CEFEscapeExtension(sv),
				)
			}
		}
	}
	body := header + strings.TrimRight(ext.String(), " ")
	return &RenderedEvent{
		Bytes:       []byte(body),
		ContentType: "text/plain; charset=utf-8",
	}, nil
}

// --- RFC 5424 syslog ---

const (
	syslogVersion      = "1"
	syslogSeverityInfo = 6
	syslogHostname     = "yauth"
	syslogAppName      = "yauth"
	// yauthPEN is IANA-reserved-for-documentation (RFC 5612 §3.4). Operators
	// register their own Private Enterprise Number for canonical SD parsing;
	// 32473 keeps the wire shape stable for examples and tests.
	yauthPEN = 32473
)

func renderRFC5424(audit *domain.AuditLog, facility uint8) (*RenderedEvent, error) {
	if facility > 23 {
		return nil, fmt.Errorf("auditexport: invalid syslog facility %d (must be 0..=23)", facility)
	}
	pri := int(facility)*8 + syslogSeverityInfo
	ts := audit.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z")
	msgid := sanitizeMSGID(audit.EventType)
	sd := structuredData(audit)
	msg := renderMSG(audit)
	line := fmt.Sprintf(
		"<%d>%s %s %s %s - %s %s %s",
		pri, syslogVersion, ts, syslogHostname, syslogAppName, msgid, sd, msg,
	)
	return &RenderedEvent{
		Bytes:       []byte(line),
		ContentType: "text/plain; charset=utf-8",
	}, nil
}

// sanitizeMSGID returns a 1..=32 char ASCII token suitable for the MSGID
// slot. Falls back to "audit" when the input contains no usable chars.
func sanitizeMSGID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			if b.Len() == 32 {
				break
			}
		}
	}
	if b.Len() == 0 {
		return "audit"
	}
	return b.String()
}

// SDEscape escapes an SD-PARAM-VALUE per RFC 5424 §6.3.3.
func SDEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case ']':
			b.WriteString(`\]`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func structuredData(audit *domain.AuditLog) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[yauth@%d ", yauthPEN)
	fmt.Fprintf(&b, `id="%s" event_type="%s"`,
		SDEscape(audit.ID),
		SDEscape(audit.EventType),
	)
	if audit.UserID != nil {
		fmt.Fprintf(&b, ` user_id="%s"`, SDEscape(*audit.UserID))
	}
	if audit.IPAddress != nil {
		fmt.Fprintf(&b, ` ip="%s"`, SDEscape(*audit.IPAddress))
	}
	b.WriteString(`]`)
	return b.String()
}

func renderMSG(audit *domain.AuditLog) string {
	payload := map[string]any{
		"event_type": audit.EventType,
		"user_id":    audit.UserID,
		"ip_address": audit.IPAddress,
	}
	if len(audit.Metadata) > 0 {
		var meta any
		if err := json.Unmarshal(audit.Metadata, &meta); err == nil {
			payload["metadata"] = meta
		}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ErrUnknownFormat is returned by Render when format is unrecognised.
var ErrUnknownFormat = errors.New("auditexport: unknown format")
