package auditexport

import (
	"strings"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
)

func sampleAudit() *domain.AuditLog {
	uid := "00000000-0000-0000-0000-000000000000"
	ip := "203.0.113.5"
	return &domain.AuditLog{
		ID:        "00000000-0000-0000-0000-000000000001",
		UserID:    &uid,
		EventType: "user.login",
		IPAddress: &ip,
		Metadata:  []byte(`{"k":"v"}`),
		CreatedAt: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC),
	}
}

func TestRenderJSON_ContainsRequiredFields(t *testing.T) {
	r, err := Render(domain.AuditExportFormatJSON, sampleAudit(), 13)
	if err != nil {
		t.Fatalf("render json: %v", err)
	}
	s := string(r.Bytes)
	if !strings.Contains(s, `"event_type":"user.login"`) {
		t.Errorf("missing event_type: %s", s)
	}
	if !strings.Contains(s, `"ip_address":"203.0.113.5"`) {
		t.Errorf("missing ip_address: %s", s)
	}
	if r.ContentType != "application/json" {
		t.Errorf("got content-type %q", r.ContentType)
	}
}

func TestRenderRFC5424_StartsWithPRI(t *testing.T) {
	r, err := Render(domain.AuditExportFormatRFC5424, sampleAudit(), 13)
	if err != nil {
		t.Fatalf("render rfc5424: %v", err)
	}
	s := string(r.Bytes)
	// facility 13 * 8 + severity 6 = 110
	if !strings.HasPrefix(s, "<110>1 ") {
		t.Errorf("expected <110>1 prefix, got: %s", s)
	}
}

func TestRenderRFC5424_ContainsAppAndMSGID(t *testing.T) {
	r, _ := Render(domain.AuditExportFormatRFC5424, sampleAudit(), 13)
	s := string(r.Bytes)
	if !strings.Contains(s, " yauth yauth - user.login ") {
		t.Errorf("expected 'yauth yauth - user.login', got: %s", s)
	}
	if !strings.Contains(s, "[yauth@32473 ") {
		t.Errorf("expected SD prefix, got: %s", s)
	}
}

func TestRenderRFC5424_InvalidFacility(t *testing.T) {
	if _, err := Render(domain.AuditExportFormatRFC5424, sampleAudit(), 99); err == nil {
		t.Fatal("expected error for invalid facility")
	}
}

func TestCEFEscapePrefix(t *testing.T) {
	if got := CEFEscapePrefix("a|b"); got != `a\|b` {
		t.Errorf(`expected a\|b, got %q`, got)
	}
	if got := CEFEscapePrefix(`a\b`); got != `a\\b` {
		t.Errorf(`expected a\\b, got %q`, got)
	}
	if got := CEFEscapePrefix("a\nb"); got != "a b" {
		t.Errorf("expected 'a b', got %q", got)
	}
}

func TestCEFEscapeExtension(t *testing.T) {
	if got := CEFEscapeExtension("a=b"); got != `a\=b` {
		t.Errorf(`expected a\=b, got %q`, got)
	}
	if got := CEFEscapeExtension(`a\b`); got != `a\\b` {
		t.Errorf(`expected a\\b, got %q`, got)
	}
	if got := CEFEscapeExtension("line1\nline2"); got != `line1\nline2` {
		t.Errorf(`expected line1\nline2, got %q`, got)
	}
}

func TestSDEscape(t *testing.T) {
	if got := SDEscape(`a"b`); got != `a\"b` {
		t.Errorf(`expected a\"b, got %q`, got)
	}
	if got := SDEscape(`a\b`); got != `a\\b` {
		t.Errorf(`expected a\\b, got %q`, got)
	}
	if got := SDEscape(`a]b`); got != `a\]b` {
		t.Errorf(`expected a\]b, got %q`, got)
	}
}

func TestRenderCEF(t *testing.T) {
	r, err := Render(domain.AuditExportFormatCEF, sampleAudit(), 13)
	if err != nil {
		t.Fatalf("render cef: %v", err)
	}
	s := string(r.Bytes)
	if !strings.HasPrefix(s, "CEF:0|yauth|yauth|") {
		t.Errorf("expected CEF prefix, got: %s", s)
	}
	if !strings.Contains(s, "user.login") {
		t.Errorf("missing event type")
	}
	if !strings.Contains(s, "src=203.0.113.5") {
		t.Errorf("missing src=ip")
	}
}
