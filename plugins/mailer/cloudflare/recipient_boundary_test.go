// recipient_boundary_test.go — the two things the Cloudflare mailer does with
// a recipient address that it should not.
//
//  1. It never validates it. doSend takes `to` straight from the plugin
//     (magiclink /send and emailpassword /forgot-password both accept anything
//     containing "@" — validEmail is a strings.Contains check) and marshals it
//     into the API payload. An address carrying a bare CRLF —
//     "victim@a.com\r\nBcc: attacker@evil.example" — is handed to Cloudflare's
//     send endpoint to interpret, and yauth has formed no opinion about
//     whether it is an address at all. The SMTP backend is saved by accident:
//     net/smtp.SendMail runs validateLine over every recipient BEFORE it dials,
//     so the same input never reaches a socket. There is no equivalent here,
//     and the boundary is the mailer's own to hold.
//
//  2. It puts the address in its error strings. cloudflare.go:293 and :308
//     format `to` into the returned error, send() passes that error to
//     telemetry.RecordErrorOnCx, and RecordErrorOnCx (telemetry/otel.go:118-128)
//     writes it into span.AddEvent("error.message") AND span.SetStatus
//     description. Spans are exported off-host. That is two lines below a
//     comment in the same file stating that the recipient is PII and is
//     deliberately not recorded as a span attribute — which is true of the
//     attributes, and false of the status. telemetry_test.go only ever
//     inspected Attributes(), which is how it stayed true-looking.
//
// The refusals are paired with a positive control: an ordinary address must
// still be POSTed and still produce a clean span.
package cloudflare

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestSend_RejectsRecipientWithCRLF proves nothing goes on the wire.
func TestSend_RejectsRecipientWithCRLF(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		okResponse(w, "victim@a.example")
	}))
	defer srv.Close()

	const injected = "victim@a.example\r\nBcc: attacker@evil.example"
	err := newTestMailer(srv).SendPasswordReset(testCtx(), injected, "https://x/reset")
	if err == nil {
		t.Errorf("a recipient containing a bare CRLF was accepted without complaint")
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the malformed recipient was POSTed to the send endpoint (%d request(s)) — "+
			"yauth handed a header-injection payload to the mail backend to interpret", n)
	}
}

// TestSend_BounceDoesNotPutTheRecipientOnTheSpan is the PII leak. The bounce
// path is the one that fires in production, on exactly the addresses an
// operator has no business exporting.
func TestSend_BounceDoesNotPutTheRecipientOnTheSpan(t *testing.T) {
	rec := installRecorder(t)
	const recipient = "someone.private@example.com"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"errors":  []any{},
			"result": map[string]any{
				"delivered":         []string{},
				"permanent_bounces": []string{recipient},
				"queued":            []string{},
			},
		})
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendPasswordReset(testCtx(), recipient, "https://x/reset"); err == nil {
		t.Fatal("a permanent bounce must still be an error")
	}

	span := spanByName(rec.Ended(), "mailer.cloudflare.send")
	if span == nil {
		t.Fatal("no mailer.cloudflare.send span was recorded")
	}
	if d := span.Status().Description; strings.Contains(d, recipient) {
		t.Errorf("span status description carries the recipient address: %q — "+
			"spans are exported off-host and this is the PII the attribute policy in this file already refuses", d)
	}
	for _, ev := range span.Events() {
		for _, kv := range ev.Attributes {
			if strings.Contains(kv.Value.String(), recipient) {
				t.Errorf("span event %q attribute %q carries the recipient address: %q",
					ev.Name, kv.Key, kv.Value.String())
			}
		}
	}
	// The disposition must still be recorded — the operator needs to know a
	// mail bounced, just not to whom.
	if v, ok := attrString(span, "mailer.disposition"); !ok || v != "bounced" {
		t.Errorf("mailer.disposition = %q (set=%v), want bounced", v, ok)
	}
}

// POSITIVE CONTROL. Validation must not turn into "refuses real addresses":
// an ordinary recipient still has to be POSTed and still has to succeed.
func TestSend_OrdinaryRecipientStillGoesOnTheWire(t *testing.T) {
	var requests atomic.Int32
	var gotTo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if v, ok := body["to"].(string); ok {
			gotTo = v
		}
		okResponse(w, "user+tag@sub.example.com")
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendPasswordReset(testCtx(), "user+tag@sub.example.com", "https://x/reset"); err != nil {
		t.Fatalf("ordinary recipient: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("expected exactly one POST, got %d", requests.Load())
	}
	if gotTo != "user+tag@sub.example.com" {
		t.Fatalf("recipient was rewritten on the way out: %q", gotTo)
	}
}
