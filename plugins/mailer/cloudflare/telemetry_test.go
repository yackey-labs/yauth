// Tracing tests for the Cloudflare mailer.
//
// Two properties matter here and neither is visible from the send-result
// tests in cloudflare_test.go:
//
//   - The DEFAULT client (HTTPClient nil) must be otelhttp-wrapped. That is
//     the path NewFromConfig's yaml wiring takes — it never sets HTTPClient
//     — so without it every auth email from a config-driven deployment is
//     invisible in traces.
//   - A permanent bounce must mark the span as an error. Cloudflare answers
//     HTTP 200 on that path, so transport-level instrumentation alone
//     records a perfectly healthy call for a mail that went nowhere.

package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// installRecorder swaps the global tracer provider for an in-memory recorder
// and registers the W3C TraceContext propagator (so otelhttp injects
// traceparent on the outbound send). Prior globals are restored on cleanup.
func installRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return rec
}

func spanByName(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// attrString returns the string value of key on span, and whether it was set.
func attrString(span sdktrace.ReadOnlySpan, key string) (string, bool) {
	for _, kv := range span.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

// The mailer used by the yaml path leaves HTTPClient nil. That default must
// carry otelhttp, which we prove by the traceparent header arriving at the
// server — an unwrapped http.Client injects nothing.
func TestSend_DefaultClientIsInstrumented(t *testing.T) {
	installRecorder(t)

	var gotTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		okResponse(w, "user@example.com")
	}))
	defer srv.Close()

	// Note: no HTTPClient — exactly what buildCloudflareMailer constructs.
	m := New(Mailer{
		AccountID: "acct123",
		APIToken:  "tok-secret",
		From:      "noreply@example.com",
		BaseURL:   srv.URL,
	})
	if err := m.SendVerification(context.Background(), "user@example.com", "https://x/verify"); err != nil {
		t.Fatalf("SendVerification: %v", err)
	}
	if gotTraceparent == "" {
		t.Error("default client injected no traceparent — otelhttp is not wired into it, so config-driven sends are untraced")
	}
}

// A caller-supplied client must be used verbatim, never swapped or mutated.
func TestSend_CallerSuppliedClientIsNotReplaced(t *testing.T) {
	custom := &http.Client{}
	m := New(Mailer{HTTPClient: custom})
	if got := m.httpClient(); got != custom {
		t.Error("httpClient() replaced a caller-supplied client")
	}
}

func TestSend_EmitsSpanWithKindAndDisposition(t *testing.T) {
	rec := installRecorder(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		okResponse(w, "user@example.com")
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendMagicLink(context.Background(), "user@example.com", "https://x/login"); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}

	span := spanByName(rec.Ended(), "mailer.cloudflare.send")
	if span == nil {
		t.Fatal("no mailer.cloudflare.send span was recorded")
	}
	if v, _ := attrString(span, "mailer.provider"); v != "cloudflare" {
		t.Errorf("mailer.provider = %q", v)
	}
	if v, _ := attrString(span, "mailer.message.kind"); v != "magic_link" {
		t.Errorf("mailer.message.kind = %q, want magic_link", v)
	}
	if v, _ := attrString(span, "mailer.disposition"); v != "delivered" {
		t.Errorf("mailer.disposition = %q, want delivered", v)
	}
	if span.Status().Code == codes.Error {
		t.Errorf("a successful send should not be an error span: %v", span.Status())
	}
}

// The bounce path is the reason this span exists: Cloudflare says HTTP 200,
// so otelhttp records a healthy call while the mail went nowhere.
func TestSend_BounceMarksSpanAsError(t *testing.T) {
	rec := installRecorder(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"errors":  []any{},
			"result": map[string]any{
				"delivered":         []string{},
				"permanent_bounces": []string{"user@example.com"},
				"queued":            []string{},
			},
		})
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendVerification(context.Background(), "user@example.com", "https://x/verify"); err == nil {
		t.Fatal("expected a bounce error")
	}

	span := spanByName(rec.Ended(), "mailer.cloudflare.send")
	if span == nil {
		t.Fatal("no mailer.cloudflare.send span was recorded")
	}
	if span.Status().Code != codes.Error {
		t.Errorf("a bounced send must be an error span, got %v — HTTP was 200, so nothing else marks this a failure", span.Status())
	}
	if v, _ := attrString(span, "mailer.disposition"); v != "bounced" {
		t.Errorf("mailer.disposition = %q, want bounced", v)
	}
}

// Recipient addresses are PII and spans are exported off-host. No attribute
// on any emitted span may contain one.
func TestSend_SpanAttributesNeverCarryRecipient(t *testing.T) {
	rec := installRecorder(t)

	const recipient = "very.identifiable.person@example.com"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		okResponse(w, recipient)
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendPasswordReset(context.Background(), recipient, "https://x/reset"); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}

	for _, span := range rec.Ended() {
		for _, kv := range span.Attributes() {
			if strings.Contains(kv.Value.String(), recipient) {
				t.Errorf("span %q leaked the recipient address in attribute %q", span.Name(), kv.Key)
			}
		}
	}
}
