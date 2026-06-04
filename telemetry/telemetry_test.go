package telemetry_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/telemetry"
)

func TestInitNoop_HelpersDoNotPanic(t *testing.T) {
	telemetry.InitNoop()

	ctx := context.Background()

	telemetry.RecordError(ctx, "evt", errors.New("boom"))
	telemetry.AddEvent(ctx, "evt")
	telemetry.SetAttribute(ctx, "k", "v")
	telemetry.SetAttribute(ctx, "n", int64(7))
	telemetry.SetAttribute(ctx, "b", true)
	telemetry.SetAttribute(ctx, "f", 1.5)

	if err := telemetry.WithSpan(ctx, "noop", trace.SpanKindInternal, func(ctx context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("WithSpan returned err: %v", err)
	}

	c, span := telemetry.StartSpan(ctx, "noop2", trace.SpanKindInternal)
	telemetry.SetAttributeOnCx(c, "k", "v")
	telemetry.AddEventOnCx(c, "evt")
	telemetry.RecordErrorOnCx(c, "evt", errors.New("x"))
	span.End()
}

// TestInit_BuildsProvider exercises the real Init path — in particular the
// resource.Merge of resource.Default() with our explicit semconv.SchemaURL,
// which errors at runtime if the two schema URLs conflict. The OTLP gRPC
// dialer is lazy, so no collector is required for the merge to be checked.
func TestInit_BuildsProvider(t *testing.T) {
	prev := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		otel.SetTextMapPropagator(prevProp)
	})

	shutdown, err := telemetry.Init(context.Background(), telemetry.Config{Enabled: true})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if shutdown == nil {
		t.Fatal("Init returned nil shutdown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// TestInit_HTTPProtocol_BuildsProvider exercises the OTLP/HTTP exporter path
// (Config.Protocol = "http"), the case a consumer hits when their collector
// only exposes the OTLP/HTTP receiver. Like the gRPC path the HTTP dialer is
// lazy, so the provider build and schema merge are checked without a
// reachable collector.
func TestInit_HTTPProtocol_BuildsProvider(t *testing.T) {
	prev := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		otel.SetTextMapPropagator(prevProp)
	})

	shutdown, err := telemetry.Init(context.Background(), telemetry.Config{
		Enabled:  true,
		Protocol: "http",
	})
	if err != nil {
		t.Fatalf("Init(http): %v", err)
	}
	if shutdown == nil {
		t.Fatal("Init returned nil shutdown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// installRecorder installs a recording exporter as the global tracer
// provider and registers the W3C propagator. Returns the recorder and a
// cleanup func.
func installRecorder(t *testing.T) (*tracetest.SpanRecorder, func()) {
	t.Helper()
	prev := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	telemetry.InitNoop() // ensure clean slate before swapping in real provider
	otel.SetTracerProvider(tp)

	return rec, func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
		otel.SetTextMapPropagator(prevProp)
	}
}

func TestTraceMiddleware_Records200(t *testing.T) {
	rec, cleanup := installRecorder(t)
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(middleware.TraceMiddleware(mux))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	span := spans[0]
	if span.SpanKind() != trace.SpanKindServer {
		t.Errorf("kind = %v, want Server", span.SpanKind())
	}
	if got := span.Name(); got == "" {
		t.Errorf("empty span name")
	}
	gotStatus := false
	for _, kv := range span.Attributes() {
		if string(kv.Key) == "http.response.status_code" {
			gotStatus = true
			if kv.Value.AsInt64() != 200 {
				t.Errorf("status_code = %d, want 200", kv.Value.AsInt64())
			}
		}
	}
	if !gotStatus {
		t.Errorf("missing http.response.status_code attribute")
	}
}

func TestSetUserID_RecordsUserIDAttribute(t *testing.T) {
	rec, cleanup := installRecorder(t)
	defer cleanup()

	ctx, span := telemetry.StartSpan(context.Background(), "op", trace.SpanKindServer)
	telemetry.SetUserID(ctx, "user-123")
	telemetry.SetUserID(ctx, "") // empty id must be ignored
	span.End()

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	var got string
	var found int
	for _, kv := range spans[0].Attributes() {
		if string(kv.Key) == "user.id" {
			found++
			got = kv.Value.AsString()
		}
	}
	if found != 1 {
		t.Fatalf("expected exactly 1 user.id attribute, got %d", found)
	}
	if got != "user-123" {
		t.Errorf("user.id = %q, want %q", got, "user-123")
	}
}

func TestTraceMiddleware_SkipsHealth(t *testing.T) {
	rec, cleanup := installRecorder(t)
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(middleware.TraceMiddleware(mux))
	defer srv.Close()

	for _, p := range []string{"/health", "/api/health"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
	}

	if got := len(rec.Ended()); got != 0 {
		t.Fatalf("expected 0 spans for health checks, got %d", got)
	}
}
