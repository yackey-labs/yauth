package yauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
	"github.com/yackey-labs/yauth-go/telemetry"
)

// serverSpanCount drives one request through a YAuth built with the supplied
// builder mutator and returns how many SpanKindServer spans the global
// recorder captured. A recording provider is installed for the duration so
// yauth's TraceMiddleware (when present) exports against it.
func serverSpanCount(t *testing.T, configure func(*yauth.YAuthBuilder) *yauth.YAuthBuilder) int {
	t.Helper()

	prev := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})

	db, err := gormrepo.OpenSQLite("file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	b := yauth.New(gormrepo.New(db), yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{HIBPCheck: false, HIBPCheckSet: true})).
		WithTelemetry(telemetry.DefaultConfig())
	ya, err := configure(b).Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/does-not-exist")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	server := 0
	for _, s := range rec.Ended() {
		if s.SpanKind() == trace.SpanKindServer {
			server++
		}
	}
	return server
}

func TestRouter_TraceMiddlewareDefaultsOn(t *testing.T) {
	if got := serverSpanCount(t, func(b *yauth.YAuthBuilder) *yauth.YAuthBuilder { return b }); got != 1 {
		t.Fatalf("expected 1 yauth server span by default, got %d", got)
	}
}

func TestRouter_TraceMiddlewareOptOut(t *testing.T) {
	got := serverSpanCount(t, func(b *yauth.YAuthBuilder) *yauth.YAuthBuilder {
		return b.WithTraceMiddleware(false)
	})
	if got != 0 {
		t.Fatalf("expected 0 yauth server spans with WithTraceMiddleware(false), got %d", got)
	}
}
