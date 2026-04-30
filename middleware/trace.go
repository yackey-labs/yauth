package middleware

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// traceTracerName matches the global tracer name used by the telemetry
// package so spans cluster under one instrumentation library.
const traceTracerName = "yauth"

// TraceMiddleware opens a server-kind OpenTelemetry span around each
// inbound HTTP request, mirroring the Rust `trace_middleware` axum layer.
//
// Behavior:
//   - Requests whose path starts with /health or /api/health are passed
//     through without instrumentation.
//   - The W3C TraceContext propagator extracts any inbound traceparent so
//     this span links to its upstream parent.
//   - The span is named "{METHOD} {ROUTE}" where ROUTE is r.Pattern when
//     the stdlib ServeMux matched a pattern (Go 1.22+) or r.URL.Path as a
//     fallback.
//   - Standard semantic-convention attributes are set: http.request.method,
//     http.route, url.path, and http.response.status_code on completion.
//   - Status is marked Error when the response code is >= 500.
func TraceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/health") || strings.HasPrefix(path, "/api/health") {
			next.ServeHTTP(w, r)
			return
		}

		method := r.Method
		route := r.Pattern
		if route == "" {
			route = path
		}

		propagator := otel.GetTextMapPropagator()
		parentCtx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		tracer := otel.Tracer(traceTracerName)
		ctx, span := tracer.Start(parentCtx, method+" "+route,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(method),
				semconv.HTTPRoute(route),
				semconv.URLPath(path),
			),
		)
		defer span.End()

		sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))

		span.SetAttributes(attribute.Int(string(semconv.HTTPResponseStatusCodeKey), sw.status))
		if sw.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(sw.status))
		}
	})
}

// statusRecorder wraps an http.ResponseWriter to capture the status code
// written by the downstream handler so it can be attached to the span.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
