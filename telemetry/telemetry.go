// Package telemetry provides OpenTelemetry tracing initialization and helpers
// for yauth.
//
// The helpers in otel.go always record against the global TracerProvider
// (go.opentelemetry.io/otel), per OpenTelemetry's guidance that a library
// must use the global provider and never configure the SDK itself. So if your
// application already sets up OpenTelemetry, you do NOT need anything here:
// yauth's spans, the user.id tag, and DB spans attach to your existing
// pipeline automatically. Init is an optional convenience for standalone
// deployments that want yauth to own telemetry setup.
//
// Two init paths are exposed (both intended to be called once, by the
// application — not by library code, which must not clobber the global):
//
//   - Init: build a real OTLP tracer provider over gRPC or HTTP (selectable
//     via Config.Protocol / OTEL_EXPORTER_OTLP_PROTOCOL), register a composite
//     W3C TraceContext + Baggage propagator, set it as the global provider, and
//     return a shutdown func that flushes spans. Call this only when yauth owns
//     telemetry setup; if your app already configured OpenTelemetry, skip
//     Init so you don't replace its provider with a second export stream.
//   - InitNoop: install a no-op tracer provider so callers (and tests) can
//     invoke the helpers in this package without configuring an exporter.
//
// All helpers in otel.go degrade to no-ops automatically when the global
// tracer provider is the no-op provider, so call sites need no telemetry
// guards.
package telemetry

import (
	"context"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	noopt "go.opentelemetry.io/otel/trace/noop"
)

// TracerName is the global tracer name used by the otel.go helpers and the
// HTTP trace middleware.
const TracerName = "yauth"

// Config controls how Init wires the OpenTelemetry SDK. The zero value is
// usable: Enabled=false disables telemetry by installing a no-op provider.
type Config struct {
	// Enabled toggles real OTLP export vs the no-op provider. Set false to
	// disable telemetry without changing call sites.
	Enabled bool

	// Endpoint overrides OTEL_EXPORTER_OTLP_TRACES_ENDPOINT /
	// OTEL_EXPORTER_OTLP_ENDPOINT. If empty, those env vars are read; if all
	// are empty, the protocol's conventional local endpoint is used
	// (http://localhost:4317 for grpc, http://localhost:4318 for http).
	Endpoint string

	// Protocol selects the OTLP transport: "grpc" (default) or "http" (the
	// OTLP/HTTP receiver, conventionally on port 4318; "http/protobuf" is
	// accepted as an alias). If empty, OTEL_EXPORTER_OTLP_PROTOCOL is read;
	// if that is also empty, "grpc" is used. Set this to "http" when your
	// collector only exposes the OTLP/HTTP receiver.
	Protocol string

	// ServiceName overrides OTEL_SERVICE_NAME. If empty, the env variable
	// is read; if that is also empty, "yauth" is used.
	ServiceName string
}

// DefaultConfig returns a Config with Enabled=true and all other fields
// resolved from the environment at Init time.
func DefaultConfig() Config { return Config{Enabled: true} }

// Init initializes the global OpenTelemetry tracer provider and propagator
// according to cfg. When cfg.Enabled is false it delegates to InitNoop.
//
// The returned shutdown function should be deferred at app exit to flush
// in-flight spans. It is safe to call shutdown multiple times.
func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if !cfg.Enabled {
		InitNoop()
		return func(context.Context) error { return nil }, nil
	}

	protocol := resolveProtocol(cfg.Protocol)

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = defaultEndpoint(protocol)
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = os.Getenv("OTEL_SERVICE_NAME")
	}
	if serviceName == "" {
		serviceName = "yauth"
	}

	exporter, err := newExporter(ctx, protocol, endpoint)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	// Register a composite propagator so both W3C TraceContext (trace
	// correlation) and W3C Baggage (e.g. carrying user.id to descendant spans
	// and downstream services) propagate out of the box. Baggage is additive:
	// it only travels when a caller explicitly puts members in it.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

// resolveProtocol normalizes the configured/env OTLP protocol to "http" or
// "grpc". Empty falls back to OTEL_EXPORTER_OTLP_PROTOCOL, then "grpc". The
// OTel-standard "http/protobuf" (and "http/json") are treated as "http".
func resolveProtocol(p string) string {
	if p == "" {
		p = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "http", "http/protobuf", "http/json":
		return "http"
	default:
		return "grpc"
	}
}

// defaultEndpoint returns the conventional local OTLP endpoint for the
// protocol: 4317 for grpc, 4318 for http.
func defaultEndpoint(protocol string) string {
	if protocol == "http" {
		return "http://localhost:4318"
	}
	return "http://localhost:4317"
}

// newExporter builds an OTLP span exporter for the resolved protocol. The
// gRPC and HTTP dialers are lazy, so this does not require a reachable
// collector at construction time.
func newExporter(ctx context.Context, protocol, endpoint string) (sdktrace.SpanExporter, error) {
	if protocol == "http" {
		return otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
	}
	return otlptracegrpc.New(ctx, otlptracegrpc.WithEndpointURL(endpoint))
}

// InitNoop installs a no-op tracer provider as the global. Callers can still
// invoke the helpers in this package; they will compile and run but produce
// no spans. No propagator is registered.
func InitNoop() {
	otel.SetTracerProvider(noopt.NewTracerProvider())
}
