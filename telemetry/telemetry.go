// Package telemetry provides OpenTelemetry tracing initialization and helpers
// for yauth-go. It is the Go counterpart to the Rust telemetry feature in
// crates/yauth/src/telemetry.
//
// Two init paths are exposed:
//
//   - Init: build a real OTLP gRPC tracer provider, register the W3C
//     TraceContext propagator, and return a shutdown func that flushes spans.
//   - InitNoop: install a no-op tracer provider so callers (and tests) can
//     invoke the helpers in this package without configuring an exporter.
//
// All helpers in otel.go degrade to no-ops automatically when the global
// tracer provider is the no-op provider, mirroring the Rust side's
// `#[cfg(not(feature = "telemetry"))]` branch.
package telemetry

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	noopt "go.opentelemetry.io/otel/trace/noop"
)

// TracerName is the global tracer name used by the otel.go helpers and the
// HTTP trace middleware. Matches the Rust side ("yauth").
const TracerName = "yauth"

// Config controls how Init wires the OpenTelemetry SDK. The zero value is
// usable: Enabled=false disables telemetry by installing a no-op provider.
type Config struct {
	// Enabled toggles real OTLP export vs the no-op provider. Provided to
	// give Go callers the equivalent of the Rust feature flag.
	Enabled bool

	// Endpoint overrides OTEL_EXPORTER_OTLP_ENDPOINT. If empty, the env
	// variable is read; if that is also empty, http://localhost:4317 is
	// used.
	Endpoint string

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

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "http://localhost:4317"
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = os.Getenv("OTEL_SERVICE_NAME")
	}
	if serviceName == "" {
		serviceName = "yauth"
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpointURL(endpoint),
	)
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
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp.Shutdown, nil
}

// InitNoop installs a no-op tracer provider as the global. Callers can still
// invoke the helpers in this package; they will compile and run but produce
// no spans. No propagator is registered.
func InitNoop() {
	otel.SetTracerProvider(noopt.NewTracerProvider())
}
