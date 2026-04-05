pub mod layer;

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

/// Initialize the OpenTelemetry SDK for yauth telemetry.
///
/// This function:
/// - Creates an OTLP gRPC span exporter
/// - Builds a tracer provider with the service name from `OTEL_SERVICE_NAME` (default: "yauth")
/// - Registers the `TraceContextPropagator` globally for W3C traceparent/tracestate extraction
/// - Registers the tracer provider globally
///
/// **Diesel query instrumentation** is now handled by `DieselPgBackend` construction —
/// it is backend-specific and only active when using the Diesel backend.
///
/// **Does NOT** set up any log subscriber — that is the consumer's responsibility.
///
/// Returns the `SdkTracerProvider` for lifecycle management (e.g., shutdown on app exit).
pub fn init() -> SdkTracerProvider {
    let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".into());
    let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "yauth".into());

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&otel_endpoint)
        .build()
        .expect("Failed to create OTLP exporter");

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_attribute(KeyValue::new(SERVICE_NAME, service_name))
                .build(),
        )
        .build();

    // CRITICAL: Register the W3C TraceContext propagator globally.
    // Without this, all traceparent headers from upstream services are silently ignored.
    global::set_text_map_propagator(TraceContextPropagator::new());

    global::set_tracer_provider(provider.clone());

    provider
}
