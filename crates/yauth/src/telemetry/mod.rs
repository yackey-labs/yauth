pub mod layer;

use diesel::connection::{InstrumentationEvent, set_default_instrumentation};
use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue, global};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_semantic_conventions::attribute::{DB_OPERATION_NAME, DB_SYSTEM_NAME};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

/// Extract the SQL operation (SELECT, INSERT, etc.) from a query's Display output.
fn extract_db_operation(query: &str) -> &str {
    let trimmed = query.trim_start();
    if let Some(pos) = trimmed.find(|c: char| c.is_whitespace()) {
        let op = &trimmed[..pos];
        match op {
            s if s.eq_ignore_ascii_case("SELECT") => "SELECT",
            s if s.eq_ignore_ascii_case("INSERT") => "INSERT",
            s if s.eq_ignore_ascii_case("UPDATE") => "UPDATE",
            s if s.eq_ignore_ascii_case("DELETE") => "DELETE",
            _ => op,
        }
    } else {
        trimmed
    }
}

/// Diesel instrumentation that creates native OTel spans for database queries.
struct QueryTracing {
    span_cx: Option<Context>,
}

impl diesel::connection::Instrumentation for QueryTracing {
    fn on_connection_event(&mut self, event: InstrumentationEvent<'_>) {
        match event {
            InstrumentationEvent::StartQuery { query, .. } => {
                let query_str = format!("{query}");
                let operation = extract_db_operation(&query_str);

                let tracer = global::tracer("yauth");
                let span = tracer
                    .span_builder(format!("{operation} db"))
                    .with_kind(SpanKind::Client)
                    .with_attributes(vec![
                        KeyValue::new(DB_SYSTEM_NAME, "postgresql"),
                        KeyValue::new(DB_OPERATION_NAME, operation.to_string()),
                    ])
                    .start(&tracer);

                let cx = Context::current().with_span(span);
                self.span_cx = Some(cx);
            }
            InstrumentationEvent::FinishQuery { error, .. } => {
                if let Some(ref cx) = self.span_cx {
                    if let Some(err) = error {
                        let span = cx.span();
                        span.add_event(
                            "query_error".to_string(),
                            vec![KeyValue::new("error.message", err.to_string())],
                        );
                        span.set_status(Status::error(err.to_string()));
                    }
                    cx.span().end();
                }
                self.span_cx.take();
            }
            _ => {}
        }
    }
}

/// Initialize the OpenTelemetry SDK for yauth telemetry.
///
/// This function:
/// - Creates an OTLP gRPC span exporter
/// - Builds a tracer provider with the service name from `OTEL_SERVICE_NAME` (default: "yauth")
/// - Registers the `TraceContextPropagator` globally for W3C traceparent/tracestate extraction
/// - Registers the tracer provider globally
/// - Sets up Diesel query instrumentation with native OTel spans
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

    // Register diesel query instrumentation so every connection traces queries.
    {
        let _ = set_default_instrumentation(|| Some(Box::new(QueryTracing { span_cx: None })));
    }

    provider
}
