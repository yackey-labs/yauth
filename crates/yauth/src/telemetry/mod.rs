pub mod layer;

#[cfg(feature = "diesel-async")]
use diesel::connection::{InstrumentationEvent, set_default_instrumentation};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Extract the SQL operation (SELECT, INSERT, etc.) from a query's Display output.
#[cfg(feature = "diesel-async")]
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

/// Diesel instrumentation that creates tracing spans for database queries.
#[cfg(feature = "diesel-async")]
struct QueryTracing {
    span: Option<tracing::Span>,
}

#[cfg(feature = "diesel-async")]
impl diesel::connection::Instrumentation for QueryTracing {
    fn on_connection_event(&mut self, event: InstrumentationEvent<'_>) {
        match event {
            InstrumentationEvent::StartQuery { query, .. } => {
                let query_str = format!("{query}");
                let operation = extract_db_operation(&query_str);
                let span = tracing::info_span!(
                    "db.query",
                    db.system = "postgresql",
                    db.operation.name = operation,
                    otel.name = format!("{operation} db"),
                );
                self.span = Some(span);
            }
            InstrumentationEvent::FinishQuery { error, .. } => {
                if let Some(ref span) = self.span
                    && let Some(err) = error
                {
                    span.record("otel.status_code", "ERROR");
                    tracing::error!(parent: span, error = %err, "query failed");
                }
                self.span.take();
            }
            _ => {}
        }
    }
}

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

    global::set_tracer_provider(provider.clone());

    let tracer = provider.tracer("yauth");

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tower_http=debug")),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .with(OpenTelemetryLayer::new(tracer))
        .init();

    // Register diesel query instrumentation so every connection traces queries.
    #[cfg(feature = "diesel-async")]
    {
        let _ = set_default_instrumentation(|| Some(Box::new(QueryTracing { span: None })));
    }

    provider
}
