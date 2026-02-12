pub mod layer;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

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

    provider
}
