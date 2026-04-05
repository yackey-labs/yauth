//! Optional OpenTelemetry instrumentation for conformance tests.
//!
//! Uses `tracing` + `tracing-opentelemetry` to bridge spans to OTel, with an
//! HTTP/protobuf exporter sending to the local OTel collector.
//!
//! When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are emitted for each
//! test x backend combination. When unset, all helpers are no-ops.
//!
//! Usage:
//!   OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-local.yackey.cloud \
//!   OTEL_SERVICE_NAME=yauth-conformance-tests \
//!   cargo test --features full --test repo_conformance -- --test-threads=4

use std::sync::{Mutex, Once};

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;

static INIT: Once = Once::new();
static PROVIDER: Mutex<Option<SdkTracerProvider>> = Mutex::new(None);

/// Initialize the tracing + OTel pipeline once. No-op if `OTEL_EXPORTER_OTLP_ENDPOINT` is unset.
pub fn ensure_init() {
    INIT.call_once(|| {
        if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
            let provider = init_provider();
            init_tracing();
            *PROVIDER.lock().unwrap() = Some(provider);
        }
    });
}

fn init_provider() -> SdkTracerProvider {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "https://otel-local.yackey.cloud".into());
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "yauth-conformance-tests".into());

    // HTTP exporter with /v1/traces suffix (matching anchor's working pattern).
    // Uses reqwest-blocking-client — safe here because tracing-opentelemetry's
    // BatchSpanProcessor runs export on a background thread (not inside tokio).
    let trace_endpoint = format!("{}/v1/traces", endpoint.trim_end_matches('/'));

    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(&trace_endpoint)
        .build()
        .expect("Failed to create OTLP HTTP exporter");

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_attribute(KeyValue::new(SERVICE_NAME, service_name))
                .build(),
        )
        .build();

    global::set_text_map_propagator(TraceContextPropagator::new());
    global::set_tracer_provider(provider.clone());

    provider
}

fn init_tracing() {
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(OpenTelemetryLayer::new(global::tracer("yauth-conformance")))
        .init();
}

/// Flush pending spans and shut down the tracer provider.
/// Call at the end of the test suite (via `zzz_otel_shutdown` test).
pub fn flush() {
    if let Some(provider) = PROVIDER.lock().unwrap().take() {
        // force_flush is synchronous and blocks until the batch processor exports
        let _ = provider.force_flush();
        let _ = provider.shutdown();
    }
}

/// Returns `true` if OTel tracing is active for tests.
fn is_active() -> bool {
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok()
}

/// A tracing span guard that wraps a single test x backend iteration.
/// Uses `tracing::info_span!` which flows through tracing-opentelemetry to OTel.
pub struct TestSpan {
    _guard: Option<tracing::span::EnteredSpan>,
}

impl TestSpan {
    pub fn new(test_name: &str, backend_name: &str) -> Self {
        if !is_active() {
            return Self { _guard: None };
        }

        let span = tracing::info_span!(
            "conformance_test",
            test.name = test_name,
            backend.name = backend_name,
            otel.status_code = tracing::field::Empty,
        );

        Self {
            _guard: Some(span.entered()),
        }
    }

    #[allow(dead_code)]
    pub fn record_error(&self, msg: &str) {
        if self._guard.is_some() {
            tracing::error!(error.message = msg, "test assertion failed");
        }
    }
}

/// A tracing span for helper operations.
pub struct HelperSpan {
    _guard: Option<tracing::span::EnteredSpan>,
}

impl HelperSpan {
    pub fn new(operation: &str) -> Self {
        if !is_active() {
            return Self { _guard: None };
        }

        let span = tracing::info_span!("conformance_helper", operation = operation);
        Self {
            _guard: Some(span.entered()),
        }
    }
}
