use axum::{extract::MatchedPath, extract::Request, middleware::Next, response::Response};
use opentelemetry::global;
use opentelemetry::propagation::Extractor;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Adapter to extract W3C traceparent/tracestate from HTTP request headers.
struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

pub async fn trace_middleware(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();

    // Skip health checks entirely — no span created
    if path.starts_with("/api/health") || path.starts_with("/health") {
        return next.run(req).await;
    }

    let method = req.method().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| path.clone());

    // Extract W3C trace context from incoming request headers for distributed tracing.
    let parent_cx = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    });

    let span = tracing::info_span!(
        "HTTP request",
        otel.name = %format!("{} {}", method, route),
        otel.kind = "Server",
        http.request.method = %method,
        http.route = %route,
        url.path = %path,
        http.response.status_code = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        // Auth context (populated by auth middleware/handlers)
        user.id = tracing::field::Empty,
        user.email = tracing::field::Empty,
        user.role = tracing::field::Empty,
        enduser.id = tracing::field::Empty,
        // Auth operation context
        yauth.auth_method = tracing::field::Empty,
        yauth.session_found = tracing::field::Empty,
        yauth.rate_limited = tracing::field::Empty,
        yauth.hibp.breach_count = tracing::field::Empty,
        yauth.mfa_required = tracing::field::Empty,
    );

    // Link the tracing span to the incoming OTel context so frontend and backend
    // traces share the same trace ID.
    let _ = span.set_parent(parent_cx);

    let response = {
        use tracing::Instrument;
        next.run(req).instrument(span.clone()).await
    };

    let status = response.status().as_u16();
    span.record("http.response.status_code", status);
    if status >= 500 {
        span.record("otel.status_code", "ERROR");
    }

    response
}
