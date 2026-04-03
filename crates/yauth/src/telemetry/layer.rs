use axum::{extract::MatchedPath, extract::Request, middleware::Next, response::Response};
use opentelemetry::context::FutureExt as OtelFutureExt;
use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{KeyValue, global};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_semantic_conventions::attribute::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, HTTP_ROUTE, URL_PATH,
};

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

    let tracer = global::tracer("yauth");
    let span = tracer
        .span_builder(format!("{method} {route}"))
        .with_kind(SpanKind::Server)
        .with_attributes(vec![
            KeyValue::new(HTTP_REQUEST_METHOD, method),
            KeyValue::new(HTTP_ROUTE, route),
            KeyValue::new(URL_PATH, path),
        ])
        .start_with_context(&tracer, &parent_cx);

    let cx = parent_cx.with_span(span);

    // Store context in request extensions for code that receives the request object.
    let mut req = req;
    req.extensions_mut().insert(cx.clone());

    // Propagate context across the .await using FutureExt::with_context() instead of
    // cx.attach() — ContextGuard is !Send and cannot be held across .await in Axum
    // middleware (which requires Send futures for the multi-threaded Tokio scheduler).
    let response = next.run(req).with_context(cx.clone()).await;

    let status = response.status().as_u16();
    let span_ref = cx.span();
    span_ref.set_attribute(KeyValue::new(HTTP_RESPONSE_STATUS_CODE, i64::from(status)));
    if status >= 500 {
        span_ref.set_status(Status::error(format!("HTTP {status}")));
    }
    span_ref.end();

    response
}
