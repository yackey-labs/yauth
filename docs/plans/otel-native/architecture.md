# Architecture

## What's Changing

The `telemetry` feature currently uses `tracing` for both structured logging and span creation, with `tracing-opentelemetry` bridging spans to the OTel SDK. This migration removes `tracing` entirely and uses the OpenTelemetry SDK directly for spans, span events, and context propagation.

**Before:** `tracing::info_span!()` → tracing subscriber → `OpenTelemetryLayer` → OTel SDK → OTLP exporter
**Before (logging):** `tracing::error!()` → tracing subscriber → stdout JSON (disconnected from traces)
**After:** `tracer.start("span_name")` → OTel SDK → OTLP exporter
**After (errors in request context):** `span.add_event("error_name", attributes)` → attached to span → visible in Honeycomb traces
**After (operational logging):** `log::info!()` → env_logger → stdout

## Data Model Changes
None — this is a telemetry pipeline change, no database changes.

## Patterns

### Span Events Replace In-Context Logging
Every `tracing::error!("DB error: {}", e)` inside a request handler becomes:
```rust
use opentelemetry::trace::Span;
span.add_event("db_error", vec![KeyValue::new("error.message", e.to_string())]);
span.set_status(Status::error(e.to_string()));
```
This attaches the error directly to the trace in Honeycomb, enabling BubbleUp to correlate errors with request dimensions (user, endpoint, version).

### OTel Context via Request Extensions
The HTTP trace middleware creates an OTel `Context` containing the server span and stores it in Axum request extensions. Downstream code retrieves it with `req.extensions().get::<opentelemetry::Context>()` or uses `opentelemetry::Context::current()`.

### Feature-Gated OTel Helpers
Create `crate::otel` module with:
- **When `telemetry` enabled**: re-exports OTel types, provides `set_attribute()`, `add_event()`, `record_error()` helpers that operate on the current active span
- **When `telemetry` disabled**: no-op stubs that compile away

This keeps the 200+ call sites clean — `crate::otel::record_error("db_error", &e)` works in both builds.

### Diesel Instrumentation
`QueryTracing` creates native OTel spans with `db.system`, `db.operation.name` attributes. On query error, records error as span event + sets error status.

### HTTP Middleware Span Lifecycle (traceparent propagation)
1. Extract parent context from W3C `traceparent`/`tracestate` headers via `global::get_text_map_propagator()` + `opentelemetry_http::HeaderExtractor`
2. Create server span as child of extracted context: `tracer.span_builder().with_kind(SpanKind::Server).start_with_context(&tracer, &parent_cx)`
3. Build new `Context` from parent + span: `let cx = parent_cx.with_span(span)`
4. **Attach context to current task**: `let _guard = cx.attach()` — this makes `Context::current()` return the correct context for all downstream code (handlers, services, DB calls)
5. **Store context in request extensions**: `req.extensions_mut().insert(cx.clone())` — for code that receives the request object
6. After response, retrieve span from context, set `http.response.status_code` + status, call `span.end()`

**Consumer propagation guarantee**: Because `init()` registers a `TraceContextPropagator` globally and the middleware uses `start_with_context()` with the extracted parent, any incoming `traceparent` header from an upstream service (frontend, gateway, other microservice) is correctly linked. The span ID created by yauth becomes the parent for any child spans the consumer creates in their own handlers.

### Consumer Integration Patterns
Two supported patterns for library consumers:

**Pattern A — yauth owns OTel init** (simple apps):
```rust
let _provider = yauth::telemetry::init(); // sets tracer provider + propagator + logger
let app = Router::new()
    .layer(axum::middleware::from_fn(yauth::telemetry::layer::trace_middleware))
    .nest("/auth", auth.router())
    .with_state(auth_state);
```

**Pattern B — consumer owns OTel init** (apps with existing OTel setup):
```rust
// Consumer sets up their own tracer provider, propagator, etc.
// yauth's trace_middleware uses global::tracer("yauth") — works with any provider
let app = Router::new()
    .layer(axum::middleware::from_fn(yauth::telemetry::layer::trace_middleware))
    .nest("/auth", auth.router())
    .with_state(auth_state);
```

In Pattern B, the consumer MUST have registered a `TraceContextPropagator` (or composite propagator including it) via `global::set_text_map_propagator()` for W3C header extraction to work.

### Operational Logging
Startup, config, and non-request-context messages use `log::info!()` / `log::warn!()` / `log::error!()`. The `log` crate is the library's logging facade. Consumers choose their own log backend (`env_logger`, `tracing`, `fern`, etc.). yauth's `telemetry::init()` does NOT set up a log subscriber — that's the consumer's responsibility.

## Files Modified

### Telemetry module (full rewrite)
- `crates/yauth/src/telemetry/mod.rs` — OTel SDK init, Diesel instrumentation, `env_logger` setup
- `crates/yauth/src/telemetry/layer.rs` — HTTP middleware using native OTel spans

### New internal helper
- `crates/yauth/src/otel.rs` — feature-gated helpers: `record_error(name, err)`, `set_attribute(key, val)`, `add_event(name, attrs)`, `with_span(name, f)`

### All plugin/auth files (tracing→OTel span events)
~20 files across `plugins/`, `auth/`, `stores/`, `middleware.rs`, `state.rs`:
- Replace `tracing::error!(...)` with `crate::otel::record_error(...)` (span event + status)
- Replace `tracing::warn!(...)` with `crate::otel::add_event(...)` (span event, no error status)
- Replace `tracing::info!(...)` / `debug!(...)` with `crate::otel::add_event(...)` or `log::info!()` depending on whether it's in request context
- Remove all `use tracing::*` imports
- Replace `tracing::info_span!` with OTel `Tracer` API
- Replace `tracing::Span::current().record()` with `crate::otel::set_attribute()`

### Dependency configuration
- `Cargo.toml` (workspace) — M1: remove `tracing-opentelemetry`, add `opentelemetry-http`, `log`. M3: remove `tracing`, `tracing-subscriber`.
- `crates/yauth/Cargo.toml` — update feature flag, deps. `env_logger` as dev-dependency only (for example server).

## Cross-Milestone Dependencies
- M1 → M2: The `crate::otel` helper module created in M1 is used by all call sites updated in M2.
- M2 → M3: M2 migrates span creation sites; M3 migrates all logging calls across plugin files.
