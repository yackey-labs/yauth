# Milestone 1: Native OTel telemetry pipeline + helper module

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

### What must work:
1. `telemetry::init()` initializes the OTel SDK directly — OTLP exporter, tracer provider, and **explicitly registers `TraceContextPropagator`** via `global::set_text_map_propagator()` for W3C traceparent/tracestate extraction. Does NOT set up a log subscriber — that's the consumer's responsibility. (no `tracing-subscriber`, no `OpenTelemetryLayer`)
2. `trace_middleware` creates native OTel server spans with W3C context extraction via `opentelemetry_http::HeaderExtractor`, HTTP semantic convention attributes, and proper status recording
3. Diesel query instrumentation creates native OTel spans with `db.system`, `db.operation.name` attributes and records errors as span events
4. A feature-gated `crate::otel` helper module provides: `record_error(name, err)` (adds span event + sets error status), `add_event(name, attrs)` (adds span event), `set_attribute(key, val)` (sets attribute on current span), `with_span(name, kind, f)` (runs closure in new span). All compile to no-ops when `telemetry` is disabled.
5. `tracing-opentelemetry` removed from workspace deps, crate deps, and the `telemetry` feature flag. `tracing` and `tracing-subscriber` are kept temporarily — they are removed in M3 after all call sites are migrated.
6. `opentelemetry-http` added to workspace deps and `telemetry` feature
7. `log` added as a non-optional dependency (the library's long-term logging facade for operational messages)
8. Example server (`examples/server.rs`) updated to use `env_logger` + `log` instead of `tracing_subscriber` + `tracing` for its own startup logging. `env_logger` is a dev-dependency only.
9. `cargo test --features full` passes
10. `cargo clippy --features full -- -D warnings` passes

### After building, prove it works:
Start the app with `cargo run --example server --features full` with `OTEL_EXPORTER_OTLP_ENDPOINT` set.

- **OTel init**: App starts without panic. Operational logs appear on stdout. Confirm zero `tracing` imports exist anywhere in the crate (`grep -rn "use tracing" crates/yauth/src/telemetry/`).
- **HTTP spans**: `curl http://localhost:3000/api/health` returns 200 with no span. `curl http://localhost:3000/session` returns 401 with a server span containing `http.request.method=GET`, `http.route=/session`, `http.response.status_code=401`.
- **Distributed tracing (traceparent propagation)**: `curl -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" http://localhost:3000/session` — verify the created span has trace ID `4bf92f3577b34da6a3ce929d0e0e4736` and parent span ID `00f067aa0ba902b7`. This proves W3C context extraction works end-to-end.
- **Context flows to downstream code**: Inside a handler, `opentelemetry::Context::current().span().span_context().trace_id()` returns the propagated trace ID, not an empty/invalid ID. This proves `cx.attach()` in the middleware correctly propagates to async handler code.
- **Consumer Pattern B (external provider)**: Without calling `telemetry::init()`, manually register a tracer provider and propagator, then add `trace_middleware`. Verify spans still appear with correct parent context. This proves the middleware works with any global provider.
- **Compile without telemetry**: `cargo check` and `cargo check --features email-password` both compile — no OTel types leak into non-telemetry builds.
- **Full test suite**: `cargo test --features full` passes.

### Test strategy:
- `cargo test --features full` — existing unit tests pass
- `cargo clippy --features full -- -D warnings` — clean
- `cargo check` (default features) — telemetry gating correct
- `cargo check --features "email-password,passkey,mfa,bearer,api-key"` — non-telemetry builds compile

### Known pitfalls:
1. **Tracing removal is staged, not M1**: `tracing` uses structured field syntax (`error!(field = val, "msg")`) that `log` does not support. You cannot swap `tracing` → `log` as a drop-in. Keep `tracing` + `tracing-subscriber` as dependencies through M1 and M2 so the 200+ call sites in plugin files keep compiling. Only the telemetry module and example server are rewritten in M1. `tracing` is fully removed in M3 after every call site is migrated.
2. **Library must not init a log subscriber**: yauth is a library. `telemetry::init()` must NOT call `env_logger::init()` or `tracing_subscriber::init()` — that's the consumer's job. `init()` only sets up the OTel tracer provider and propagator. The example server sets up `env_logger` itself. `env_logger` goes in `[dev-dependencies]`, not `[dependencies]`.
3. **OTel Context is thread-local**: `Context::current()` uses thread-local storage. In async Axum handlers, use `let _guard = cx.attach()` to make a context current for the duration of the handler. The middleware should attach the context before calling `next.run(req)`.
4. **Span must be explicitly ended**: OTel spans from `tracer.start()` need `.end()` called. Use `tracer.in_span()` where possible for auto-end. In the HTTP middleware, call `span.end()` after recording response status.
5. **HeaderExtractor type**: `opentelemetry_http::HeaderExtractor` wraps `&http::HeaderMap`. Since axum re-exports `http`, this is compatible — verify the import compiles.
6. **Diesel Instrumentation trait**: Replace `Option<tracing::Span>` with the OTel span type. The `on_connection_event` method is `&mut self` so storing the span works.
7. **Semantic convention imports**: Use `opentelemetry_semantic_conventions::attribute::*` constants (e.g., `HTTP_REQUEST_METHOD`, `HTTP_RESPONSE_STATUS_CODE`, `HTTP_ROUTE`). Never use raw string literals for standard attribute names.
8. **CRITICAL — Propagator registration**: The current `init()` never calls `global::set_text_map_propagator()`. Without this, `get_text_map_propagator()` in the middleware returns a `NoopTextMapPropagator` and ALL traceparent headers are silently ignored. The new `init()` MUST call `global::set_text_map_propagator(TraceContextPropagator::new())` BEFORE the middleware processes any requests. For consumers using Pattern B (own OTel setup), document that they must register a propagator themselves.
9. **Context attachment in async middleware**: After creating the span and context, call `let _guard = cx.attach()` BEFORE `next.run(req).await`. The guard must live across the `.await` — so it must be bound (not dropped) before the await. This ensures `Context::current()` returns the correct context inside handlers. If the guard is dropped early, downstream `Context::current()` returns an empty context and all span attributes/events go to a noop span.
