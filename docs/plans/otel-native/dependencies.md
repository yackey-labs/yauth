# Dependencies

## Existing (keeping)
- `opentelemetry` 0.31 — core OTel API (Tracer, Span, Context, KeyValue)
- `opentelemetry_sdk` 0.31 — SdkTracerProvider, batch exporter, Resource
- `opentelemetry-otlp` 0.31 — OTLP gRPC exporter via tonic
- `opentelemetry-semantic-conventions` 0.31 — HTTP, DB, and service semantic convention constants

## To Remove
- `tracing-opentelemetry` 0.32 — the bridge layer, removed in M1
- `tracing` 0.1 — replaced by native OTel span events (request context) and `log` crate (operational). Kept through M1/M2 for compilation, removed in M3 after all call sites migrated.
- `tracing-subscriber` 0.3 — removed in M3 alongside `tracing`

## To Add
- `opentelemetry-http` 0.31 — official `HeaderExtractor`/`HeaderInjector` for W3C trace context propagation. Replaces hand-rolled `HeaderExtractor`. [docs.rs/opentelemetry-http](https://docs.rs/opentelemetry-http)
- `log` 0.4 — lightweight logging facade for operational messages (startup, config) that don't belong on spans. Non-optional library dependency. [docs.rs/log](https://docs.rs/log)
- `env_logger` 0.11 — stdout log formatting with `RUST_LOG` env filter. **Dev-dependency only** (used in example server, not in the library itself). [docs.rs/env_logger](https://docs.rs/env_logger)

## Approach Decisions
- **Span events, not logs**: All `tracing::error!()` / `warn!()` / `info!()` calls within request-handling code become OTel span events via `span.add_event()`. This keeps error context attached to traces — visible in Honeycomb's trace waterfall and queryable via BubbleUp. Disconnected logs lose correlation with the request that produced them.
- **`log` for operational messages**: Startup messages, config warnings, and non-request-context logging use the `log` crate. These don't have a span to attach to and are genuinely operational output.
- **No tracing bridge at all**: Removing `tracing` entirely eliminates the bridge indirection and makes the OTel API the single source of truth for both spans and span events. One system, not two.
- **Error span events + status**: When recording an error as a span event, also call `span.set_status(Status::error(msg))`. Honeycomb uses span status to identify error spans in queries and BubbleUp.
