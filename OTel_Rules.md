# OpenTelemetry Rules for YAuth

Rules for instrumenting applications that use the yauth authentication library. Following these ensures full correlation between traces, logs, and metrics in Grafana.

YAuth uses `tracing` + `tracing-opentelemetry` to bridge spans into OTel format. The library provides optional telemetry helpers via the `telemetry` Cargo feature.

## Required Environment Variables

Set these in your deployment manifest:

```yaml
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: "http://alloy.observability.svc.cluster.local:4317"
- name: OTEL_SERVICE_NAME
  value: "<your-app-name>"
- name: OTEL_RESOURCE_ATTRIBUTES
  value: "deployment.environment=production,k8s.namespace.name=$(NAMESPACE),k8s.pod.name=$(POD_NAME)"
```

## Telemetry Feature

Enable with `features = ["telemetry"]` in your `Cargo.toml`. This gates the OTel bridge and exporter dependencies. `tracing` itself is always available (zero-cost when no subscriber is registered).

### Provided Helpers

```rust
use yauth::telemetry;

// Initialize OTel tracer provider + tracing subscriber.
// Returns SdkTracerProvider for graceful shutdown.
let provider = telemetry::init();

// Trace middleware for Axum (wraps requests in SERVER spans).
// Apply as a layer to your Axum router.
app.layer(axum::middleware::from_fn(telemetry::layer::trace_middleware));

// On shutdown — flush pending spans
provider.shutdown().expect("Failed to flush traces");
```

## Span Naming Reference

Every span name must follow these conventions. Dashboards query `span_name` labels against these exact patterns.

| Context | Span Kind | Name Format | Example |
|---|---|---|---|
| API route handler | `SERVER` | `{METHOD} {route}` | `POST /api/auth/email/login` |
| Outbound HTTP call | `CLIENT` | `HTTP {METHOD}` | `HTTP GET` |
| Database query | `CLIENT` | `{OPERATION} {table}` | `SELECT yauth_users` |
| Auth operation | `INTERNAL` | `yauth.{operation}` | `yauth.password_hash` |
| Auth event | `INTERNAL` | `yauth.event {type}` | `yauth.event login_succeeded` |

### Rules

- **Low cardinality**: Never put IDs, query params, or request bodies in span names. Use route templates with `:param` placeholders, not resolved paths.
- **Uppercase operations**: SQL operations (`SELECT`, `INSERT`) and HTTP methods (`GET`, `POST`) are always uppercase.
- **Route templates**: Use the framework's route pattern. `POST /api/auth/admin/users/:id` not `POST /api/auth/admin/users/abc-123`.

## API Spans (SERVER) — Provided by trace_middleware

The `trace_middleware` creates a SERVER span for each request (excluding health checks):

```rust
let span = tracing::info_span!(
    "HTTP request",
    otel.name = %format!("{} {}", method, route),
    otel.kind = "Server",
    http.request.method = %method,
    http.route = %route,
    url.path = %path,
    http.response.status_code = tracing::field::Empty,
    otel.status_code = tracing::field::Empty,
);
```

### Required attributes (SERVER spans)

| Attribute | Value | Example |
|---|---|---|
| `http.request.method` | HTTP verb | `POST` |
| `http.route` | Route template | `/api/auth/email/login` |
| `url.path` | Actual path | `/api/auth/email/login` |
| `http.response.status_code` | Status code int | `200` |

### Error handling

- 5xx responses: set `otel.status_code = "ERROR"` on the span
- 4xx responses: do NOT set error status (client errors are not server errors)

## YAuth Auth Operation Spans (INTERNAL)

These spans instrument yauth's internal auth operations. They are created automatically when the `telemetry` feature is enabled.

| Span Name | Description | Key Attributes |
|---|---|---|
| `yauth.password_hash` | Argon2id hashing | duration (for tuning cost params) |
| `yauth.session_validate` | Session lookup + expiry check | `yauth.session_found` |
| `yauth.hibp_check` | HIBP API call (CLIENT span) | `http.request.method`, `http.response.status_code` |
| `yauth.rate_limit_check` | Rate limiter check | `yauth.rate_limit.allowed`, `yauth.rate_limit.key` |
| `yauth.webauthn_verify` | WebAuthn credential verification | `yauth.user_id` |
| `yauth.totp_verify` | TOTP code verification | `yauth.user_id` |
| `yauth.jwt_verify` | JWT signature + expiry validation | `yauth.jwt_valid` |

## Auth Event Spans (INTERNAL)

Emitted by the plugin event system when auth events occur:

| Span Name | Attributes |
|---|---|
| `yauth.event login_succeeded` | `yauth.event.type`, `yauth.user_id`, `yauth.auth_method` |
| `yauth.event login_failed` | `yauth.event.type`, `yauth.email`, `yauth.reason` |
| `yauth.event user_registered` | `yauth.event.type`, `yauth.user_id`, `yauth.email` |
| `yauth.event session_created` | `yauth.event.type`, `yauth.user_id`, `yauth.session_id` |
| `yauth.event password_changed` | `yauth.event.type`, `yauth.user_id` |
| `yauth.event email_verified` | `yauth.event.type`, `yauth.user_id` |
| `yauth.event mfa_enabled` | `yauth.event.type`, `yauth.user_id`, `yauth.mfa_method` |
| `yauth.event user_banned` | `yauth.event.type`, `yauth.user_id` |

## Database Spans (SeaORM)

YAuth prefixes all its tables with `yauth_`. For proper span naming matching `{OPERATION} {table}`:

```
[CLIENT] SELECT yauth_users
[CLIENT] INSERT yauth_sessions
[CLIENT] DELETE yauth_password_resets
```

### Required attributes (CLIENT DB spans)

| Attribute | Value | Required |
|---|---|---|
| `db.system` | `"postgresql"` | Yes |
| `db.name` | Database name | Yes |
| `db.statement` | SQL query text | Yes |
| `server.address` | DB hostname | Yes |
| `server.port` | DB port number | Yes |

## Health Checks

Health check routes are excluded from tracing in the trace middleware. No span is created for:
- `/api/health*`
- `/health*`

```rust
// In trace_middleware — health checks skip span creation entirely
if path.starts_with("/api/health") || path.starts_with("/health") {
    return next.run(req).await;
}
```

## Signal Strategy: What Goes Where

### Traces — "Where and why is it wrong?"
Trace every user-facing request. The SERVER span records method, route, status, and duration. Auth operation spans nest inside the SERVER span to show exactly where time is spent (password hashing, HIBP check, DB queries).

### Logs — "What happened outside a request?"
Only log what traces don't cover. Use `tracing` macros (`info!`, `warn!`, `error!`) which automatically include trace context via `tracing-opentelemetry`.

### Metrics — "Is something wrong?"
Tempo generates RED metrics automatically from traces. Only add custom metrics for things traces can't cover: rate limit hit rates, auth method distribution, failed login trends.

### Decision table

| Event | Signal | Why |
|---|---|---|
| Auth request handled | **Trace** (SERVER span) | Span has method, route, status, duration |
| DB query executed | **Trace** (CLIENT span) | Span has statement, duration, error |
| User authenticated | **Span attribute** (`user.id`) | Attach to SERVER span in auth middleware |
| Password hashed | **Trace** (INTERNAL span) | Duration matters for Argon2id tuning |
| HIBP API called | **Trace** (CLIENT span) | External call duration and success |
| Login succeeded/failed | **Auth event span** | Structured auth audit trail |
| Rate limit hit | **Span attribute** | `yauth.rate_limited = true` on SERVER span |
| App started / shutdown | **Log** | No request context |
| Background cleanup | **Log** | No parent span |

## CORS for Context Propagation

The consuming app's CORS layer must allow `traceparent` and `tracestate` headers for distributed tracing:

```rust
use axum::http::header;
use axum::http::HeaderName;
use tower_http::cors::CorsLayer;

let cors = CorsLayer::new()
    .allow_headers([
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        HeaderName::from_static("traceparent"),
        HeaderName::from_static("tracestate"),
        HeaderName::from_static("x-api-key"),
    ]);
```

## Context Propagation

- Traefik (or your ingress) injects W3C `traceparent` headers on all ingress requests
- `tracing-opentelemetry` extracts `traceparent` automatically via `TraceContextPropagator`
- No manual context manager needed in Rust — `tracing` uses task-local storage natively

## Logs (Rust)

Use `tracing` macros with structured fields. `tracing-opentelemetry` automatically injects `trace_id` and `span_id`:

```rust
use tracing::{info, warn, error};

// Inside a request (trace context auto-attached)
info!(user_id = %user.id, event = "login_success", "User logged in");

// Outside a request (startup, background jobs)
info!(migration = "m20260101_core", "Migration applied");
```

Configure `tracing-subscriber` with JSON output for production:

```rust
tracing_subscriber::registry()
    .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
    .with(tracing_subscriber::fmt::layer().json())
    .with(OpenTelemetryLayer::new(tracer))
    .init();
```

## Trace Structure Examples

### Login request with MFA
```
[SERVER] POST /api/auth/email/login (my-app)
  +-- [INTERNAL] yauth.rate_limit_check
  +-- [CLIENT] SELECT yauth_users (postgresql)
  +-- [INTERNAL] yauth.password_hash (argon2id verify)
  +-- [INTERNAL] yauth.event login_succeeded
  +-- response: { mfa_required: true, pending_session_id: "..." }
```

### MFA verify then session creation
```
[SERVER] POST /api/auth/mfa/verify (my-app)
  +-- [INTERNAL] yauth.totp_verify
  +-- [CLIENT] INSERT yauth_sessions (postgresql)
  +-- [INTERNAL] yauth.event session_created
  +-- Set-Cookie: session=...
```

### Bearer token authentication
```
[SERVER] GET /api/me (my-app)
  +-- [INTERNAL] yauth.jwt_verify
  +-- [CLIENT] SELECT yauth_users (postgresql)
  +-- response: { user data }
```

### Registration with HIBP check
```
[SERVER] POST /api/auth/email/register (my-app)
  +-- [INTERNAL] yauth.rate_limit_check
  +-- [CLIENT] SELECT yauth_users (postgresql)  -- check existing
  +-- [CLIENT] HTTP GET (api.pwnedpasswords.com)  -- HIBP k-anonymity
  +-- [INTERNAL] yauth.password_hash (argon2id hash)
  +-- [CLIENT] INSERT yauth_users (postgresql)
  +-- [CLIENT] INSERT yauth_passwords (postgresql)
  +-- [INTERNAL] yauth.event user_registered
  +-- response: 201 Created
```

## Checklist

### Instrumentation
- [ ] `telemetry` feature enabled in Cargo.toml
- [ ] `telemetry::init()` called before Axum server starts
- [ ] `OTEL_SERVICE_NAME` set in deployment manifest
- [ ] `trace_middleware` applied as Axum layer
- [ ] SERVER spans named `{METHOD} {route}` with route templates
- [ ] Auth operation INTERNAL spans created for password hashing, session validation, etc.
- [ ] Auth event spans emitted on login, registration, logout, etc.
- [ ] DB spans follow `{OPERATION} {table}` naming with semantic attributes
- [ ] Error spans set `otel.status_code = "ERROR"` for 5xx only

### Noise reduction
- [ ] Health check routes skip span creation
- [ ] No spans for `/api/health*`, `/health*`

### Signal hygiene
- [ ] Not logging what the trace already records
- [ ] `tracing` macros used instead of `println`/`log` for structured output
- [ ] No custom RED metrics — Tempo generates from traces
- [ ] `debug` level disabled in production via `RUST_LOG`

### Context propagation
- [ ] CORS allows `traceparent` and `tracestate` headers
- [ ] `x-api-key` allowed in CORS if API key auth is enabled
- [ ] `SdkTracerProvider::shutdown()` called on graceful exit to flush pending spans
