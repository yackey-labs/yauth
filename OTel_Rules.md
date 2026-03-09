# OpenTelemetry Rules for YAuth

Rules for instrumenting applications that use the yauth authentication library. Following these ensures full correlation between traces, logs, and metrics in Grafana.

YAuth uses `tracing` + `tracing-opentelemetry` to bridge spans into OTel format. The library provides optional telemetry helpers via the `telemetry` Cargo feature.

## Wide Event Philosophy (Honeycomb-style)

YAuth follows the **wide event** approach to observability:

**Prefer adding attributes to the parent span over creating child spans.**

A single SERVER span for an HTTP request should contain all the context needed to understand what happened: who authenticated, how they authenticated, whether they were rate limited, and what the outcome was. This produces fewer, richer spans that are easier to query and correlate in Honeycomb, Grafana Tempo, or any trace backend.

### When to widen the parent span (add attributes)
- **Fast operations** where separate timing is not useful: session lookup, JWT verification, rate limit check, password verify result, user context after authentication
- **Auth context**: user ID, email, role, auth method — always recorded on the SERVER span
- **Boolean outcomes**: `yauth.session_found`, `yauth.rate_limited`, `yauth.mfa_required`

### When to create a child span
Only create child spans for operations where **separate timing matters**:
- **CPU-bound work** (100ms+): password hashing with Argon2id (`yauth.password_hash`, `yauth.password_verify`)
- **External network calls**: HIBP API check (`yauth.hibp_check` with `otel.kind = "Client"`)

### Auth events as span events (not separate spans)
Auth outcomes (login succeeded, login failed, user registered) should be recorded as **span events** on the SERVER span using `tracing::info!()` within the span context, not as separate INTERNAL spans. The structured fields on the log event are automatically attached to the parent span's trace context.

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

Enable with `features = ["telemetry"]` in your `Cargo.toml`. This gates the OTel bridge and exporter dependencies. `tracing` itself is always available — spans and `.record()` calls are zero-cost no-ops when no subscriber is registered.

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

## SERVER Span: The Wide Event

The `trace_middleware` creates a single SERVER span per request with **pre-declared Empty fields** that auth code populates during request processing:

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
    // User context — OTel semconv user.* namespace (populated after auth)
    user.id = tracing::field::Empty,
    user.email = tracing::field::Empty,
    user.roles = tracing::field::Empty,
    // Auth operation context
    yauth.auth_method = tracing::field::Empty,
    yauth.session_found = tracing::field::Empty,
    yauth.rate_limited = tracing::field::Empty,
    yauth.hibp.breach_count = tracing::field::Empty,
    yauth.mfa_required = tracing::field::Empty,
);
```

Fields are recorded using `tracing::Span::current().record("field", value)` from anywhere within the request's span context. The field must be pre-declared as `tracing::field::Empty` on the span — recording a field that wasn't declared is silently ignored.

### Attributes on the SERVER span

| Attribute | When Populated | Example Value |
|---|---|---|
| `http.request.method` | Always | `POST` |
| `http.route` | Always | `/api/auth/email/login` |
| `url.path` | Always | `/api/auth/email/login` |
| `http.response.status_code` | After response | `200` |
| `user.id` | After auth | `550e8400-e29b-41d4-a716-446655440000` |
| `user.email` | After auth | `user@example.com` |
| `user.roles` | After auth | `admin` |
| `yauth.auth_method` | After auth | `session`, `bearer`, `api_key` |
| `yauth.session_found` | After session lookup | `true` / `false` |
| `yauth.rate_limited` | When rate limited | `true` |
| `yauth.hibp.breach_count` | After HIBP check | `42` |
| `yauth.mfa_required` | When MFA needed | `true` |

### Error handling

- 5xx responses: set `otel.status_code = "ERROR"` on the span
- 4xx responses: do NOT set error status (client errors are not server errors)

## Child Spans (only for slow/external operations)

These are the **only** operations that warrant their own child span:

| Span Name | Kind | Why | Key Attributes |
|---|---|---|---|
| `yauth.password_hash` | INTERNAL | CPU-bound Argon2id hashing (100ms+) | duration |
| `yauth.password_verify` | INTERNAL | CPU-bound Argon2id verification (100ms+) | duration |
| `yauth.hibp_check` | CLIENT | External HTTP call to HIBP API | `http.request.method`, `yauth.hibp.breach_count` |

Everything else (session lookup, JWT verify, rate limit check, user lookup) is fast enough that separate timing is not useful — the result is recorded as an attribute on the SERVER span.

## Span Naming Reference

| Context | Span Kind | Name Format | Example |
|---|---|---|---|
| API route handler | `SERVER` | `{METHOD} {route}` | `POST /api/auth/email/login` |
| Password hash/verify | `INTERNAL` | `yauth.{operation}` | `yauth.password_hash` |
| HIBP API call | `CLIENT` | `yauth.hibp_check` | `yauth.hibp_check` |
| Database query | `CLIENT` | `{OPERATION} {table}` | `SELECT yauth_users` |

### Rules

- **Low cardinality**: Never put IDs, query params, or request bodies in span names. Use route templates with `:param` placeholders, not resolved paths.
- **Uppercase operations**: SQL operations (`SELECT`, `INSERT`) and HTTP methods (`GET`, `POST`) are always uppercase.
- **Route templates**: Use the framework's route pattern. `POST /api/auth/admin/users/:id` not `POST /api/auth/admin/users/abc-123`.

## Consuming App Instrumentation

Apps using yauth should add their own attributes to the SERVER span using the `app.*` prefix:

```rust
let span = tracing::Span::current();
span.record("app.guitar_id", &guitar_id.to_string());
span.record("app.action", "restring");
```

Pre-declare these fields on the SERVER span in your app's trace middleware (or add a second middleware layer that widens the span with app-specific Empty fields).

## Database Spans (SeaORM / Diesel)

YAuth prefixes all its tables with `yauth_`. Database spans follow `{OPERATION} {table}` naming:

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

## Signal Strategy: What Goes Where

### Traces — "Where and why is it wrong?"
A single wide SERVER span per request captures method, route, status, duration, auth context, and outcomes. Child spans only exist for password hashing and HIBP checks where separate timing matters.

### Logs — "What happened outside a request?"
Only log what the span doesn't cover. Use `tracing` macros (`info!`, `warn!`, `error!`) which automatically include trace context via `tracing-opentelemetry`. Auth events (login succeeded, login failed, etc.) are logged with structured fields inside the SERVER span context.

### Metrics — "Is something wrong?"
Tempo generates RED metrics automatically from traces. Only add custom metrics for things traces can't cover: rate limit hit rates, auth method distribution, failed login trends.

### Decision table

| Event | Signal | Why |
|---|---|---|
| Auth request handled | **Span attribute** on SERVER span | Span has method, route, status, duration, auth context |
| User authenticated | **Span attribute** (`user.id`, `user.email`, `yauth.auth_method`) | Widened onto SERVER span by auth middleware |
| Session lookup result | **Span attribute** (`yauth.session_found`) | Fast DB lookup, no child span needed |
| Rate limit hit | **Span attribute** (`yauth.rate_limited`) | In-memory check, no child span needed |
| Password hashed/verified | **Child span** (`yauth.password_hash` / `yauth.password_verify`) | CPU-bound 100ms+, timing matters for Argon2id tuning |
| HIBP API called | **Child span** (`yauth.hibp_check`, CLIENT kind) | External network call, timing matters |
| Login succeeded/failed | **Log event** (`tracing::info!`) inside SERVER span | Structured fields auto-attached to trace context |
| User registered | **Log event** (`tracing::info!`) inside SERVER span | Structured fields auto-attached to trace context |
| App started / shutdown | **Log** | No request context |
| Background cleanup | **Log** | No parent span |

## Trace Structure Example

### Login request (wide event style)

```
[SERVER] POST /api/auth/email/login
    user.id = "abc-123"
    user.email = "user@example.com"
    user.roles = "user"
    yauth.auth_method = "session"
    yauth.session_found = true
    yauth.rate_limited = false
    http.response.status_code = 200
    +-- [INTERNAL] yauth.password_verify (112ms)
```

Compare with the old approach that created 5+ child spans — the wide event captures the same information in a single queryable span.

### Registration with HIBP check

```
[SERVER] POST /api/auth/email/register
    yauth.hibp.breach_count = 0
    http.response.status_code = 201
    +-- [INTERNAL] yauth.password_hash (145ms)
    +-- [CLIENT] yauth.hibp_check (89ms)
            http.request.method = "GET"
            yauth.hibp.breach_count = 0
```

### Authenticated API request

```
[SERVER] GET /api/guitars
    user.id = "abc-123"
    user.email = "user@example.com"
    user.roles = "user"
    yauth.auth_method = "session"
    yauth.session_found = true
    http.response.status_code = 200
```

No child spans at all — session validation is fast and the result is an attribute.

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
- `tracing::Span::current()` always returns the active span — auth code can record attributes without passing span references around

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

## Checklist

### Instrumentation
- [ ] `telemetry` feature enabled in Cargo.toml
- [ ] `telemetry::init()` called before Axum server starts
- [ ] `OTEL_SERVICE_NAME` set in deployment manifest
- [ ] `trace_middleware` applied as Axum layer — creates wide SERVER span with auth Empty fields
- [ ] SERVER spans named `{METHOD} {route}` with route templates
- [ ] Auth middleware records `user.id`, `user.email`, `user.roles`, `yauth.auth_method` on SERVER span
- [ ] Session validation records `yauth.session_found` on SERVER span
- [ ] Rate limiter records `yauth.rate_limited` on SERVER span when blocked
- [ ] Password hash/verify have their own child spans (CPU-bound)
- [ ] HIBP check has its own CLIENT child span (network-bound)
- [ ] Error spans set `otel.status_code = "ERROR"` for 5xx only

### Noise reduction
- [ ] Health check routes skip span creation
- [ ] No child spans for fast operations (session lookup, JWT verify, rate limit check)
- [ ] Auth events are log events inside the SERVER span, not separate INTERNAL spans

### Signal hygiene
- [ ] Not logging what the span already records
- [ ] `tracing` macros used instead of `println`/`log` for structured output
- [ ] No custom RED metrics — Tempo generates from traces
- [ ] `debug` level disabled in production via `RUST_LOG`

### Context propagation
- [ ] CORS allows `traceparent` and `tracestate` headers
- [ ] `x-api-key` allowed in CORS if API key auth is enabled
- [ ] `SdkTracerProvider::shutdown()` called on graceful exit to flush pending spans
