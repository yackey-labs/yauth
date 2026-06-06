# Telemetry — OpenTelemetry tracing

yauth emits OpenTelemetry spans for its HTTP routes, its internal operations,
and (when it owns the database pool) every SQL query. It always records against
the **global** `TracerProvider`, per OpenTelemetry's guidance that a library
must never configure the SDK itself. That single rule drives the two modes
below.

## Enabling

```yaml
telemetry:
  enabled: true            # off by default
  service_name: my-app     # OTEL_SERVICE_NAME if empty; "yauth" as last resort
  manage_provider: true    # default — see below
  otlp_endpoint: http://localhost:4317
  otlp_protocol: grpc      # or "http" (OTLP/HTTP receiver, usually :4318)
  http_middleware: true    # default — yauth's own HTTP server-span middleware
```

Inspect every field with `yauth schema config` (the `telemetry` block carries
inline descriptions).

## Mode 1 — yauth manages the provider (default)

With `manage_provider: true` (the default), `NewFromConfig` calls
`telemetry.Init`, which:

- builds a real OTLP exporter (gRPC or HTTP, per `otlp_protocol`) pointed at
  `otlp_endpoint`,
- registers it as the **global** `TracerProvider`, and
- registers a composite **W3C TraceContext + W3C Baggage** propagator.

The Baggage propagator means baggage members (e.g. `user.id`) ride out of the
box to descendant spans and downstream services — baggage is additive, so it
only travels when you explicitly put something in it (see `SetUserBaggage`
below). Use this mode for standalone deployments where yauth is the thing
standing up telemetry.

## Mode 2 — your app owns the provider (`manage_provider: false`)

Set `manage_provider: false` when your application already configures
OpenTelemetry. yauth then records into the provider and propagator **your app
already registered** and does not stand up a second export stream or touch the
propagator. `otlp_endpoint` / `otlp_protocol` are ignored in this mode.

You almost always also want `http_middleware: false` here: if your app wraps
its whole mux in `otelhttp` (or equivalent), yauth's own HTTP server-span
middleware would emit a *second* server span per request. Disabling it leaves
exactly one server span — your app's — and yauth's spans nest under it.

```go
// 1. App configures OpenTelemetry however it likes (its own exporter,
//    TracerProvider, and propagator — including baggage if it wants it).
shutdown := myapp.InitOTel(ctx)
defer shutdown(ctx)

// 2. yauth attaches to that pipeline — no second provider, no extra server span.
cfg, _ := yauthcfg.Load("yauth.yaml")
cfg.Telemetry = yauthcfg.TelemetryConfig{
    Enabled:        true,
    ManageProvider: ptr(false), // record into the app's provider
    HTTPMiddleware: ptr(false), // app's otelhttp owns the server span
}
ya, err := yauth.NewFromConfig(ctx, cfg)
```

(`ptr` is any `func[T any](v T) *T` helper; the two fields are `*bool` so the
unset state is distinguishable from an explicit `false`.)

Equivalent YAML, if you prefer to keep it declarative:

```yaml
telemetry:
  enabled: true
  manage_provider: false
  http_middleware: false
```

## Enriching spans

- `telemetry.SetUserID(ctx, id)` records the authenticated user's id on the
  **current span** using the `user.id` semantic convention. It is a safe no-op
  when no recording span is present, so it works under yauth's own
  `TraceMiddleware` or under your app's `otelhttp` server span alike.
- `telemetry.SetUserBaggage(ctx, id) context.Context` puts `user.id` into W3C
  **baggage** and returns the new context. Unlike `SetUserID`, baggage rides
  across span and service boundaries (via the Baggage propagator), so
  descendant spans and downstream services can read it back with
  `baggage.FromContext(ctx)` and enrich their own telemetry. It returns ctx
  unchanged for an empty or invalid id.
- DB query spans come from the otelpgx tracer attached by
  `pgxrepo.WithOTelTracing()`. `NewFromConfig` applies this automatically when
  `telemetry.enabled` is true and yauth opens the pool; if you inject your own
  pool (`yauth.WithPool`), attach the tracer when you build that pool.

## See also

- `yauth schema config` — the reflected `telemetry` block (field descriptions)
- `yauth docs configuration` — full config precedence and loading rules
