//! Feature-gated OpenTelemetry helpers.
//!
//! When the `telemetry` feature is enabled, these functions operate on the
//! current active OTel span. When disabled, they compile to no-ops.

#[cfg(feature = "telemetry")]
mod inner {
    use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
    use opentelemetry::{Context, KeyValue, global};
    use std::fmt::Display;

    /// Record an error on the current span: adds an error event and sets error status.
    pub fn record_error(name: &str, err: &dyn Display) {
        let cx = Context::current();
        let span = cx.span();
        span.add_event(
            name.to_string(),
            vec![KeyValue::new("error.message", err.to_string())],
        );
        span.set_status(Status::error(err.to_string()));
    }

    /// Add a named event with attributes to the current span.
    pub fn add_event(name: &str, attrs: Vec<KeyValue>) {
        let cx = Context::current();
        let span = cx.span();
        span.add_event(name.to_string(), attrs);
    }

    /// Set a single attribute on the current span.
    pub fn set_attribute(key: &'static str, val: impl Into<opentelemetry::Value>) {
        let cx = Context::current();
        let span = cx.span();
        span.set_attribute(KeyValue::new(key, val.into()));
    }

    /// Run a closure inside a new span with the given name and kind.
    /// The span is automatically ended when the closure returns.
    pub fn with_span<F, T>(name: &str, kind: SpanKind, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let tracer = global::tracer("yauth");
        let span = tracer
            .span_builder(name.to_string())
            .with_kind(kind)
            .start(&tracer);
        let cx = Context::current().with_span(span);
        let _guard = cx.attach();
        f()
    }

    /// Create a new span and return a context containing it.
    ///
    /// The caller is responsible for attaching the context (e.g. via `cx.attach()`)
    /// and ending the span. This is useful for async code where `ContextGuard`
    /// cannot be held across `.await` boundaries (since it is `!Send`).
    ///
    /// Usage pattern for async:
    /// ```ignore
    /// let cx = crate::otel::start_span("name", SpanKind::Client);
    /// // ... do async work using crate::otel::set_attribute_on_cx(&cx, ...) ...
    /// cx.span().end();
    /// ```
    pub fn start_span(name: &str, kind: SpanKind) -> Context {
        let tracer = global::tracer("yauth");
        let span = tracer
            .span_builder(name.to_string())
            .with_kind(kind)
            .start(&tracer);
        Context::current().with_span(span)
    }

    /// Set an attribute on a specific context's span (not the current thread-local).
    pub fn set_attribute_on_cx(
        cx: &Context,
        key: &'static str,
        val: impl Into<opentelemetry::Value>,
    ) {
        let span = cx.span();
        span.set_attribute(KeyValue::new(key, val.into()));
    }

    /// Add a named event with attributes on a specific context's span.
    pub fn add_event_on_cx(cx: &Context, name: &str, attrs: Vec<KeyValue>) {
        let span = cx.span();
        span.add_event(name.to_string(), attrs);
    }

    /// Record an error on a specific context's span.
    pub fn record_error_on_cx(cx: &Context, name: &str, err: &dyn Display) {
        let span = cx.span();
        span.add_event(
            name.to_string(),
            vec![KeyValue::new("error.message", err.to_string())],
        );
        span.set_status(Status::error(err.to_string()));
    }

    /// End a span contained in a context.
    pub fn end_span(cx: &Context) {
        cx.span().end();
    }
}

#[cfg(not(feature = "telemetry"))]
#[allow(dead_code)]
mod inner {
    use std::fmt::Display;

    /// No-op: telemetry feature is disabled.
    #[inline(always)]
    pub fn record_error(_name: &str, _err: &dyn Display) {}

    /// No-op: telemetry feature is disabled.
    #[inline(always)]
    pub fn add_event(_name: &str, _attrs: Vec<()>) {}

    /// No-op: telemetry feature is disabled.
    #[inline(always)]
    pub fn set_attribute<V>(_key: &'static str, _val: V) {}

    /// No-op: telemetry feature is disabled. Runs the closure directly.
    #[inline(always)]
    pub fn with_span<F, T>(_name: &str, _kind: (), f: F) -> T
    where
        F: FnOnce() -> T,
    {
        f()
    }

    /// No-op: telemetry feature is disabled. Returns a unit placeholder.
    #[inline(always)]
    pub fn start_span(_name: &str, _kind: ()) {}

    /// No-op: telemetry feature is disabled.
    #[inline(always)]
    pub fn set_attribute_on_cx<V>(_cx: &(), _key: &'static str, _val: V) {}

    /// No-op: telemetry feature is disabled.
    #[inline(always)]
    pub fn add_event_on_cx(_cx: &(), _name: &str, _attrs: Vec<()>) {}

    /// No-op: telemetry feature is disabled.
    #[inline(always)]
    pub fn record_error_on_cx(_cx: &(), _name: &str, _err: &dyn Display) {}

    /// No-op: telemetry feature is disabled.
    #[inline(always)]
    pub fn end_span(_cx: &()) {}
}

pub use inner::*;
