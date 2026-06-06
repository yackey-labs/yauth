package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"
)

// tracer returns the global tracer registered under TracerName. When the
// no-op provider is installed this returns a no-op tracer and every helper
// below becomes a cheap pass-through.
func tracer() trace.Tracer { return otel.Tracer(TracerName) }

// RecordError adds an error event to the current span and sets its status
// to Error. Mirrors the Rust `record_error` helper.
func RecordError(ctx context.Context, name string, err error) {
	if err == nil {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(
		attribute.String("error.message", err.Error()),
	))
	span.SetStatus(codes.Error, err.Error())
}

// AddEvent attaches a named event with attributes to the current span.
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SetUserID records the authenticated user's identifier on the span carried
// by ctx using the OpenTelemetry `user.id` semantic convention. It is a safe
// no-op when no recording span is present, so it works whether the request is
// covered by yauth's own TraceMiddleware or by a consumer's HTTP
// instrumentation (e.g. otelhttp) — in the latter case it enriches the
// consumer's server span. Empty ids are ignored.
func SetUserID(ctx context.Context, id string) {
	if id == "" {
		return
	}
	trace.SpanFromContext(ctx).SetAttributes(semconv.UserID(id))
}

// SetUserBaggage returns a context that carries the authenticated user's
// identifier as a W3C baggage member under the `user.id` key. Unlike SetUserID
// — which records user.id on the *current* span only — baggage rides the
// context across span and service boundaries (via the Baggage propagator that
// Init registers), so descendant spans and downstream services can read it and
// enrich their own telemetry.
//
// It returns the input ctx unchanged when id is empty or when id violates the
// W3C baggage value restrictions (so it never panics or drops the existing
// context). Reading it back is standard OTel: walk baggage.FromContext(ctx).
func SetUserBaggage(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	member, err := baggage.NewMember(string(semconv.UserIDKey), id)
	if err != nil {
		return ctx
	}
	bag, err := baggage.FromContext(ctx).SetMember(member)
	if err != nil {
		return ctx
	}
	return baggage.ContextWithBaggage(ctx, bag)
}

// SetAttribute sets a single attribute on the current span. Accepts the
// scalar types OpenTelemetry supports natively; anything else is converted
// to a string via fmt.Sprintf("%v", val) so call sites do not have to
// branch on type.
func SetAttribute(ctx context.Context, key string, val any) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(toKeyValue(key, val))
}

// WithSpan opens a span named name with the given kind, runs fn under it,
// records any returned error on the span, and ends the span. The returned
// error is fn's error verbatim.
func WithSpan(ctx context.Context, name string, kind trace.SpanKind, fn func(context.Context) error) error {
	ctx, span := tracer().Start(ctx, name, trace.WithSpanKind(kind))
	defer span.End()

	err := fn(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	return err
}

// StartSpan opens a span and returns the new context plus the span. The
// caller is responsible for calling span.End().
func StartSpan(ctx context.Context, name string, kind trace.SpanKind) (context.Context, trace.Span) {
	return tracer().Start(ctx, name, trace.WithSpanKind(kind))
}

// SetAttributeOnCx sets an attribute on the span carried by cx without
// looking at the goroutine-local "current" span.
func SetAttributeOnCx(cx context.Context, key string, val any) {
	trace.SpanFromContext(cx).SetAttributes(toKeyValue(key, val))
}

// AddEventOnCx attaches an event to the span carried by cx.
func AddEventOnCx(cx context.Context, name string, attrs ...attribute.KeyValue) {
	trace.SpanFromContext(cx).AddEvent(name, trace.WithAttributes(attrs...))
}

// RecordErrorOnCx records err on the span carried by cx.
func RecordErrorOnCx(cx context.Context, name string, err error) {
	if err == nil {
		return
	}
	span := trace.SpanFromContext(cx)
	span.AddEvent(name, trace.WithAttributes(
		attribute.String("error.message", err.Error()),
	))
	span.SetStatus(codes.Error, err.Error())
}

// EndSpan ends the span carried by cx. Provided for parity with the Rust
// helper of the same name.
func EndSpan(cx context.Context) {
	trace.SpanFromContext(cx).End()
}

// toKeyValue narrows an arbitrary scalar to the closest attribute.KeyValue
// representation. Supported native types: string, bool, int / int32 / int64,
// float32 / float64. Everything else is rendered with fmt.Sprintf.
func toKeyValue(key string, val any) attribute.KeyValue {
	switch v := val.(type) {
	case string:
		return attribute.String(key, v)
	case bool:
		return attribute.Bool(key, v)
	case int:
		return attribute.Int64(key, int64(v))
	case int32:
		return attribute.Int64(key, int64(v))
	case int64:
		return attribute.Int64(key, v)
	case float32:
		return attribute.Float64(key, float64(v))
	case float64:
		return attribute.Float64(key, v)
	case fmt.Stringer:
		return attribute.String(key, v.String())
	default:
		return attribute.String(key, fmt.Sprintf("%v", val))
	}
}
