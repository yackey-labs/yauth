package middleware

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/yackey-labs/yauth/domain"
)

// TestWithAuthUser_TagsUserID asserts that attaching a resolved AuthUser to a
// request context also records the `user.id` semantic-convention attribute on
// the active span. This is the integration point that lets yauth participate
// in a consumer's traces (their otelhttp span) without yauth's own middleware.
func TestWithAuthUser_TagsUserID(t *testing.T) {
	prev := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})

	ctx, span := otel.Tracer("test").Start(context.Background(), "GET /thing",
		trace.WithSpanKind(trace.SpanKindServer))

	au := &domain.AuthUser{User: domain.User{ID: "user-abc"}}
	_ = withAuthUser(ctx, au)
	span.End()

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	got := spanAttrs(spans[0])
	if got["user.id"] != "user-abc" {
		t.Errorf("user.id = %q, want %q", got["user.id"], "user-abc")
	}
	// Without org/bearer plugins the AuthUser carries no org context, so
	// only user.id is emitted.
	for _, k := range []string{"yauth.active_org.id", "yauth.org.role", "yauth.auth.method", "yauth.principal.kind"} {
		if v, ok := got[k]; ok {
			t.Errorf("unexpected attribute %s=%q on a bare AuthUser", k, v)
		}
	}
}

// TestWithAuthUser_TagsOrgAndAuthContext asserts that the org/role/method/
// principal context hydrated onto an AuthUser is emitted under the yauth.*
// namespace alongside the semconv user.id.
func TestWithAuthUser_TagsOrgAndAuthContext(t *testing.T) {
	prev := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})

	ctx, span := otel.Tracer("test").Start(context.Background(), "GET /thing",
		trace.WithSpanKind(trace.SpanKindServer))

	orgID, role := "org-456", "admin"
	au := &domain.AuthUser{
		User:        domain.User{ID: "user-abc"},
		Method:      domain.AuthMethodBearer,
		ActiveOrgID: &orgID,
		OrgRole:     &role,
		Principal:   domain.Principal{Kind: domain.PrincipalKindUser},
	}
	_ = withAuthUser(ctx, au)
	span.End()

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	got := spanAttrs(spans[0])
	want := map[string]string{
		"user.id":              "user-abc",
		"yauth.active_org.id":  "org-456",
		"yauth.org.role":       "admin",
		"yauth.auth.method":    domain.AuthMethodBearer,
		"yauth.principal.kind": string(domain.PrincipalKindUser),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// spanAttrs flattens a recorded span's attributes into a string map.
func spanAttrs(s sdktrace.ReadOnlySpan) map[string]string {
	out := make(map[string]string)
	for _, kv := range s.Attributes() {
		out[string(kv.Key)] = kv.Value.AsString()
	}
	return out
}
