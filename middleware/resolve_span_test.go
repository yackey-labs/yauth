package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// ctxCapturingRepo wraps fakeRepo and records the SpanContext carried by the
// context the middleware threads into GetUserByID. That is the direct proof
// that the yauth.resolve span's child ctx — not the bare request ctx — reaches
// the repo lookups, so SQL spans (under otelpgx in production) would re-parent
// under yauth.resolve. The in-memory fakeRepo emits no SQL spans of its own,
// so we assert the parentage at the context level instead.
type ctxCapturingRepo struct {
	*fakeRepo
	lookupSpanCtx trace.SpanContext
}

func (c *ctxCapturingRepo) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	c.lookupSpanCtx = trace.SpanContextFromContext(ctx)
	return c.fakeRepo.GetUserByID(ctx, id)
}

// TestResolveAuth_EmitsResolveSpanNestedUnderRoot drives a cookie-authenticated
// request whose context already carries an inbound (root) server span — the
// shape produced once the W3C traceparent is extracted by the consumer's HTTP
// instrumentation. It asserts that:
//
//   - a yauth.resolve INTERNAL span is recorded,
//   - it shares the inbound trace and nests directly under the root span,
//   - user.id (+ yauth.auth.method) land on the resolve span, and
//   - the session/user lookups run under the resolve span (the ctx threaded
//     into GetUserByID is parented by yauth.resolve).
func TestResolveAuth_EmitsResolveSpanNestedUnderRoot(t *testing.T) {
	prev := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})

	base := newFakeRepo()
	r := &ctxCapturingRepo{fakeRepo: base}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	user, err := base.CreateUser(ctx, domain.NewUser{
		ID:        uuid.NewString(),
		Email:     "alice@example.com",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	raw, _, err := auth.IssueSession(ctx, base, user.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	mw := New(r, Config{CookieName: "yauth_session"})

	// Seed a root SERVER span in the request ctx, mirroring the post-extraction
	// state the consumer's otelhttp middleware would hand yauth.
	rootCtx, rootSpan := otel.Tracer("test").Start(context.Background(), "GET /thing",
		trace.WithSpanKind(trace.SpanKindServer))
	rootSC := rootSpan.SpanContext()

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(rootCtx)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})

	au, err := mw.ResolveAuth(req)
	if err != nil {
		t.Fatalf("ResolveAuth: %v", err)
	}
	if au == nil || au.User.ID != user.ID {
		t.Fatalf("unexpected AuthUser: %+v", au)
	}
	rootSpan.End()

	// Find the yauth.resolve span.
	var resolve sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.Name() == "yauth.resolve" {
			resolve = s
			break
		}
	}
	if resolve == nil {
		t.Fatalf("no yauth.resolve span recorded; got %d spans", len(rec.Ended()))
	}

	if resolve.SpanKind() != trace.SpanKindInternal {
		t.Errorf("yauth.resolve kind = %v, want Internal", resolve.SpanKind())
	}
	if resolve.SpanContext().TraceID() != rootSC.TraceID() {
		t.Errorf("yauth.resolve trace = %s, want %s (shared with root)",
			resolve.SpanContext().TraceID(), rootSC.TraceID())
	}
	if resolve.Parent().SpanID() != rootSC.SpanID() {
		t.Errorf("yauth.resolve parent = %s, want root %s",
			resolve.Parent().SpanID(), rootSC.SpanID())
	}

	attrs := spanAttrs(resolve)
	if attrs["user.id"] != user.ID {
		t.Errorf("yauth.resolve user.id = %q, want %q", attrs["user.id"], user.ID)
	}
	if attrs["yauth.auth.method"] != domain.AuthMethodCookie {
		t.Errorf("yauth.resolve yauth.auth.method = %q, want %q",
			attrs["yauth.auth.method"], domain.AuthMethodCookie)
	}

	// The user lookup ctx must be parented by the resolve span — proof the
	// child ctx was threaded into the repo calls, so SQL re-parents under it.
	if got := r.lookupSpanCtx.SpanID(); got != resolve.SpanContext().SpanID() {
		t.Errorf("GetUserByID ran under span %s, want yauth.resolve %s",
			got, resolve.SpanContext().SpanID())
	}
}
