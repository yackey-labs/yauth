package emailpassword_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// installRecorder swaps the global tracer provider for an in-memory recorder
// and registers the W3C TraceContext propagator (so otelhttp extracts inbound
// traceparent and injects it on the outbound HIBP call). It restores the prior
// globals on cleanup and returns the recorder.
func installRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return rec
}

// spanByName returns the first recorded span with the given name, or nil.
func spanByName(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// TestTelemetry_RegisterInstrumentation exercises the full register flow under a
// consumer-owned otelhttp root span (http_middleware:false), carrying an inbound
// W3C traceparent, and asserts:
//   - every new yauth check span shares the inbound TraceId (nested, not orphaned),
//   - the check spans are INTERNAL (no second SERVER span beyond the app's root),
//   - the outbound HIBP breach check injects the same traceparent (CLIENT span),
//   - user.id is stamped on the server span (Tier 1 attribution).
func TestTelemetry_RegisterInstrumentation(t *testing.T) {
	rec := installRecorder(t)

	// Stand-in HIBP range endpoint that records the inbound traceparent and
	// returns a "not breached" body so registration succeeds.
	var gotTraceparent string
	hibp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		// Any suffix that does not match the candidate's → count 0 → allowed.
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:0\r\n"))
	}))
	defer hibp.Close()

	repoRef := memrepo.New()
	ya, err := yauth.New(repoRef, yauth.NewDefaultConfig()).
		WithTraceMiddleware(false). // app owns the root span (otelhttp), as in prod
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         true,
			HIBPCheckSet:      true,
			HIBPEndpoint:      hibp.URL + "/range/",
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	// Wrap with otelhttp: this is the app's single root SERVER span and the
	// layer that EXTRACTS the inbound traceparent (yauth's own middleware is off).
	srv := httptest.NewServer(otelhttp.NewHandler(mux, "auth"))
	defer srv.Close()

	// Inbound trace: a fixed parent traceparent the otelhttp handler extracts.
	const traceID = "0af7651916cd43dd8448eb211c80319c"
	const inboundTP = "00-" + traceID + "-b7ad6b7169203331-01"

	buf, _ := json.Marshal(map[string]any{
		"email":    "telemetry@example.com",
		"password": "correct horse battery staple",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/register", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", inboundTP)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", res.StatusCode)
	}

	spans := rec.Ended()

	// 1) Traceparent round-trip: the outbound HIBP call carried a traceparent
	//    that shares the inbound TraceId.
	if gotTraceparent == "" {
		t.Fatalf("HIBP endpoint received no traceparent header (outbound not instrumented)")
	}
	if want := "00-" + traceID + "-"; len(gotTraceparent) < len(want) || gotTraceparent[:len(want)] != want {
		t.Errorf("outbound traceparent = %q, want prefix %q (same trace)", gotTraceparent, want)
	}

	// 2) Each named yauth check span exists, is INTERNAL, and shares the
	//    inbound TraceId (nested, not orphaned).
	wantInternal := []string{
		"yauth.ratelimit",
		"yauth.user.lookup",
		"yauth.password.policy",
		"yauth.password.breach_check",
		"yauth.session.create",
	}
	for _, name := range wantInternal {
		s := spanByName(spans, name)
		if s == nil {
			t.Errorf("missing span %q", name)
			continue
		}
		if s.SpanKind() != trace.SpanKindInternal {
			t.Errorf("span %q kind = %v, want Internal", name, s.SpanKind())
		}
		if got := s.SpanContext().TraceID().String(); got != traceID {
			t.Errorf("span %q TraceID = %s, want %s (orphaned from inbound trace)", name, got, traceID)
		}
		if !s.Parent().IsValid() {
			t.Errorf("span %q has no parent (orphaned)", name)
		}
	}

	// 3) Exactly one SERVER span (the app's otelhttp root) — yauth added no
	//    second server span in http_middleware:false mode.
	serverSpans := 0
	for _, s := range spans {
		if s.SpanKind() == trace.SpanKindServer {
			serverSpans++
		}
	}
	if serverSpans != 1 {
		t.Errorf("server spans = %d, want exactly 1 (no yauth duplicate server span)", serverSpans)
	}

	// 4) The outbound HIBP call produced a CLIENT span on the same trace.
	clientSpans := 0
	for _, s := range spans {
		if s.SpanKind() == trace.SpanKindClient {
			clientSpans++
			if got := s.SpanContext().TraceID().String(); got != traceID {
				t.Errorf("HIBP client span TraceID = %s, want %s", got, traceID)
			}
		}
	}
	if clientSpans == 0 {
		t.Errorf("no CLIENT span recorded for the outbound HIBP call")
	}

	// 5) Tier 1: user.id is stamped on the server (root) span.
	var serverSpan sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.SpanKind() == trace.SpanKindServer {
			serverSpan = s
			break
		}
	}
	if serverSpan == nil {
		t.Fatalf("no server span to inspect for user.id")
	}
	var userID string
	for _, kv := range serverSpan.Attributes() {
		if string(kv.Key) == "user.id" {
			userID = kv.Value.AsString()
		}
	}
	if userID == "" {
		t.Errorf("server span missing user.id attribute (Tier 1 attribution not applied)")
	}
}

// TestTelemetry_SessionResolveStampsUserID asserts that a RequireAuth-gated
// huma route (GET /session) stamps user.id onto the app-owned span when the
// caller is authenticated via a session cookie. This covers the resolve path:
// RequireAuthHuma must tag the active span (it injects the AuthUser by a path
// that bypasses withAuthUser, so without an explicit tag, session attribution
// would be silently missing on huma-native routes).
func TestTelemetry_SessionResolveStampsUserID(t *testing.T) {
	rec := installRecorder(t)

	repoRef := memrepo.New()
	ya, err := yauth.New(repoRef, yauth.NewDefaultConfig()).
		WithTraceMiddleware(false).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(otelhttp.NewHandler(mux, "auth"))
	defer srv.Close()

	// Register to obtain a session cookie.
	r1 := postJSON(t, srv.URL+"/api/auth/register",
		map[string]any{"email": "resolve@example.com", "password": "correct horse battery staple"})
	cookie := findCookie(r1, "yauth_session")
	r1.Body.Close()
	if cookie == nil {
		t.Fatalf("no session cookie from register")
	}

	const traceID = "33333333333333333333333333333333"
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/session", nil)
	req.AddCookie(cookie)
	req.Header.Set("traceparent", "00-"+traceID+"-4444444444444444-01")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session status = %d, want 200", res.StatusCode)
	}

	var sessionServer sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.SpanKind() == trace.SpanKindServer && s.SpanContext().TraceID().String() == traceID {
			sessionServer = s
			break
		}
	}
	if sessionServer == nil {
		t.Fatalf("no server span on the /session trace")
	}
	var userID string
	for _, kv := range sessionServer.Attributes() {
		if string(kv.Key) == "user.id" {
			userID = kv.Value.AsString()
		}
	}
	if userID == "" {
		t.Errorf("/session server span missing user.id (RequireAuthHuma resolve attribution not applied)")
	}
}

// TestTelemetry_LoginStampsUserID asserts that a successful login stamps user.id
// onto the active (app-owned) span the moment the user is resolved — without
// yauth's own HTTP middleware — and that the password.verify check span nests
// under the inbound trace.
func TestTelemetry_LoginStampsUserID(t *testing.T) {
	rec := installRecorder(t)

	repoRef := memrepo.New()
	ya, err := yauth.New(repoRef, yauth.NewDefaultConfig()).
		WithTraceMiddleware(false).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(otelhttp.NewHandler(mux, "auth"))
	defer srv.Close()

	const email = "login-telemetry@example.com"
	const password = "correct horse battery staple"

	// Register first (records spans for the register flow; we focus on login).
	r1 := postJSON(t, srv.URL+"/api/auth/register", map[string]any{"email": email, "password": password})
	r1.Body.Close()
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", r1.StatusCode)
	}

	const traceID = "11111111111111111111111111111111"
	buf, _ := json.Marshal(map[string]any{"email": email, "password": password})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/login", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", "00-"+traceID+"-2222222222222222-01")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", res.StatusCode)
	}

	spans := rec.Ended()

	// password.verify span exists, is INTERNAL, and nests under the login trace.
	verify := spanByName(spans, "yauth.password.verify")
	if verify == nil {
		t.Fatalf("missing yauth.password.verify span")
	}
	if verify.SpanKind() != trace.SpanKindInternal {
		t.Errorf("password.verify kind = %v, want Internal", verify.SpanKind())
	}
	if got := verify.SpanContext().TraceID().String(); got != traceID {
		t.Errorf("password.verify TraceID = %s, want %s", got, traceID)
	}

	// user.id is stamped on the login server span.
	var loginServer sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.SpanKind() == trace.SpanKindServer && s.SpanContext().TraceID().String() == traceID {
			loginServer = s
			break
		}
	}
	if loginServer == nil {
		t.Fatalf("no server span on the login trace")
	}
	var userID string
	for _, kv := range loginServer.Attributes() {
		if string(kv.Key) == "user.id" {
			userID = kv.Value.AsString()
		}
	}
	if userID == "" {
		t.Errorf("login server span missing user.id (Tier 1 login attribution not applied)")
	}
}
