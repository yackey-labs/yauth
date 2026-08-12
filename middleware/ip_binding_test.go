package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// proxiedRequest models what a reverse proxy actually presents: the peer is
// the proxy on private space, and the client's address arrives in
// X-Forwarded-For.
func proxiedRequest(raw, clientIP string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.5:41234"
	r.Header.Set("X-Forwarded-For", clientIP)
	r.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
	return r
}

// TestRequireAuth_BindIP_ProxiedSessionIsNotAMismatch is the end-to-end form
// of the finding. The session's ip_address is written by
// middleware.RequestIP, which reads X-Forwarded-For; the binding check used
// to compare it against r.RemoteAddr, which behind a proxy is the PROXY. So
// every single request from a legitimately proxied session was scored a
// mismatch: with ip_mismatch_action=invalidate that logged the user out on
// their very next request, and under the default warn it filled the audit
// log with noise a real hijack could hide in.
//
// Before the fix this 401'd, and the session row was deleted.
func TestRequireAuth_BindIP_ProxiedSessionIsNotAMismatch(t *testing.T) {
	// The session was issued from a proxied login, so its stored IP is the
	// value RequestIP produced there.
	stored := RequestIP(proxiedRequest("", "203.0.113.9"))
	if stored == nil || *stored != "203.0.113.9" {
		t.Fatalf("RequestIP at login = %v; want 203.0.113.9", stored)
	}

	cap, raw, tokenHash := setupBindingHarness(t, *stored, "")
	mw := New(cap, Config{
		CookieName:       "yauth_session",
		BindIP:           true,
		IPMismatchAction: MismatchActionInvalidate,
	})

	hit := false
	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, proxiedRequest(raw, "203.0.113.9"))

	if rec.Code != http.StatusOK {
		t.Fatalf("same client behind the same proxy should pass, got %d", rec.Code)
	}
	if !hit {
		t.Fatal("expected the handler to run")
	}
	if _, ok := cap.fakeRepo.sessions[tokenHash]; !ok {
		t.Fatal("session was invalidated for a client that never moved")
	}
	if len(cap.audits) != 0 {
		t.Fatalf("expected no mismatch audit, got %+v", cap.audits)
	}
}

// A genuine hijack — a different client behind the SAME proxy — must still
// be caught. The fix must not turn IP binding into a no-op behind a proxy,
// which is what comparing proxy-to-proxy would have done.
func TestRequireAuth_BindIP_ProxiedHijackStillCaught(t *testing.T) {
	cap, raw, tokenHash := setupBindingHarness(t, "203.0.113.9", "")
	mw := New(cap, Config{
		CookieName:       "yauth_session",
		BindIP:           true,
		IPMismatchAction: MismatchActionInvalidate,
	})

	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, proxiedRequest(raw, "198.51.100.66"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stolen cookie replayed from another client should 401, got %d", rec.Code)
	}
	if _, ok := cap.fakeRepo.sessions[tokenHash]; ok {
		t.Fatal("session row should be deleted on invalidate")
	}
	if len(cap.audits) != 1 || cap.audits[0].EventType != "session_ip_mismatch_invalidate" {
		t.Fatalf("expected session_ip_mismatch_invalidate audit, got %+v", cap.audits)
	}
}

// A client that reaches the listener directly cannot dodge IP binding by
// asserting the session's stored address in a header it wrote itself.
func TestRequireAuth_BindIP_ForgedXFFCannotDefeatBinding(t *testing.T) {
	cap, raw, _ := setupBindingHarness(t, "203.0.113.9", "")
	mw := New(cap, Config{
		CookieName:       "yauth_session",
		BindIP:           true,
		IPMismatchAction: MismatchActionInvalidate,
	})

	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.66:52000" // public peer: no proxy in front
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a self-asserted X-Forwarded-For must not satisfy IP binding, got %d", rec.Code)
	}
	if len(cap.audits) != 1 || cap.audits[0].EventType != "session_ip_mismatch_invalidate" {
		t.Fatalf("expected session_ip_mismatch_invalidate audit, got %+v", cap.audits)
	}
}
