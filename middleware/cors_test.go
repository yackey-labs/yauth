package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestCORS_NoOriginsDisablesMiddleware(t *testing.T) {
	wrapped := CORS(CORSConfig{})(okHandler())
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO should be empty when middleware is disabled, got %q", got)
	}
}

func TestCORS_PreflightAllowedOrigin(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           5 * time.Minute,
	}
	wrapped := CORS(cfg)(okHandler())
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("preflight status: want 204, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO: want exact origin, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("ACAC: want true, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Fatalf("ACAM: want POST in %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type" {
		t.Fatalf("ACAH: want Content-Type, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Max-Age"); got != "300" {
		t.Fatalf("ACMA: want 300, got %q", got)
	}
}

func TestCORS_PreflightBlockedOrigin(t *testing.T) {
	cfg := CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
	wrapped := CORS(cfg)(okHandler())
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("preflight blocked: want 403, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("blocked preflight must not set ACAO")
	}
}

func TestCORS_NonPreflightAllowed(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowCredentials: true,
	}
	wrapped := CORS(cfg)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("simple status: want 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO: want origin reflected, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("ACAC: want true, got %q", got)
	}
	if got := rr.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary: want Origin, got %q", got)
	}
}

func TestCORS_WildcardWithoutCredentials(t *testing.T) {
	cfg := CORSConfig{AllowedOrigins: []string{"*"}}
	wrapped := CORS(cfg)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anywhere.example")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("ACAO: want *, got %q", got)
	}
}

// TestCORS_WildcardWithCredentialsDoesNotReflectArpinOrigin pins the
// credentials-mode wildcard refusal: reflecting an attacker-chosen Origin
// with Access-Control-Allow-Credentials is what made every credentialed
// cross-origin response readable from anywhere. The wildcard entry must
// contribute nothing when credentials are on — explicitly listed origins
// keep working, and the attacker's origin gets no ACAO at all.
func TestCORS_WildcardWithCredentialsDoesNotReflectArbitraryOrigin(t *testing.T) {
	cfg := CORSConfig{
		// "*" is present, but so is a real origin: the real one is the
		// only thing the wildcard list is still good for.
		AllowedOrigins:   []string{"*", "https://app.example.com"},
		AllowCredentials: true,
	}
	wrapped := CORS(cfg)(okHandler())

	// The listed origin is still served credentially.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO for listed origin: want origin reflected, got %q", got)
	}

	// A cheeky third-party origin gets nothing, credentials or not.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://attacker.example")
	rr = httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO for unlisted origin: want empty, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("ACAC for unlisted origin: want empty, got %q", got)
	}
}

func TestCORS_NoOriginPassthrough(t *testing.T) {
	cfg := CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
	called := false
	wrapped := CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if !called {
		t.Fatal("non-CORS request should pass through to handler")
	}
}
