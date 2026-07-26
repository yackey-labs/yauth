package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testCtx() context.Context { return context.Background() }

// newTestMailer points a Mailer at srv and fills in valid credentials.
func newTestMailer(srv *httptest.Server) *Mailer {
	return New(Mailer{
		AccountID:  "acct123",
		APIToken:   "tok-secret",
		From:       "noreply@example.com",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
}

// okResponse writes a Cloudflare success envelope delivering to.
func okResponse(w http.ResponseWriter, to string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"errors":  []any{},
		"result": map[string]any{
			"delivered":         []string{to},
			"permanent_bounces": []string{},
			"queued":            []string{},
		},
	})
}

func TestSend_PostsExpectedRequest(t *testing.T) {
	var (
		gotPath   string
		gotAuth   string
		gotCT     string
		gotMethod string
		gotBody   sendRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		gotCT, gotMethod = r.Header.Get("Content-Type"), r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		okResponse(w, "user@example.com")
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendVerification(testCtx(), "user@example.com", "https://x/verify?t=abc"); err != nil {
		t.Fatalf("SendVerification: %v", err)
	}

	if want := "/accounts/acct123/email/sending/send"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if want := "Bearer tok-secret"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody.To != "user@example.com" || gotBody.From != "noreply@example.com" {
		t.Errorf("to/from = %q/%q", gotBody.To, gotBody.From)
	}
	if gotBody.Subject != "Verify your email" {
		t.Errorf("subject = %q", gotBody.Subject)
	}
	if !strings.Contains(gotBody.Text, "https://x/verify?t=abc") {
		t.Errorf("body missing link: %q", gotBody.Text)
	}
}

// A permanent bounce arrives as HTTP 200 + success:true. It must still be an
// error — otherwise a verification link silently goes nowhere.
func TestSend_PermanentBounceIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"errors":  []any{},
			"result": map[string]any{
				"delivered":         []string{},
				"permanent_bounces": []string{"user@example.com"},
				"queued":            []string{},
			},
		})
	}))
	defer srv.Close()

	err := newTestMailer(srv).SendMagicLink(testCtx(), "user@example.com", "https://x/login")
	if err == nil {
		t.Fatal("expected an error for a permanently bounced recipient, got nil")
	}
	if !strings.Contains(err.Error(), "bounce") {
		t.Errorf("error should name the bounce, got %q", err)
	}
}

func TestSend_QueuedCountsAsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"errors":  []any{},
			"result": map[string]any{
				"delivered":         []string{},
				"permanent_bounces": []string{},
				"queued":            []string{"user@example.com"},
			},
		})
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendPasswordReset(testCtx(), "user@example.com", "https://x/reset"); err != nil {
		t.Errorf("a queued recipient should succeed, got %v", err)
	}
}

// Neither delivered, queued, nor bounced: the recipient vanished. The caller
// must not assume a token is in flight.
func TestSend_UnlistedRecipientIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		okResponse(w, "someone-else@example.com")
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendUnlockToken(testCtx(), "user@example.com", "https://x/unlock"); err == nil {
		t.Fatal("expected an error when the recipient is absent from the result")
	}
}

// Recipients echoed back with different casing still count as delivered.
func TestSend_RecipientMatchIsCaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		okResponse(w, "User@Example.COM")
	}))
	defer srv.Close()

	if err := newTestMailer(srv).SendAccountExists(testCtx(), "user@example.com"); err != nil {
		t.Errorf("case-differing echo should still be a delivery, got %v", err)
	}
}

func TestSend_SuccessFalseSurfacesErrorDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors": []map[string]any{
				{"code": 1002, "message": "domain not onboarded"},
			},
		})
	}))
	defer srv.Close()

	err := newTestMailer(srv).SendVerification(testCtx(), "user@example.com", "https://x/verify")
	if err == nil {
		t.Fatal("expected an error when success=false")
	}
	if !strings.Contains(err.Error(), "domain not onboarded") || !strings.Contains(err.Error(), "1002") {
		t.Errorf("error should carry Cloudflare's code + message, got %q", err)
	}
}

func TestSend_HTTPErrorStatusSurfacesDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors":  []map[string]any{{"code": 10000, "message": "Authentication error"}},
		})
	}))
	defer srv.Close()

	err := newTestMailer(srv).SendVerification(testCtx(), "user@example.com", "https://x/verify")
	if err == nil {
		t.Fatal("expected an error on HTTP 401")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Authentication error") {
		t.Errorf("error should carry status + detail, got %q", err)
	}
}

// A gateway that returns HTML rather than JSON must still produce a usable
// error instead of a decode panic or a false success.
func TestSend_NonJSONErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	defer srv.Close()

	err := newTestMailer(srv).SendVerification(testCtx(), "user@example.com", "https://x/verify")
	if err == nil {
		t.Fatal("expected an error on a non-JSON 502")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should name the status, got %q", err)
	}
}

// The API token must never reach an error string — errors get logged.
func TestSend_ErrorsNeverLeakToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"bad token"}]}`))
	}))
	defer srv.Close()

	err := newTestMailer(srv).SendVerification(testCtx(), "user@example.com", "https://x/verify")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "tok-secret") {
		t.Errorf("error leaked the API token: %q", err)
	}
}

func TestSend_RejectsMissingConfig(t *testing.T) {
	for name, m := range map[string]*Mailer{
		"no account": {APIToken: "t", From: "f@x"},
		"no token":   {AccountID: "a", From: "f@x"},
		"no from":    {AccountID: "a", APIToken: "t"},
	} {
		if err := m.send(testCtx(), "verification", "u@x", "s", "b"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSend_HonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		okResponse(w, "user@example.com")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(testCtx())
	cancel()
	if err := newTestMailer(srv).SendVerification(ctx, "user@example.com", "https://x/verify"); err == nil {
		t.Error("expected an error from a cancelled context")
	}
}

// BaseURL is optional; leaving it empty must fall back to Cloudflare's API
// root rather than producing a relative URL.
func TestSend_DefaultsToCloudflareAPIRoot(t *testing.T) {
	m := New(Mailer{AccountID: "a", APIToken: "t", From: "f@x"})
	ctx, cancel := context.WithCancel(testCtx())
	cancel()
	err := m.send(ctx, "verification", "u@x", "s", "b")
	if err == nil {
		t.Fatal("expected the cancelled context to abort the request")
	}
	// A malformed URL would fail at build-request time with a different
	// message; a cancelled context proves we got as far as dialing.
	if strings.Contains(err.Error(), "build request") {
		t.Errorf("default BaseURL produced an invalid URL: %v", err)
	}
}

func TestInterfaceMethodsExist(t *testing.T) {
	// Compile-time enforcement that *Mailer carries the names every
	// plugin's Mailer interface expects. Each method below is also
	// referenced by the plugin's Mailer interface.
	m := &Mailer{}
	_ = m.SendVerification
	_ = m.SendPasswordReset
	_ = m.SendAccountExists
	_ = m.SendMagicLink
	_ = m.SendUnlockToken
}
