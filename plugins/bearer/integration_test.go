package bearer_test

// End-to-end cover for the native (token) login path against the REAL
// plugin stack — memrepo + yauth + email-password + mfa + bearer + lockout.
// The in-package tests in mfa_test.go drive bearer through doubles; these
// prove the wiring itself: that the mfa plugin's login.succeeded handler
// reaches /token, that its pending session is completable at /token/mfa,
// and that lockout now counts /token failures.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	jwtSecret    = "test-secret-min-32-bytes-long-yes-yes"
)

type stack struct {
	srv *httptest.Server
	// cookies is a jar-backed client used only for the cookie-side setup
	// (register + TOTP enrolment). The token flow never touches it.
	cookies *http.Client
}

// newStack builds the full plugin stack. extra plugins (e.g. lockout) are
// appended after mfa.
func newStack(t *testing.T, withMFA bool, extra ...plugin.Plugin) (*stack, func()) {
	t.Helper()

	b := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).
		WithJWTSecret([]byte(jwtSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		}))

	if withMFA {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		p, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: "yauth-test"})
		if err != nil {
			t.Fatalf("mfa.New: %v", err)
		}
		b = b.WithPlugin(p)
	}
	b = b.WithPlugin(bearer.New(bearer.Config{}))
	for _, p := range extra {
		b = b.WithPlugin(p)
	}

	ya, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)

	jar, _ := cookiejar.New(nil)
	return &stack{srv: srv, cookies: &http.Client{Jar: jar}}, srv.Close
}

func (s *stack) post(t *testing.T, cl *http.Client, path string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+path, &buf)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

// tokenBody is the union /token can answer with.
type tokenBody struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RequireMfa       bool   `json:"require_mfa"`
	PendingSessionID string `json:"pending_session_id"`
}

func decode(t *testing.T, res *http.Response) tokenBody {
	t.Helper()
	defer res.Body.Close()
	var out tokenBody
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func drain(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func (s *stack) register(t *testing.T) {
	t.Helper()
	res := s.post(t, s.cookies, "/api/auth/register", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// enrolTOTP runs the cookie-side enrolment and returns the shared secret.
func (s *stack) enrolTOTP(t *testing.T) string {
	t.Helper()
	res := s.post(t, s.cookies, "/api/auth/mfa/totp/setup", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("totp setup: %d (%s)", res.StatusCode, drain(res))
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(res.Body).Decode(&setup); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	res.Body.Close()

	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	res = s.post(t, s.cookies, "/api/auth/mfa/totp/confirm", map[string]string{"code": code})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("totp confirm: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	return setup.Secret
}

// TestTokenLogin_TOTPEnrolled_RequiresSecondFactor is the end-to-end
// regression test: before the fix, this /token call returned a full token
// pair on the password alone, silently voiding the user's second factor.
func TestTokenLogin_TOTPEnrolled_RequiresSecondFactor(t *testing.T) {
	s, stop := newStack(t, true)
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	// Leg 1: password only — no tokens, a challenge instead.
	res := s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: %d (%s)", res.StatusCode, drain(res))
	}
	first := decode(t, res)
	if !first.RequireMfa || first.PendingSessionID == "" {
		t.Fatalf("expected require_mfa + pending_session_id, got %+v", first)
	}
	if first.AccessToken != "" || first.RefreshToken != "" {
		t.Fatalf("MFA-enrolled account got tokens from the password alone: %+v", first)
	}

	// Leg 2: complete the challenge with a real TOTP code.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	res = s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": first.PendingSessionID,
		"code":               code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token/mfa: %d (%s)", res.StatusCode, drain(res))
	}
	pair := decode(t, res)
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.TokenType != "Bearer" {
		t.Fatalf("expected a token pair, got %+v", pair)
	}

	// The access token really authenticates.
	req, _ := http.NewRequest(http.MethodGet, s.srv.URL+"/api/auth/session", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session with issued access token: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// The pending session is spent — replaying it fails.
	code2, _ := totp.GenerateCode(secret, time.Now().Add(31*time.Second))
	res = s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": first.PendingSessionID,
		"code":               code2,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed pending session: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestTokenLogin_WrongCodeRejected: a bad code never yields tokens, and it
// burns the challenge.
func TestTokenLogin_WrongCodeRejected(t *testing.T) {
	s, stop := newStack(t, true)
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	res := s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	first := decode(t, res)

	res = s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": first.PendingSessionID,
		"code":               "000000",
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	good, _ := totp.GenerateCode(secret, time.Now())
	res = s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": first.PendingSessionID,
		"code":               good,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("spent challenge: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestTokenLogin_NoMFA_Unchanged is the backwards-compatibility guard: with
// the mfa plugin loaded but no TOTP enrolled, one /token call still returns
// the token pair.
func TestTokenLogin_NoMFA_Unchanged(t *testing.T) {
	s, stop := newStack(t, true)
	defer stop()

	s.register(t)

	res := s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: %d (%s)", res.StatusCode, drain(res))
	}
	body := decode(t, res)
	if body.RequireMfa || body.PendingSessionID != "" {
		t.Fatalf("unexpected step-up for a user with no second factor: %+v", body)
	}
	if body.AccessToken == "" || body.RefreshToken == "" || body.TokenType != "Bearer" || body.ExpiresIn <= 0 {
		t.Fatalf("expected the classic token body, got %+v", body)
	}
}

// TestTokenLogin_LockoutApplies is the regression test for the second half
// of the bypass: /token was an unthrottled password oracle because lockout
// never saw its failures. With MaxAttempts=2, the third call — carrying the
// CORRECT password — must be blocked.
func TestTokenLogin_LockoutApplies(t *testing.T) {
	s, stop := newStack(t, false, lockout.New(lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{time.Minute},
	}))
	defer stop()

	s.register(t)

	for i := 0; i < 2; i++ {
		res := s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
			"email": testEmail, "password": "wrong-password",
		})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bad password #%d: expected 401, got %d (%s)", i+1, res.StatusCode, drain(res))
		}
		res.Body.Close()
	}

	res := s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked account: expected 429, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestTokenLogin_MFAExchangeWithoutMFAPlugin: a deployment with bearer but
// no mfa plugin has no verifier, so the exchange fails closed.
func TestTokenLogin_MFAExchangeWithoutMFAPlugin(t *testing.T) {
	s, stop := newStack(t, false)
	defer stop()

	s.register(t)

	res := s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": "anything",
		"code":               "123456",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}
