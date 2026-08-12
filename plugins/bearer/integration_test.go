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
	"strings"
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
	// cookies is a jar-backed client used for the cookie-side setup
	// (register + TOTP enrolment) and for the cookie login flow.
	cookies *http.Client
}

// stackOpts configures the plugin stack, including the ORDER mfa and
// lockout are registered in. That order used to decide behaviour — it must
// not any more, so the tests drive it both ways.
type stackOpts struct {
	mfa     bool
	lockout *lockout.Config
	// lockoutFirst registers lockout BEFORE mfa, which is what
	// NewFromConfig does. The zero value registers mfa first, the
	// ordering that starved lockout of its clear.
	lockoutFirst bool
}

func newMFAPlugin(t *testing.T) plugin.Plugin {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	p, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: "yauth-test"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}
	return p
}

// newStack builds the full plugin stack in the requested order.
func newStack(t *testing.T, opts stackOpts) (*stack, func()) {
	t.Helper()

	b := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).
		WithJWTSecret([]byte(jwtSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		}))

	var mfaPlug, lockPlug plugin.Plugin
	if opts.mfa {
		mfaPlug = newMFAPlugin(t)
	}
	if opts.lockout != nil {
		lockPlug = lockout.New(*opts.lockout)
	}
	ordered := []plugin.Plugin{mfaPlug, lockPlug}
	if opts.lockoutFirst {
		ordered = []plugin.Plugin{lockPlug, mfaPlug}
	}
	for _, p := range ordered {
		if p != nil {
			b = b.WithPlugin(p)
		}
	}
	b = b.WithPlugin(bearer.New(bearer.Config{}))

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
	s, stop := newStack(t, stackOpts{mfa: true})
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
	s, stop := newStack(t, stackOpts{mfa: true})
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
	s, stop := newStack(t, stackOpts{mfa: true})
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
	s, stop := newStack(t, stackOpts{lockout: &lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{time.Minute},
	}})
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

// --- lockout state across a stepped-up login -----------------------------
//
// login.succeeded means "password verified", and for an MFA user that is
// NOT the end of the login. Two defects followed, and which one you got
// depended on plugin registration order:
//
//   - mfa before lockout: the RequireMfa decision short-circuits Emit, so
//     lockout's clear never ran. An MFA user's failure count accumulated
//     across every login until they were locked out despite always
//     authenticating correctly.
//   - lockout before mfa (what NewFromConfig does): the clear ran at
//     password time, so wrong TOTP codes were forgiven by the next password
//     login and MFA brute force was never throttled.
//
// The fix is two-sided: mfa's step-up is a pipeline GATE (always ahead of
// observers), and completing a challenge emits its own marked
// login.succeeded. The tests below run BOTH orderings.

// failPassword drives one bad-password login and asserts the opaque 401.
func (s *stack) failPassword(t *testing.T, path string) {
	t.Helper()
	res := s.post(t, http.DefaultClient, path, map[string]string{
		"email": testEmail, "password": "wrong-password",
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password on %s: expected 401, got %d (%s)", path, res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// bearerStepUp does the password leg of a native login and returns the
// pending session id.
func (s *stack) bearerStepUp(t *testing.T) string {
	t.Helper()
	res := s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: %d (%s)", res.StatusCode, drain(res))
	}
	body := decode(t, res)
	if !body.RequireMfa || body.PendingSessionID == "" {
		t.Fatalf("expected a step-up, got %+v", body)
	}
	return body.PendingSessionID
}

// cookieStepUp does the password leg of a cookie login and returns the
// pending session id.
func (s *stack) cookieStepUp(t *testing.T, cl *http.Client) string {
	t.Helper()
	res := s.post(t, cl, "/api/auth/login", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d (%s)", res.StatusCode, drain(res))
	}
	var body struct {
		RequireMfa       bool   `json:"require_mfa"`
		PendingSessionID string `json:"pending_session_id"`
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if !body.RequireMfa || body.PendingSessionID == "" {
		t.Fatalf("expected a step-up, got %+v", body)
	}
	return body.PendingSessionID
}

// TestLockout_ClearedByBearerMFACompletion_MFAFirst is defect 1 with mfa
// registered BEFORE lockout — the ordering in which the clear never ran, so
// a correct MFA login walked the user closer to a spurious lockout.
func TestLockout_ClearedByBearerMFACompletion_MFAFirst(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true, lockout: &lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{time.Minute},
	}})
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	s.failPassword(t, "/api/auth/token") // count = 1

	// A complete, correct MFA login must reset that count.
	pending := s.bearerStepUp(t)
	code, _ := totp.GenerateCode(secret, time.Now())
	res := s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": pending, "code": code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token/mfa: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	s.failPassword(t, "/api/auth/token") // count = 1 again, NOT 2

	// Still under the threshold: the next correct password reaches the
	// step-up rather than a lock.
	res = s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("spurious lockout: the MFA completion never cleared the failure count (%s)", drain(res))
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestLockout_ClearedByCookieMFACompletion_LockoutFirst is the same defect
// on the cookie path with the NewFromConfig ordering (lockout before mfa).
// Here the gate is what makes it work: mfa now runs ahead of lockout, so
// nothing is cleared at password time, and /mfa/verify's completion event
// is what clears.
func TestLockout_ClearedByCookieMFACompletion_LockoutFirst(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true, lockoutFirst: true, lockout: &lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{time.Minute},
	}})
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	s.failPassword(t, "/api/auth/login") // count = 1

	cl := &http.Client{}
	pending := s.cookieStepUp(t, cl)
	code, _ := totp.GenerateCode(secret, time.Now())
	res := s.post(t, cl, "/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pending, "code": code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mfa/verify: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	s.failPassword(t, "/api/auth/login") // count = 1 again, NOT 2

	res = s.post(t, s.cookies, "/api/auth/login", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("spurious lockout: the MFA completion never cleared the failure count (%s)", drain(res))
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestLockout_CountsWrongTOTPCodes_Bearer is defect 2 on the native path: a
// wrong code emits login.failed, so lockout throttles MFA brute force. Run
// in the NewFromConfig order (lockout first) because that is the ordering
// that used to forgive the count on every fresh password login.
func TestLockout_CountsWrongTOTPCodes_Bearer(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true, lockoutFirst: true, lockout: &lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{time.Minute},
	}})
	defer stop()

	s.register(t)
	s.enrolTOTP(t)

	for i := 0; i < 2; i++ {
		pending := s.bearerStepUp(t)
		res := s.post(t, http.DefaultClient, "/api/auth/token/mfa", map[string]string{
			"pending_session_id": pending, "code": "000000",
		})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong code #%d: expected 401, got %d (%s)", i+1, res.StatusCode, drain(res))
		}
		res.Body.Close()
	}

	// Two wrong codes is the threshold: the account is locked, and the
	// correct password no longer even reaches the step-up.
	res := s.post(t, http.DefaultClient, "/api/auth/token", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("MFA brute force went unthrottled: expected 429, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestLockout_CountsWrongTOTPCodes_Cookie is the same for /mfa/verify.
func TestLockout_CountsWrongTOTPCodes_Cookie(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true, lockoutFirst: true, lockout: &lockout.Config{
		MaxAttempts:      2,
		LockoutDurations: []time.Duration{time.Minute},
	}})
	defer stop()

	s.register(t)
	s.enrolTOTP(t)

	cl := &http.Client{}
	for i := 0; i < 2; i++ {
		pending := s.cookieStepUp(t, cl)
		res := s.post(t, cl, "/api/auth/mfa/verify", map[string]string{
			"pending_session_id": pending, "code": "000000",
		})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong code #%d: expected 401, got %d (%s)", i+1, res.StatusCode, drain(res))
		}
		res.Body.Close()
	}

	res := s.post(t, cl, "/api/auth/login", map[string]string{
		"email": testEmail, "password": testPassword,
	})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("MFA brute force went unthrottled: expected 429, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestMFAVerify_NoChallengeLoop: completing a challenge must not hand back
// another one. The completion event is a login.succeeded, so without the
// marker the mfa gate would re-challenge its own completion forever.
func TestMFAVerify_NoChallengeLoop(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true})
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	// A jar, so the session the verify issues is actually carried below.
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar}
	pending := s.cookieStepUp(t, cl)
	code, _ := totp.GenerateCode(secret, time.Now())
	res := s.post(t, cl, "/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pending, "code": code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mfa/verify: %d (%s)", res.StatusCode, drain(res))
	}
	body := drain(res)
	if strings.Contains(body, "require_mfa") || strings.Contains(body, "pending_session_id") {
		t.Fatalf("verify handed back another challenge — that is the loop: %s", body)
	}

	// And the session it issued really works.
	req, _ := http.NewRequest(http.MethodGet, s.srv.URL+"/api/auth/session", nil)
	res2, err := cl.Do(req)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("session after verify: %d (%s)", res2.StatusCode, drain(res2))
	}
	res2.Body.Close()
}

// TestTokenLogin_MFAExchangeWithoutMFAPlugin: a deployment with bearer but
// no mfa plugin has no verifier, so the exchange fails closed.
func TestTokenLogin_MFAExchangeWithoutMFAPlugin(t *testing.T) {
	s, stop := newStack(t, stackOpts{})
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
