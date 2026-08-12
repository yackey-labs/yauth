package magiclink_test

// End-to-end cover for /magic-link/verify against the REAL plugin stack —
// memrepo + yauth + email-password + magic-link + mfa + lockout.
//
// The route used to emit login.succeeded and throw the Decision away, then
// Set-Cookie unconditionally. That waved MFA through for anyone with an
// inbox and let a locked account back in. These tests assert on the
// Set-Cookie header, not just on the body, because "looks like a challenge"
// is not the property that matters — "issued no session" is.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/plugins/magiclink"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
)

type stack struct {
	srv    *httptest.Server
	mailer *captureMailer
	// cookies is a jar-backed client used for the cookie-side setup
	// (register + TOTP enrolment).
	cookies *http.Client
}

// stackOpts configures the plugin stack, including the ORDER mfa and
// lockout are registered in. That order used to decide behaviour — it must
// not any more, so the tests drive it both ways.
type stackOpts struct {
	mfa     bool
	lockout *lockout.Config
	// lockoutFirst registers lockout BEFORE mfa, which is what
	// NewFromConfig does (from_config.go wires lockout at :493 and mfa at
	// :513). The zero value registers mfa first, the ordering a
	// hand-built stack usually has.
	lockoutFirst bool
	// satisfiesMFA flips magic-link's own second-factor policy.
	satisfiesMFA bool
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

func newStack(t *testing.T, opts stackOpts) (*stack, func()) {
	t.Helper()

	mailer := &captureMailer{}
	b := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).
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
	b = b.WithPlugin(magiclink.New(magiclink.Config{
		Mailer:       mailer,
		LinkBaseURL:  "https://example.test/magic",
		SatisfiesMFA: opts.satisfiesMFA,
	}))

	ya, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)

	jar, _ := cookiejar.New(nil)
	return &stack{srv: srv, mailer: mailer, cookies: &http.Client{Jar: jar}}, srv.Close
}

// noRedirect never follows a redirect and carries no jar, so Set-Cookie is
// observable verbatim on the response.
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
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

// verifyBody is the union /magic-link/verify can answer with.
type verifyBody struct {
	User *struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	RequireMfa       bool   `json:"require_mfa"`
	PendingSessionID string `json:"pending_session_id"`
}

func decode(t *testing.T, res *http.Response) verifyBody {
	t.Helper()
	defer res.Body.Close()
	var out verifyBody
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func sessionCookie(res *http.Response) string {
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			return c.Value
		}
	}
	return ""
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

	// Confirm with the PREVIOUS step's code — still inside the server's ±1-step
	// acceptance window, so enrolment completes normally. Confirming with the
	// CURRENT step's code would spend that step (TOTP codes are single-use, see
	// domain.TOTPSecret.LastUsedStep) and the login code these tests mint
	// moments later would be refused as a replay of it.
	code, err := totp.GenerateCode(setup.Secret, time.Now().Add(-30*time.Second))
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

// link requests a magic link and returns the raw token it carries.
func (s *stack) link(t *testing.T) string {
	t.Helper()
	res := s.post(t, http.DefaultClient, "/api/auth/magic-link/send", map[string]string{
		"email": testEmail,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("magic-link/send: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	_, link, ok := s.mailer.last()
	if !ok {
		t.Fatalf("no magic link was mailed")
	}
	return tokenFromLink(link)
}

func (s *stack) verify(t *testing.T, token string) *http.Response {
	t.Helper()
	return s.post(t, noRedirect(), "/api/auth/magic-link/verify", map[string]string{
		"token": token,
	})
}

// --- MFA step-up --------------------------------------------------------

// TestVerify_TOTPEnrolled_StepsUp is the regression test: before the fix
// this call handed the user a session cookie on the strength of an email
// link alone, silently voiding their second factor.
func TestVerify_TOTPEnrolled_StepsUp(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true})
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	res := s.verify(t, s.link(t))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d (%s)", res.StatusCode, drain(res))
	}
	if got := res.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("challenge response set a cookie: %q", got)
	}
	first := decode(t, res)
	if !first.RequireMfa || first.PendingSessionID == "" {
		t.Fatalf("expected require_mfa + pending_session_id, got %+v", first)
	}
	if first.User != nil {
		t.Errorf("challenge response must not carry the user")
	}

	// The challenge completes at the EXISTING cookie endpoint.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	res = s.post(t, noRedirect(), "/api/auth/mfa/verify", map[string]string{
		"pending_session_id": first.PendingSessionID,
		"code":               code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mfa/verify: %d (%s)", res.StatusCode, drain(res))
	}
	if sessionCookie(res) == "" {
		t.Fatalf("completing the challenge issued no session cookie")
	}
	res.Body.Close()
}

// TestVerify_CompletionDoesNotLoop: the completion emits its own
// login.succeeded, which mfa's gate sees too. Without the MetaMFAVerified
// marker the gate would mint another challenge and the client would step up
// forever.
func TestVerify_CompletionDoesNotLoop(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true})
	defer stop()

	s.register(t)
	secret := s.enrolTOTP(t)

	first := decode(t, s.verify(t, s.link(t)))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	res := s.post(t, noRedirect(), "/api/auth/mfa/verify", map[string]string{
		"pending_session_id": first.PendingSessionID,
		"code":               code,
	})
	body := drain(res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mfa/verify: %d (%s)", res.StatusCode, body)
	}
	if bytes.Contains([]byte(body), []byte("pending_session_id")) {
		t.Fatalf("completion handed back another challenge: %s", body)
	}
}

// TestVerify_NoTOTP_UnchangedSingleLeg: a user with no second factor must
// see exactly the old response — user body plus a session cookie.
func TestVerify_NoTOTP_UnchangedSingleLeg(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true})
	defer stop()

	s.register(t)
	res := s.verify(t, s.link(t))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d (%s)", res.StatusCode, drain(res))
	}
	if sessionCookie(res) == "" {
		t.Fatalf("expected a session cookie")
	}
	out := decode(t, res)
	if out.RequireMfa || out.User == nil || out.User.Email != testEmail {
		t.Fatalf("unexpected body: %+v", out)
	}
}

// TestVerify_NoPluginsUnchanged: a deployment wiring neither mfa nor
// lockout must be behaviourally identical to before.
func TestVerify_NoPluginsUnchanged(t *testing.T) {
	s, stop := newStack(t, stackOpts{})
	defer stop()

	s.register(t)
	res := s.verify(t, s.link(t))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d (%s)", res.StatusCode, drain(res))
	}
	if sessionCookie(res) == "" {
		t.Fatalf("expected a session cookie")
	}
	out := decode(t, res)
	if out.RequireMfa || out.User == nil {
		t.Fatalf("unexpected body: %+v", out)
	}
}

// TestVerify_SatisfiesMFA_SkipsStepUp: the opt-out is a real switch, and
// the login still completes in one leg for a TOTP-enrolled user.
func TestVerify_SatisfiesMFA_SkipsStepUp(t *testing.T) {
	s, stop := newStack(t, stackOpts{mfa: true, satisfiesMFA: true})
	defer stop()

	s.register(t)
	s.enrolTOTP(t)

	res := s.verify(t, s.link(t))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d (%s)", res.StatusCode, drain(res))
	}
	if sessionCookie(res) == "" {
		t.Fatalf("expected a session cookie")
	}
	if out := decode(t, res); out.RequireMfa {
		t.Fatalf("SatisfiesMFA=true must not challenge: %+v", out)
	}
}

// --- lockout ------------------------------------------------------------

// TestVerify_LockedAccountRefused_BothOrders: a locked account must not
// obtain a session through a magic link, whichever order mfa and lockout
// were registered in.
func TestVerify_LockedAccountRefused_BothOrders(t *testing.T) {
	for _, lockoutFirst := range []bool{false, true} {
		s, stop := newStack(t, stackOpts{
			mfa:          true,
			lockout:      &lockout.Config{MaxAttempts: 2},
			lockoutFirst: lockoutFirst,
		})

		s.register(t)
		token := s.link(t)
		lockOut(t, s, 2)

		res := s.verify(t, token)
		if res.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("lockoutFirst=%v: expected 429, got %d (%s)", lockoutFirst, res.StatusCode, drain(res))
		}
		if got := res.Header.Get("Set-Cookie"); got != "" {
			t.Fatalf("lockoutFirst=%v: blocked login set a cookie: %q", lockoutFirst, got)
		}
		res.Body.Close()
		stop()
	}
}

// TestVerify_MFACompletionClearsLockout_BothOrders: finishing the step-up
// is what clears the failure counter. With mfa registered first the gate
// short-circuits the password-time login.succeeded, so only the marked
// completion event can do it; with lockout first the counter must not be
// cleared early either. Both orders must end at zero.
func TestVerify_MFACompletionClearsLockout_BothOrders(t *testing.T) {
	for _, lockoutFirst := range []bool{false, true} {
		s, stop := newStack(t, stackOpts{
			mfa:          true,
			lockout:      &lockout.Config{MaxAttempts: 5},
			lockoutFirst: lockoutFirst,
		})

		s.register(t)
		secret := s.enrolTOTP(t)
		lockOut(t, s, 3) // 3 < MaxAttempts: counter armed, no lock yet

		first := decode(t, s.verify(t, s.link(t)))
		if !first.RequireMfa {
			t.Fatalf("lockoutFirst=%v: expected a challenge, got %+v", lockoutFirst, first)
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("totp code: %v", err)
		}
		res := s.post(t, noRedirect(), "/api/auth/mfa/verify", map[string]string{
			"pending_session_id": first.PendingSessionID,
			"code":               code,
		})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("lockoutFirst=%v: mfa/verify: %d (%s)", lockoutFirst, res.StatusCode, drain(res))
		}
		res.Body.Close()

		// The counter is clear: two more failures (5 total, past
		// MaxAttempts) must NOT lock the account.
		lockOut(t, s, 2)
		res = s.post(t, noRedirect(), "/api/auth/login", map[string]string{
			"email": testEmail, "password": testPassword,
		})
		if res.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("lockoutFirst=%v: the completed MFA login did not clear the failure counter", lockoutFirst)
		}
		res.Body.Close()
		stop()
	}
}

// lockOut banks n failed password logins against the test account.
func lockOut(t *testing.T, s *stack, n int) {
	t.Helper()
	for range n {
		res := s.post(t, noRedirect(), "/api/auth/login", map[string]string{
			"email": testEmail, "password": "wrong-" + testPassword,
		})
		res.Body.Close()
	}
}
