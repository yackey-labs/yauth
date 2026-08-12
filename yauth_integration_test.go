package yauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func newTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	repo := memrepo.New()

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, func() { srv.Close() }
}

// jsonClient wraps an *http.Client with helpers that match the email-
// password plugin's request/response shapes.
type jsonClient struct{ c *http.Client }

func newJSONClient(t *testing.T) *jsonClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &jsonClient{c: &http.Client{Jar: jar}}
}

// registerAndSignIn creates an account and leaves its session cookie in the
// client's jar.
//
// /register is enumeration-neutral by default: it answers 200 with the same
// "pending verification" body whether or not the address was already taken, and
// it issues NO session — telling the two apart was an account-existence oracle.
// See emailpassword.Config.RevealRegistrationOutcome. Callers that want a
// signed-in client therefore register and then log in, which is what a client
// application does now.
func registerAndSignIn(t *testing.T, j *jsonClient, baseURL, email, password string) {
	t.Helper()
	res := j.post(t, baseURL+"/api/auth/register", map[string]string{
		"email": email, "password": password,
	})
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		t.Fatalf("register %s: %d (%s)", email, res.StatusCode, drain(res))
	}
	res.Body.Close()

	res = j.post(t, baseURL+"/api/auth/login", map[string]string{
		"email": email, "password": password,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login after register %s: %d (%s)", email, res.StatusCode, drain(res))
	}
	res.Body.Close()
}

func (j *jsonClient) post(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := j.c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func (j *jsonClient) patch(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := j.c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func (j *jsonClient) get(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	res, err := j.c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func drain(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func TestEmailPasswordEndToEnd(t *testing.T) {
	srv, stop := newTestServer(t)
	defer stop()

	cl := newJSONClient(t)
	const email = "alice@example.com"
	const oldPW = "correct horse battery staple"
	const newPW = "another long sufficient password 123"

	// 1. register + sign in. /register is enumeration-neutral: it answers 200
	//    with the same body whether or not the address was free and issues no
	//    session, so the client signs in afterwards (see
	//    emailpassword.Config.RevealRegistrationOutcome).
	registerAndSignIn(t, cl, srv.URL, email, oldPW)

	// 2. /session via the cookie set by the sign-in
	res := cl.get(t, srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session after register: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var sessBody struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&sessBody); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	res.Body.Close()
	if sessBody.User.Email != email {
		t.Fatalf("session: expected %q, got %q", email, sessBody.User.Email)
	}

	// 3. logout
	res = cl.post(t, srv.URL+"/api/auth/logout", struct{}{})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: expected 204, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 4. /session after logout → 401
	res = cl.get(t, srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after logout: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 5. login again
	res = cl.post(t, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": oldPW,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 6. change password
	res = cl.post(t, srv.URL+"/api/auth/change-password", map[string]string{
		"current_password": oldPW,
		"new_password":     newPW,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("change-password: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 7. /session still works (we re-issued)
	res = cl.get(t, srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session after change-password: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 8. logout, then re-login with new password
	res = cl.post(t, srv.URL+"/api/auth/logout", struct{}{})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout #2: expected 204, got %d", res.StatusCode)
	}
	res.Body.Close()

	res = cl.post(t, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": oldPW,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login w/ old pw: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	res = cl.post(t, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": newPW,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login w/ new pw: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// captureMailer records every link / event passed to the Mailer so
// tests can assert against the deliveries.
type captureMailer struct {
	mu sync.Mutex

	verifications []capturedMail
	resets        []capturedMail
	exists        []string
}

type capturedMail struct {
	email string
	link  string
}

func (m *captureMailer) SendVerification(_ context.Context, email, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifications = append(m.verifications, capturedMail{email: email, link: link})
	return nil
}

func (m *captureMailer) SendPasswordReset(_ context.Context, email, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resets = append(m.resets, capturedMail{email: email, link: link})
	return nil
}

func (m *captureMailer) SendAccountExists(_ context.Context, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exists = append(m.exists, email)
	return nil
}

func (m *captureMailer) lastVerification() (capturedMail, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.verifications) == 0 {
		return capturedMail{}, false
	}
	return m.verifications[len(m.verifications)-1], true
}

func (m *captureMailer) lastReset() (capturedMail, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.resets) == 0 {
		return capturedMail{}, false
	}
	return m.resets[len(m.resets)-1], true
}

// newTestServerWithMailer returns a server whose email-password plugin
// is configured with the supplied Mailer. HIBP is disabled so the
// tests do not make outbound requests.
func newTestServerWithMailer(t *testing.T, mailer emailpassword.Mailer) (*httptest.Server, func()) {
	t.Helper()

	repo := memrepo.New()

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength:        8,
			Mailer:                   mailer,
			HIBPCheck:                false,
			HIBPCheckSet:             true,
			VerificationLinkBaseURL:  "https://app.example.com/verify",
			PasswordResetLinkBaseURL: "https://app.example.com/reset",
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, func() { srv.Close() }
}

// extractToken pulls the ?token=... value from a captured link.
func extractToken(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link %q: %v", link, err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("link %q has no token", link)
	}
	return tok
}

func TestVerifyEmail_RoundTrip(t *testing.T) {
	mailer := &captureMailer{}
	srv, stop := newTestServerWithMailer(t, mailer)
	defer stop()

	cl := newJSONClient(t)
	const email = "verify@example.com"
	const password = "correct horse battery staple"

	registerAndSignIn(t, cl, srv.URL, email, password)

	mail, ok := mailer.lastVerification()
	if !ok {
		t.Fatal("no verification email captured")
	}
	if mail.email != email {
		t.Fatalf("verification email recipient: want %q, got %q", email, mail.email)
	}

	token := extractToken(t, mail.link)
	res := cl.post(t, srv.URL+"/api/auth/verify-email", map[string]string{"token": token})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify-email: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Replay must fail.
	res = cl.post(t, srv.URL+"/api/auth/verify-email", map[string]string{"token": token})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("verify-email replay: want 401, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestForgotPassword_ResetPassword_RoundTrip(t *testing.T) {
	mailer := &captureMailer{}
	srv, stop := newTestServerWithMailer(t, mailer)
	defer stop()

	cl := newJSONClient(t)
	const email = "forgot@example.com"
	const oldPW = "correct horse battery staple"
	const newPW = "another sufficient pw 12345"

	registerAndSignIn(t, cl, srv.URL, email, oldPW)

	res := cl.post(t, srv.URL+"/api/auth/forgot-password", map[string]string{"email": email})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	mail, ok := mailer.lastReset()
	if !ok {
		t.Fatal("no reset email captured")
	}
	token := extractToken(t, mail.link)

	res = cl.post(t, srv.URL+"/api/auth/reset-password", map[string]string{
		"token":    token,
		"password": newPW,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reset-password: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Old password fails, new one works.
	cl2 := newJSONClient(t)
	res = cl2.post(t, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": oldPW,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login w/ old pw after reset: want 401, got %d", res.StatusCode)
	}
	res.Body.Close()

	res = cl2.post(t, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": newPW,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login w/ new pw: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Replay reset must fail.
	res = cl2.post(t, srv.URL+"/api/auth/reset-password", map[string]string{
		"token":    token,
		"password": newPW,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reset-password replay: want 401, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestForgotPassword_UnknownEmail_DoesNotLeak(t *testing.T) {
	mailer := &captureMailer{}
	srv, stop := newTestServerWithMailer(t, mailer)
	defer stop()

	cl := newJSONClient(t)
	res := cl.post(t, srv.URL+"/api/auth/forgot-password", map[string]string{"email": "ghost@example.com"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password unknown email: want 200, got %d", res.StatusCode)
	}
	res.Body.Close()
	if _, ok := mailer.lastReset(); ok {
		t.Fatal("reset mail sent for unknown email")
	}
}

func TestResendVerification_AlreadyVerified_DoesNotLeak(t *testing.T) {
	mailer := &captureMailer{}
	srv, stop := newTestServerWithMailer(t, mailer)
	defer stop()

	cl := newJSONClient(t)
	const email = "resend@example.com"
	registerAndSignIn(t, cl, srv.URL, email, "correct horse battery staple")

	// Verify the email so subsequent resend is a no-op.
	mail, ok := mailer.lastVerification()
	if !ok {
		t.Fatal("no verification email")
	}
	res := cl.post(t, srv.URL+"/api/auth/verify-email", map[string]string{
		"token": extractToken(t, mail.link),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify-email: %d", res.StatusCode)
	}
	res.Body.Close()

	mailer.mu.Lock()
	beforeCount := len(mailer.verifications)
	mailer.mu.Unlock()

	res = cl.post(t, srv.URL+"/api/auth/resend-verification", map[string]string{"email": email})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("resend-verification: %d", res.StatusCode)
	}
	res.Body.Close()

	mailer.mu.Lock()
	afterCount := len(mailer.verifications)
	mailer.mu.Unlock()
	if afterCount != beforeCount {
		t.Fatalf("resend-verification on verified account sent mail: before=%d after=%d", beforeCount, afterCount)
	}
}

func TestRegister_RejectsShortPassword(t *testing.T) {
	srv, stop := newTestServer(t)
	defer stop()

	cl := newJSONClient(t)
	res := cl.post(t, srv.URL+"/api/auth/register", map[string]string{
		"email":    "bob@example.com",
		"password": "short",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// TestRegister_DuplicateEmail_DoesNotLeak verifies that registering an
// email that already has an account returns a 200 + "pending
// verification" response shape — the same shape a fresh registration
// produces. This blocks email enumeration via /register.
func TestRegister_DuplicateEmail_DoesNotLeak(t *testing.T) {
	srv, stop := newTestServer(t)
	defer stop()

	cl := newJSONClient(t)
	body := map[string]string{
		"email":    "carol@example.com",
		"password": "correct horse battery staple",
	}
	res := cl.post(t, srv.URL+"/api/auth/register", body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first register: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Second registration with the SAME email must NOT return 409.
	cl2 := newJSONClient(t)
	res = cl2.post(t, srv.URL+"/api/auth/register", body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("dup register: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var pending struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(res.Body).Decode(&pending); err != nil {
		t.Fatalf("decode pending response: %v", err)
	}
	res.Body.Close()
	if pending.Status != "pending_verification" {
		t.Fatalf("status: want 'pending_verification', got %q", pending.Status)
	}

	// And the second client's cookie jar must contain NO session
	// cookie — the dup branch must not authenticate the caller.
	srvURL, _ := url.Parse(srv.URL)
	for _, c := range cl2.c.Jar.Cookies(srvURL) {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Fatalf("dup register leaked a session cookie: %v", c)
		}
	}
}

// newTestServerWithConfig is a thin wrapper over the default builder that
// lets a test override yauth.YAuthConfig (allow_signups,
// auto_admin_first_user, …) before Build. Uses a per-test in-memory DSN
// so the AutoAdminFirstUser path sees a truly empty user table.
func newTestServerWithConfig(t *testing.T, customize func(c *yauth.YAuthConfig)) (*httptest.Server, func()) {
	t.Helper()

	repo := memrepo.New()

	cfg := yauth.NewDefaultConfig()
	if customize != nil {
		customize(&cfg)
	}
	ya, err := yauth.New(repo, cfg).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, func() { srv.Close() }
}

func TestPatchMe_UpdatesDisplayName(t *testing.T) {
	srv, stop := newTestServer(t)
	defer stop()

	cl := newJSONClient(t)
	registerAndSignIn(t, cl, srv.URL, "patch@example.com", "correct horse battery staple")

	res := cl.patch(t, srv.URL+"/api/auth/me", map[string]any{
		"display_name": "Patch User",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /me: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var body struct {
		User struct {
			DisplayName *string `json:"display_name"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	if body.User.DisplayName == nil || *body.User.DisplayName != "Patch User" {
		t.Fatalf("display_name not updated: %+v", body.User.DisplayName)
	}
}

func TestPatchMe_RequiresAuth(t *testing.T) {
	srv, stop := newTestServer(t)
	defer stop()

	cl := newJSONClient(t)
	res := cl.patch(t, srv.URL+"/api/auth/me", map[string]any{"display_name": "x"})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PATCH /me without auth: want 401, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestRegister_AllowSignupsFalse_Returns403(t *testing.T) {
	srv, stop := newTestServerWithConfig(t, func(c *yauth.YAuthConfig) {
		c.AllowSignups = false
	})
	defer stop()

	cl := newJSONClient(t)
	res := cl.post(t, srv.URL+"/api/auth/register", map[string]string{
		"email":    "blocked@example.com",
		"password": "correct horse battery staple",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("register w/ signups disabled: want 403, got %d (%s)", res.StatusCode, drain(res))
	}
	// Errors are now huma-native RFC 9457 problem+json ({type,title,status,
	// detail}); the legacy {"error":{"code:"SIGNUPS_DISABLED"}} body became a
	// 403 problem+json carrying the message as "detail". The 403 status — the
	// security-relevant signal that signups are blocked — is unchanged.
	var body struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	if body.Status != http.StatusForbidden {
		t.Fatalf("problem+json status: want 403, got %d", body.Status)
	}
	if body.Detail != "public registration is disabled" {
		t.Fatalf("problem+json detail: want %q, got %q", "public registration is disabled", body.Detail)
	}
}

func TestRegister_AutoAdminFirstUser(t *testing.T) {
	srv, stop := newTestServerWithConfig(t, func(c *yauth.YAuthConfig) {
		c.AutoAdminFirstUser = true
	})
	defer stop()

	cl1 := newJSONClient(t)
	registerAndSignIn(t, cl1, srv.URL, "first@example.com", "correct horse battery staple")
	res := cl1.get(t, srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session first: %d", res.StatusCode)
	}
	var firstBody struct {
		User struct {
			Role string `json:"role"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&firstBody); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	res.Body.Close()
	if firstBody.User.Role != "admin" {
		t.Fatalf("first user role: want admin, got %q", firstBody.User.Role)
	}

	cl2 := newJSONClient(t)
	registerAndSignIn(t, cl2, srv.URL, "second@example.com", "correct horse battery staple")
	res = cl2.get(t, srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session second: %d", res.StatusCode)
	}
	var secondBody struct {
		User struct {
			Role string `json:"role"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&secondBody); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	res.Body.Close()
	if secondBody.User.Role != "user" {
		t.Fatalf("second user role: want user, got %q", secondBody.User.Role)
	}
}
