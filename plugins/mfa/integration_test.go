package mfa_test

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
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

type testEnv struct {
	srv *httptest.Server
	cl  *http.Client
}

func newTestEnv(t *testing.T) (*testEnv, func()) {
	t.Helper()

	repo := memrepo.New()

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: "yauth-test"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		WithPlugin(mfaPlugin).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)

	jar, _ := cookiejar.New(nil)
	return &testEnv{srv: srv, cl: &http.Client{Jar: jar}}, func() { srv.Close() }
}

func (e *testEnv) post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, &buf)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := e.cl.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func (e *testEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	res, err := e.cl.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func (e *testEnv) delete(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, e.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	res, err := e.cl.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

// noCookieClient returns a client whose cookie jar is fresh — used to
// simulate an unauthenticated /verify call from a different browser.
func (e *testEnv) noCookieClient(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func drain(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
)

// register signs alice up — she gets a real session cookie since MFA
// hasn't been confirmed yet.
func (e *testEnv) register(t *testing.T) {
	t.Helper()
	res := e.post(t, "/api/auth/register", map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// setupAndConfirmMFA hits /totp/setup and /totp/confirm, returning the
// raw TOTP secret and the displayed backup codes.
func (e *testEnv) setupAndConfirmMFA(t *testing.T) (secret string, backupCodes []string) {
	t.Helper()
	res := e.post(t, "/api/auth/mfa/totp/setup", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("setup: %d (%s)", res.StatusCode, drain(res))
	}
	var setup struct {
		Secret      string   `json:"secret"`
		OTPAuthURL  string   `json:"otpauth_url"`
		BackupCodes []string `json:"backup_codes"`
	}
	if err := json.NewDecoder(res.Body).Decode(&setup); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	res.Body.Close()
	if setup.Secret == "" {
		t.Fatalf("setup: empty secret")
	}
	if setup.OTPAuthURL == "" {
		t.Fatalf("setup: empty otpauth_url")
	}
	if len(setup.BackupCodes) != 10 {
		t.Fatalf("setup: expected 10 backup codes, got %d", len(setup.BackupCodes))
	}

	res = e.post(t, "/api/auth/mfa/totp/confirm", map[string]string{
		"code": priorStepCode(t, setup.Secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("confirm: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	return setup.Secret, setup.BackupCodes
}

// totpStep is one RFC 6238 time step.
const totpStep = 30 * time.Second

// priorStepCode returns a code for the step BEFORE now — still inside the
// server's ±1-step acceptance window, so it confirms an enrolment normally.
//
// Tests use it so that a code minted at time.Now() straight afterwards belongs
// to a LATER step and is accepted. Confirming with the current step's code
// would spend that step (codes are single-use — see
// domain.TOTPSecret.LastUsedStep), and every follow-up call in the same
// 30-second window would then be refused as a replay. That is correct
// behaviour, not a test workaround: it is exactly what stops a confirming code
// from being turned around and replayed as a login.
func priorStepCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().Add(-totpStep))
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

// nextStepCode returns a code for the step AFTER now — also inside the
// server's +/-1-step acceptance window, so it authenticates normally. Tests
// that have already spent the current step reach for this: steps N-1, N and
// N+1 are the whole supply a test has, since it cannot advance the clock.
func nextStepCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().Add(totpStep))
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

// currentStepCode returns a code for the current step, for use as the
// X-MFA-Code step-up factor on the management routes.
func currentStepCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

// postStepUp / deleteStepUp are post/delete carrying the X-MFA-Code header the
// MFA management routes require once a factor is enrolled.
func (e *testEnv) postStepUp(t *testing.T, path string, body any, code string) *http.Response {
	t.Helper()
	return e.doWithStepUp(t, http.MethodPost, path, body, code)
}

func (e *testEnv) deleteStepUp(t *testing.T, path, code string) *http.Response {
	t.Helper()
	return e.doWithStepUp(t, http.MethodDelete, path, nil, code)
}

func (e *testEnv) doWithStepUp(t *testing.T, method, path string, body any, code string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req, err := http.NewRequest(method, e.srv.URL+path, &buf)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if code != "" {
		req.Header.Set(mfa.StepUpHeader, code)
	}
	res, err := e.cl.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func (e *testEnv) logout(t *testing.T) {
	t.Helper()
	res := e.post(t, "/api/auth/logout", struct{}{})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// --- the actual tests ----------------------------------------------------

func TestMFA_FullSetupConfirmLoginVerifyTOTP(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)
	env.logout(t)

	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)

	// generate a fresh code and verify
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// session cookie should now be set on this client; /session returns 200
	res = getWith(t, cl, env.srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session after verify: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

func TestMFA_VerifyWithBackupCode_ConsumesIt(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	_, codes := env.setupAndConfirmMFA(t)
	if len(codes) == 0 {
		t.Fatalf("no backup codes")
	}
	env.logout(t)

	// First login: consume backup code [0].
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               codes[0],
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify w/ backup: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// the backup-code count should now be 9 — auth via the cookie just set
	res = getWith(t, cl, env.srv.URL+"/api/auth/mfa/backup-codes")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("backup-codes count: %d (%s)", res.StatusCode, drain(res))
	}
	var count struct {
		Remaining int `json:"remaining"`
	}
	_ = json.NewDecoder(res.Body).Decode(&count)
	res.Body.Close()
	if count.Remaining != 9 {
		t.Fatalf("expected 9 unused, got %d", count.Remaining)
	}

	// Logout, login again — second attempt with the SAME backup code
	// must fail (single use).
	res = postJSONWith(t, cl, env.srv.URL+"/api/auth/logout", struct{}{})
	res.Body.Close()
	cl2 := env.noCookieClient(t)
	pid2 := env.loginExpectMFAWith(t, cl2)
	res = postJSONWith(t, cl2, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid2,
		"code":               codes[0],
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("re-use of backup code: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

func TestMFA_PendingSessionConsumedOnce(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)
	env.logout(t)

	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)

	// First verify succeeds.
	code, _ := totp.GenerateCode(secret, time.Now())
	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify #1: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Re-using the same pending_session_id with a new code must fail.
	cl2 := env.noCookieClient(t)
	code2, _ := totp.GenerateCode(secret, time.Now().Add(31*time.Second))
	res = postJSONWith(t, cl2, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               code2,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("verify reuse: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

func TestMFA_LoginWithoutVerifiedTOTP_StillIssuesSession(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	// setup but DO NOT confirm
	res := env.post(t, "/api/auth/mfa/totp/setup", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("setup: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	env.logout(t)

	cl := env.noCookieClient(t)
	body, _ := json.Marshal(map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r2, err := cl.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("login: %d (%s)", r2.StatusCode, drain(r2))
	}
	var lb map[string]any
	_ = json.NewDecoder(r2.Body).Decode(&lb)
	r2.Body.Close()
	if v, ok := lb["require_mfa"].(bool); ok && v {
		t.Fatalf("expected real session login (no require_mfa), got %v", lb)
	}
}

func TestMFA_DeleteRemovesTOTPAndBackupCodes(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, codes := env.setupAndConfirmMFA(t)
	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}

	// Removing the factor requires presenting it.
	res := env.deleteStepUp(t, "/api/auth/mfa/totp", currentStepCode(t, secret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// backup-codes count is now 0
	res = env.get(t, "/api/auth/mfa/backup-codes")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("backup-codes: %d (%s)", res.StatusCode, drain(res))
	}
	var count struct {
		Remaining int `json:"remaining"`
	}
	_ = json.NewDecoder(res.Body).Decode(&count)
	res.Body.Close()
	if count.Remaining != 0 {
		t.Fatalf("expected 0 unused after delete, got %d", count.Remaining)
	}

	// login again — should NOT require mfa now
	env.logout(t)
	cl := env.noCookieClient(t)
	body, _ := json.Marshal(map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r2, err := cl.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("login: %d (%s)", r2.StatusCode, drain(r2))
	}
	var lb map[string]any
	_ = json.NewDecoder(r2.Body).Decode(&lb)
	if v, ok := lb["require_mfa"].(bool); ok && v {
		t.Fatalf("expected normal login after totp delete, got %v", lb)
	}
}

func TestMFA_RegenerateBackupCodes_RotatesAndInvalidatesOld(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, oldCodes := env.setupAndConfirmMFA(t)

	// Reissuing recovery codes requires the current factor.
	res := env.postStepUp(t, "/api/auth/mfa/backup-codes/regenerate", nil, currentStepCode(t, secret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("regenerate: %d (%s)", res.StatusCode, drain(res))
	}
	var rb struct {
		BackupCodes []string `json:"backup_codes"`
	}
	if err := json.NewDecoder(res.Body).Decode(&rb); err != nil {
		t.Fatalf("decode regenerate: %v", err)
	}
	res.Body.Close()
	if len(rb.BackupCodes) != 10 {
		t.Fatalf("expected 10 new codes, got %d", len(rb.BackupCodes))
	}
	// new codes must differ from old
	old := map[string]bool{}
	for _, c := range oldCodes {
		old[c] = true
	}
	for _, c := range rb.BackupCodes {
		if old[c] {
			t.Fatalf("new backup code %q overlaps with old set", c)
		}
	}

	// logout, login → verify with an OLD code must fail
	env.logout(t)
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res = postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               oldCodes[0],
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old code accepted after regen: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

func TestMFA_NewRequiresEncryptionKey(t *testing.T) {
	if _, err := mfa.New(mfa.Config{}); err == nil {
		t.Fatalf("expected error on zero EncryptionKey")
	}
}

// --- helpers tied to the cl-passed variants -----------------------------

func (e *testEnv) loginExpectMFAWith(t *testing.T, cl *http.Client) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login (mfa): %d (%s)", res.StatusCode, drain(res))
	}
	var lb struct {
		RequireMfa       bool   `json:"require_mfa"`
		PendingSessionID string `json:"pending_session_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&lb); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	res.Body.Close()
	if !lb.RequireMfa || lb.PendingSessionID == "" {
		t.Fatalf("expected require_mfa+pending_session_id, got %+v", lb)
	}
	return lb.PendingSessionID
}

func postJSONWith(t *testing.T, cl *http.Client, url string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", "application/json")
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return res
}

func getWith(t *testing.T, cl *http.Client, url string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return res
}
