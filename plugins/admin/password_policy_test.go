package admin_test

// password_policy_test.go — the breach half of the admin provisioning gate,
// plus the compatibility control for the zero admin.Config.
//
// POST /admin/users is the fourth place a password enters the database, and
// until admin.Config existed it was the only one that checked nothing: the
// handler took the admin-supplied string verbatim and went straight to
// auth.HashPassword, behind nothing but a hard-coded `minLength:"8"` schema
// tag. from_config now derives the gate from email_password.password_policy /
// hibp_check, so admin provisioning obeys the same rules as /register.
//
// The root-package test (security_admin_password_policy_test.go) covers the
// policy half end-to-end through NewFromConfig. What it cannot cover is HIBP,
// which needs a local stand-in for api.pwnedpasswords.com. These tests drive
// the same handler with an explicit Config:
//
//   - a breach hit must refuse with 422 (the status /register uses for HIBP, as
//     against 400 for a policy violation) and persist nothing;
//   - a breach-service OUTAGE must still provision — a HIBP failure that
//     blocked staff onboarding would be a worse outage than the weak password
//     it guards against, and fail-open is the contract emailpassword.Config
//     already documents;
//   - the zero Config — every builder-path admin.New() caller — must behave
//     exactly as before: no policy, and no outbound HIBP call at all.

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	"github.com/yackey-labs/yauth/plugins/admin"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newEnvWithConfig is newEnv with an explicit admin.Config.
func newEnvWithConfig(t *testing.T, cfg admin.Config) *testEnv {
	t.Helper()
	r := memrepo.New()
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(admin.New(cfg)).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return &testEnv{srv: srv, repo: r, stop: func() { srv.Close() }}
}

// credentialExists reports whether a credential was persisted for email — the
// artefact that matters, as against the status code alone.
func (e *testEnv) credentialExists(t *testing.T, email string) bool {
	t.Helper()
	u, err := e.repo.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		return false
	}
	pw, err := e.repo.GetPasswordByUserID(context.Background(), u.ID)
	return err == nil && pw != nil
}

// hibpRangeBody renders the range-API response for password: the 35-char
// uppercase SHA-1 suffix the k-anonymity checker searches for, with a breach
// count. Computing it here (rather than hard-coding a digest) keeps the fixture
// honest if the password string is ever edited.
func hibpRangeBody(password string, count int) string {
	sum := sha1.Sum([]byte(password))
	suffix := strings.ToUpper(hex.EncodeToString(sum[:]))[5:]
	return "0000000000000000000000000000000000A:1\r\n" + fmt.Sprintf("%s:%d\r\n", suffix, count)
}

// TestAdminCreateUser_BreachedPasswordRefused: a password the breach service
// reports as compromised is refused BEFORE the user row is written.
func TestAdminCreateUser_BreachedPasswordRefused(t *testing.T) {
	const breached = "Breached-Provisioning-1!"

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(hibpRangeBody(breached, 4213)))
	}))
	t.Cleanup(srv.Close)

	env := newEnvWithConfig(t, admin.Config{HIBPCheck: true, HIBPEndpoint: srv.URL + "/"})
	defer env.stop()
	tok := env.issueSession(t, env.seedUser(t, "admin@example.com", "admin").ID)

	res := env.do(t, http.MethodPost, "/api/auth/admin/users", tok, map[string]any{
		"email":    "breached@example.com",
		"password": breached,
	})
	body := drain(res)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("breached password accepted: %d (%s)", res.StatusCode, body)
	}
	if hits == 0 {
		t.Fatal("HIBP endpoint was never consulted")
	}
	if env.credentialExists(t, "breached@example.com") {
		t.Fatal("a credential was persisted for a known-breached password")
	}

	// POSITIVE CONTROL: a password the SAME service reports as clean still
	// provisions, so this guard cannot be satisfied by refusing everything.
	res = env.do(t, http.MethodPost, "/api/auth/admin/users", tok, map[string]any{
		"email":    "clean@example.com",
		"password": "Clean-Provisioning-9!", // different SHA-1 suffix → not in the body above
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("clean password refused: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	if !env.credentialExists(t, "clean@example.com") {
		t.Fatal("no credential persisted for a clean password")
	}
}

// TestAdminCreateUser_HIBPOutageFailsOpen pins the fail-open contract: a
// breach-service outage must not stop an operator onboarding staff.
func TestAdminCreateUser_HIBPOutageFailsOpen(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(dead.Close)

	env := newEnvWithConfig(t, admin.Config{HIBPCheck: true, HIBPEndpoint: dead.URL + "/"})
	defer env.stop()
	tok := env.issueSession(t, env.seedUser(t, "admin@example.com", "admin").ID)

	res := env.do(t, http.MethodPost, "/api/auth/admin/users", tok, map[string]any{
		"email":    "onboard@example.com",
		"password": "Outage-Provisioning-7!",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("HIBP outage blocked provisioning: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	if !env.credentialExists(t, "onboard@example.com") {
		t.Fatal("no credential persisted despite a 201")
	}
}

// TestAdminCreateUser_PolicyShapesGeneratedPassword is the outbound half at the
// plugin level: the one-time password is sized and shaped by the configured
// policy. The generator this replaced was a fixed 24 chars from an alphabet
// with no special character, so under this policy it produced a credential the
// deployment's own rules reject — twice over (length and class).
func TestAdminCreateUser_PolicyShapesGeneratedPassword(t *testing.T) {
	policy := passwordpolicy.Policy{MinLength: 32, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSpecial: true, DisallowCommon: true}
	env := newEnvWithConfig(t, admin.Config{PasswordPolicy: policy})
	defer env.stop()
	tok := env.issueSession(t, env.seedUser(t, "admin@example.com", "admin").ID)

	res := env.do(t, http.MethodPost, "/api/auth/admin/users", tok, map[string]any{"email": "temp@example.com"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d (%s)", res.StatusCode, drain(res))
	}
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	if err := policy.Check(out.Password); err != nil {
		t.Fatalf("generated password violates the configured policy: %v (pw=%q)", err, out.Password)
	}
	// POSITIVE CONTROL: the compliant string returned is the credential
	// actually stored, not a decoration.
	pw, err := env.repo.GetPasswordByUserID(context.Background(), out.User.ID)
	if err != nil || pw == nil {
		t.Fatalf("stored password: %+v err=%v", pw, err)
	}
	if ok, err := auth.VerifyPassword(out.Password, pw.PasswordHash); err != nil || !ok {
		t.Fatalf("returned password does not verify: ok=%v err=%v", ok, err)
	}
}

// TestAdminCreateUser_ZeroConfigUnchanged is the compatibility control for the
// builder-path `admin.New()` call sites: a zero Config imposes no policy and
// makes NO outbound HIBP call. (Defaulting HIBPCheck to true the way
// emailpassword.Config does would have every one of those call sites dialling
// api.pwnedpasswords.com from unit tests.) The endpoint below reports every
// password as breached and counts its callers, so a zero Config that had
// silently enabled the check would be caught by the hit counter even though
// fail-open would hide it from the status code.
func TestAdminCreateUser_ZeroConfigUnchanged(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(hibpRangeBody("Passw0rd", 99999)))
	}))
	t.Cleanup(srv.Close)

	env := newEnvWithConfig(t, admin.Config{HIBPEndpoint: srv.URL + "/"})
	defer env.stop()
	tok := env.issueSession(t, env.seedUser(t, "admin@example.com", "admin").ID)

	res := env.do(t, http.MethodPost, "/api/auth/admin/users", tok, map[string]any{
		"email": "legacy@example.com",
		// Weak by any policy — but this instance has configured none, and
		// silently imposing one on it is exactly the over-refusal this fix
		// avoids.
		"password": "Passw0rd",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("zero Config changed behaviour: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	if !env.credentialExists(t, "legacy@example.com") {
		t.Fatal("no credential persisted")
	}
	if hits != 0 {
		t.Fatalf("zero Config made %d outbound HIBP call(s); it must make none", hits)
	}
}
