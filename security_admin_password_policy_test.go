package yauth_test

// security_admin_password_policy_test.go — the deployment password policy on
// the admin provisioning surface.
//
// A deployment states its credential rules once, in
// email_password.password_policy. from_config.go maps that block onto
// passwordpolicy.Policy and hands it to plugins/emailpassword, which runs
// Policy.Violations inside validatePasswordComplexity on /register,
// /change-password and /reset-password (handlers.go:297, :948, :1494), and to
// the startup bootstrap path via effectiveBootstrapPolicy (from_config.go:90).
//
// POST /admin/users is the fourth way a password gets into the database, and
// it is the only one that never sees the policy. from_config.go builds the
// plugin as admin.New() — a constructor that takes no arguments at all
// (plugins/admin/plugin.go) — so the handler at registerCreateUser has nothing
// to check against: it takes the admin-supplied password verbatim, or calls
// generateTempPassword(), and goes straight to auth.HashPassword. The only
// floor is the hard-coded `minLength:"8"` JSON-schema tag on the request
// struct, which has no relationship to what the operator configured.
//
// That breaks in both directions at once:
//
//   - Inbound: under min_length:16 + require_special + disallow_common, the
//     byte-identical password that /register rejects with 400 is accepted by
//     /admin/users with 201, and a weak argon2id credential is persisted for a
//     real, immediately loginable account.
//
//   - Outbound: generateTempPassword draws from an alphabet with NO special
//     character and is a fixed 24 chars, so under require_special — or any
//     min_length above 24 — the server issues a credential its OWN configured
//     policy rejects, while its doc comment claims it "passes the default
//     policy". (It is not rejected on use: /change-password runs the policy
//     over new_password only, never the current one. The defect is that the
//     server states a credential rule and then violates it itself, and that a
//     deployment which raised min_length silently gets shorter temp passwords
//     than it configured.)
//
// These tests drive real HTTP through a NewFromConfig instance so the assertion
// is on the deployment contract (the yaml policy governs admin provisioning),
// not on any particular constructor shape. Every refusal is paired with a
// positive control proving admin provisioning still works, and with a contrast
// control proving the same policy really is enforced on /register — so a
// "fix" that simply broke POST /admin/users could not pass.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// strictPasswordPolicy is the policy the deployment below configures, spelled
// as the passwordpolicy.Policy that effectiveBootstrapPolicy would derive from
// the same yaml block. Tests check server-produced passwords against THIS.
func strictPasswordPolicy() passwordpolicy.Policy {
	return passwordpolicy.Policy{
		MinLength:      16,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		DisallowCommon: true,
	}
}

// adminPolicyEnv is a yauth built from a yaml-shaped config with a strict
// email_password.password_policy AND the admin plugin enabled — the exact
// deployment shape described in the finding.
type adminPolicyEnv struct {
	srv   *httptest.Server
	repo  *memrepo.Repo
	admin string // session cookie value for a role=admin user
}

func newAdminPolicyEnv(t *testing.T) *adminPolicyEnv {
	t.Helper()

	c := yauthcfg.Default()
	c.Database.Driver = "memory"
	c.Database.DSN = ""

	ep := &c.Plugins.EmailPassword
	ep.Enabled = true
	hibpOff := false
	ep.HIBPCheck = &hibpOff // no network in tests; the policy alone is the subject
	ep.PasswordPolicy = yauthcfg.PasswordPolicyConfig{
		MinLength:      16,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		DisallowCommon: true,
	}
	c.Plugins.Admin.Enabled = true

	r := memrepo.New()
	ya, err := yauth.NewFromConfig(context.Background(), c, yauth.WithRepo(r))
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	srv := httptest.NewServer(ya.Router())
	t.Cleanup(srv.Close)

	now := time.Now().UTC()
	adminUser, err := r.CreateUser(context.Background(), domain.NewUser{
		ID:            uuid.NewString(),
		Email:         "admin@example.com",
		Role:          "admin",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	raw, _, err := auth.IssueSession(context.Background(), r, adminUser.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue admin session: %v", err)
	}
	return &adminPolicyEnv{srv: srv, repo: r, admin: raw}
}

// createUser POSTs /admin/users as the seeded admin.
func (e *adminPolicyEnv) createUser(t *testing.T, body map[string]any) (int, string) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/admin/users", strings.NewReader(string(buf)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: e.admin})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return res.StatusCode, string(b)
}

// register POSTs /register anonymously — the contrast control.
func (e *adminPolicyEnv) register(t *testing.T, email, password string) (int, string) {
	t.Helper()
	buf, _ := json.Marshal(map[string]any{"email": email, "password": password})
	res, err := http.Post(e.srv.URL+"/register", "application/json", strings.NewReader(string(buf)))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return res.StatusCode, string(b)
}

// credentialFor returns the stored argon2id hash for email, or "" when the user
// or the credential does not exist. Used to assert on the PERSISTED artefact
// rather than on a status code.
func (e *adminPolicyEnv) credentialFor(t *testing.T, email string) string {
	t.Helper()
	u, err := e.repo.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		return ""
	}
	pw, err := e.repo.GetPasswordByUserID(context.Background(), u.ID)
	if err != nil || pw == nil {
		return ""
	}
	return pw.PasswordHash
}

// TestAdminCreateUser_RejectsPasswordTheDeploymentPolicyRejects is the inbound
// half. "Passw0rd" is 8 characters, has no special character and is a top-100
// breached password: three separate violations of the configured policy.
//
// The contrast control fires first — the SAME string on /register — so a
// failure here can only mean the admin surface is the one that skipped the
// check.
func TestAdminCreateUser_RejectsPasswordTheDeploymentPolicyRejects(t *testing.T) {
	env := newAdminPolicyEnv(t)

	const weak = "Passw0rd"

	// CONTRAST CONTROL: the policy is real and is enforced on the
	// self-service surface of this very same instance.
	if code, body := env.register(t, "selfserve@example.com", weak); code != http.StatusBadRequest {
		t.Fatalf("/register accepted %q with %d (%s) — the policy is not configured as this test assumes", weak, code, body)
	}
	if h := env.credentialFor(t, "selfserve@example.com"); h != "" {
		t.Fatalf("/register persisted a credential for a policy-violating password")
	}

	// The finding: the identical string through the admin surface.
	code, body := env.createUser(t, map[string]any{
		"email":    "contractor@example.com",
		"password": weak,
	})
	if code != http.StatusBadRequest {
		t.Errorf("POST /admin/users accepted %q: got %d, want 400\nbody: %s", weak, code, body)
	}
	if !strings.Contains(strings.ToLower(body), "16") && code == http.StatusBadRequest {
		t.Errorf("400 body should name the configured length requirement, got: %s", body)
	}

	// The artefact that matters: no credential was written for that account.
	if h := env.credentialFor(t, "contractor@example.com"); h != "" {
		ok, err := auth.VerifyPassword(weak, h)
		t.Fatalf("a credential for %q was persisted (verifies=%v err=%v) despite violating min_length:16, require_special and disallow_common",
			weak, ok, err)
	}
}

// TestAdminCreateUser_CompliantPasswordStillProvisions is the POSITIVE CONTROL
// for the test above: a password that satisfies the deployment policy must
// still create the account and store a working credential. Without this, a
// "fix" that rejected every admin-supplied password would pass.
func TestAdminCreateUser_CompliantPasswordStillProvisions(t *testing.T) {
	env := newAdminPolicyEnv(t)

	const good = "Str0ng-Provisioned-Pass!"
	if err := strictPasswordPolicy().Check(good); err != nil {
		t.Fatalf("test fixture is not policy-compliant: %v", err)
	}

	code, body := env.createUser(t, map[string]any{
		"email":    "goodhire@example.com",
		"password": good,
	})
	if code != http.StatusCreated {
		t.Fatalf("compliant password refused: %d\nbody: %s", code, body)
	}
	h := env.credentialFor(t, "goodhire@example.com")
	if h == "" {
		t.Fatal("no credential persisted for a compliant admin-provisioned user")
	}
	if ok, err := auth.VerifyPassword(good, h); err != nil || !ok {
		t.Fatalf("persisted credential does not verify: ok=%v err=%v", ok, err)
	}
}

// TestAdminCreateUser_GeneratedPasswordSatisfiesDeploymentPolicy is the
// outbound half: omit the password and the server generates one. A generated
// password that fails the deployment's own Check is the server violating the
// rule it publishes — and, for an install that raised min_length, a temp
// credential quietly weaker than the length it configured.
func TestAdminCreateUser_GeneratedPasswordSatisfiesDeploymentPolicy(t *testing.T) {
	env := newAdminPolicyEnv(t)

	code, body := env.createUser(t, map[string]any{"email": "tempcred@example.com"})
	if code != http.StatusCreated {
		t.Fatalf("create with generated password: %d\nbody: %s", code, body)
	}
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, body)
	}
	if out.Password == "" {
		t.Fatalf("expected a generated one-time password in the response, got: %s", body)
	}

	// POSITIVE CONTROL: whatever it generated must be the credential actually
	// stored, so this test can never be satisfied by returning a compliant
	// string the server did not persist.
	h := env.credentialFor(t, "tempcred@example.com")
	if ok, err := auth.VerifyPassword(out.Password, h); err != nil || !ok {
		t.Fatalf("returned one-time password does not verify against the stored hash: ok=%v err=%v", ok, err)
	}

	// The finding.
	if err := strictPasswordPolicy().Check(out.Password); err != nil {
		t.Fatalf("server generated a password its own policy rejects: %v (password %q)", err, out.Password)
	}
}
