package emailpassword_test

// POST /login answers the question "does this address belong to a banned,
// offboarded or not-yet-started account here?" BEFORE it ever looks at the
// password.
//
// registerLogin (handlers.go) loads the user, then refuses Banned with 403
// "account suspended", SuspendedAt with 403 "account is deactivated" and
// Staged with 403 "account is not active yet" — and only after all three does
// it call GetPasswordByUserID and auth.VerifyPassword. An unknown address, and
// a known address with the wrong password, both get 401 "invalid email or
// password". So an anonymous caller who supplies a deliberately WRONG password
// still learns, from the status and the body alone, both that the account
// exists and what administrative state it is in — an offboarding and
// disciplinary oracle over any address the caller cares to guess.
//
// The same ordering leaks a second channel: the 403 branches return before any
// Argon2id work happens, while both 401 branches pay a full DummyVerify /
// VerifyPassword at the configured cost, so the timing says it again even if
// the bodies were unified.
//
// The fix is ordering, not silence — the three distinct 403s are a real part of
// the contract for a caller who proves they hold the credential. The POSITIVE
// CONTROL below asserts exactly that: with the CORRECT password each of the
// three states still produces its own distinct 403, and a healthy account
// still logs in and gets a session cookie.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const oraclePassword = "correct horse battery staple"

func newLoginOracleServer(t *testing.T) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.SessionTTL = time.Hour
	ya, err := yauth.New(r, cfg).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// seedAccount registers email and applies one administrative state to it.
func seedAccount(t *testing.T, srv *httptest.Server, r repo.Repository, email, state string) {
	t.Helper()
	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email": email, "password": oraclePassword,
	})
	body := drain(res)
	if res.StatusCode >= 400 {
		t.Fatalf("seed %s: register returned %d %s", email, res.StatusCode, body)
	}
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("seed %s: GetUserByEmail: %v", email, err)
	}

	now := time.Now().UTC()
	var changes domain.UpdateUser
	switch state {
	case "banned":
		banned := true
		reason := "incident"
		reasonP := &reason
		changes = domain.UpdateUser{Banned: &banned, BannedReason: &reasonP, UpdatedAt: &now}
	case "suspended":
		at := now
		atP := &at
		changes = domain.UpdateUser{SuspendedAt: &atP, UpdatedAt: &now}
	case "staged":
		at := now.Add(72 * time.Hour)
		atP := &at
		changes = domain.UpdateUser{ActivatesAt: &atP, UpdatedAt: &now}
	case "healthy":
		return
	default:
		t.Fatalf("unknown state %q", state)
	}
	if _, err := r.UpdateUser(context.Background(), u.ID, changes); err != nil {
		t.Fatalf("seed %s: UpdateUser: %v", email, err)
	}
}

// loginObservation is everything an anonymous caller can see about one /login
// response. Anything that differs between the states IS the oracle.
type loginObservation struct {
	status     int
	body       string
	hasSession bool
}

func observeLogin(t *testing.T, srv *httptest.Server, email, password string) loginObservation {
	t.Helper()
	res := postJSON(t, srv.URL+"/api/auth/login", map[string]any{
		"email": email, "password": password,
	})
	obs := loginObservation{status: res.StatusCode}
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			obs.hasSession = true
		}
	}
	obs.body = drain(res)
	return obs
}

// TestLogin_DoesNotRevealAccountStateBeforePasswordVerification is the
// regression: with a WRONG password, a banned, an offboarded, a staged and a
// nonexistent address must be indistinguishable.
func TestLogin_DoesNotRevealAccountStateBeforePasswordVerification(t *testing.T) {
	srv, r := newLoginOracleServer(t)

	seedAccount(t, srv, r, "banned@corp.example", "banned")
	seedAccount(t, srv, r, "suspended@corp.example", "suspended")
	seedAccount(t, srv, r, "staged@corp.example", "staged")

	const wrong = "this-is-not-the-password"
	baseline := observeLogin(t, srv, "nobody@corp.example", wrong)
	if baseline.status != http.StatusUnauthorized {
		t.Fatalf("precondition: an unknown address must get 401, got %d %s", baseline.status, baseline.body)
	}

	for _, tc := range []struct {
		state string
		email string
	}{
		{"banned", "banned@corp.example"},
		{"suspended", "suspended@corp.example"},
		{"staged", "staged@corp.example"},
	} {
		got := observeLogin(t, srv, tc.email, wrong)
		if got.status != baseline.status {
			t.Errorf("%s account is distinguishable by status on a WRONG password: got %d, unknown address got %d",
				tc.state, got.status, baseline.status)
		}
		if got.body != baseline.body {
			t.Errorf("%s account is distinguishable by body on a WRONG password:\n  got      %s\n  unknown  %s",
				tc.state, got.body, baseline.body)
		}
		if got.hasSession != baseline.hasSession {
			t.Errorf("%s account is distinguishable by Set-Cookie on a WRONG password: got=%v unknown=%v",
				tc.state, got.hasSession, baseline.hasSession)
		}
	}
}

// TestLogin_AccountStateStillReportedToTheCredentialHolder is the POSITIVE
// CONTROL for the test above: the three distinct 403s are the contract for a
// caller who proved they hold the password, and a healthy account still signs
// in. A "fix" that collapses every refusal into 401, or that stops refusing at
// all, fails here.
func TestLogin_AccountStateStillReportedToTheCredentialHolder(t *testing.T) {
	srv, r := newLoginOracleServer(t)

	seedAccount(t, srv, r, "banned@corp.example", "banned")
	seedAccount(t, srv, r, "suspended@corp.example", "suspended")
	seedAccount(t, srv, r, "staged@corp.example", "staged")
	seedAccount(t, srv, r, "healthy@corp.example", "healthy")

	for _, tc := range []struct {
		email  string
		detail string
	}{
		{"banned@corp.example", "account suspended"},
		{"suspended@corp.example", "account is deactivated"},
		{"staged@corp.example", "account is not active yet"},
	} {
		got := observeLogin(t, srv, tc.email, oraclePassword)
		if got.status != http.StatusForbidden {
			t.Errorf("%s with the CORRECT password: expected 403, got %d %s", tc.email, got.status, got.body)
		}
		if !strings.Contains(got.body, tc.detail) {
			t.Errorf("%s with the CORRECT password: expected the %q refusal, got %s", tc.email, tc.detail, got.body)
		}
		if got.hasSession {
			t.Errorf("%s was issued a session cookie despite the refusal", tc.email)
		}
	}

	healthy := observeLogin(t, srv, "healthy@corp.example", oraclePassword)
	if healthy.status != http.StatusOK {
		t.Fatalf("control: a healthy account must still log in, got %d %s", healthy.status, healthy.body)
	}
	if !healthy.hasSession {
		t.Fatalf("control: a healthy login must set a session cookie, got %s", healthy.body)
	}
}
