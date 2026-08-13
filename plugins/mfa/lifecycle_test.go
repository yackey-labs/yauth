// Regression suite for account lifecycle on the second leg of an MFA login.
//
// A login that requires MFA completes in two requests: /login (or /token)
// checks the password, then /mfa/verify (or /token/mfa) checks the code and
// mints the session. The challenge is valid for minutes, so the account state
// that passed on the first leg need not still hold on the second — an
// offboarding can land in between.
//
// bearer's /token/mfa leg re-ran the gates, and its comment says exactly why:
// "the state that passed at /token time may not hold any more". mfa's own
// /mfa/verify leg did not. It loaded the user ONLY to populate the response
// body, SWALLOWED the lookup error, and then issued a session unconditionally
// — so a user suspended between the two legs still got a Set-Cookie, and so
// did a user whose account had been deleted outright.
//
// bearer's leg was itself incomplete: it checked Banned and
// MustChangePassword but not SuspendedAt or ActivatesAt, which are the states
// SCIM `active:false` and a scheduled start actually set.
package mfa_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newTestEnvWithRepo mirrors newTestEnv but hands back the repo so a test can
// deprovision the account between the two legs of the login.
func newTestEnvWithRepo(t *testing.T) (*testEnv, repo.Repository) {
	t.Helper()
	r := memrepo.New()

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: "yauth-test"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{HIBPCheck: false, HIBPCheckSet: true})).
		WithPlugin(mfaPlugin).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	return &testEnv{srv: srv, cl: &http.Client{Jar: jar}}, r
}

func TestMFAVerify_RefusesAnAccountDeprovisionedMidLogin(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, r repo.Repository, userID string, now time.Time)
		what   string
	}{
		{
			name: "suspended",
			mutate: func(t *testing.T, r repo.Repository, userID string, now time.Time) {
				susp := &now
				if _, err := r.UpdateUser(context.Background(), userID,
					domain.UpdateUser{SuspendedAt: &susp, UpdatedAt: &now}); err != nil {
					t.Fatalf("suspend: %v", err)
				}
			},
			what: "an account suspended between the password leg and the code leg completed its login",
		},
		{
			name: "banned",
			mutate: func(t *testing.T, r repo.Repository, userID string, now time.Time) {
				banned := true
				if _, err := r.UpdateUser(context.Background(), userID,
					domain.UpdateUser{Banned: &banned, UpdatedAt: &now}); err != nil {
					t.Fatalf("ban: %v", err)
				}
			},
			what: "an account banned between the password leg and the code leg completed its login",
		},
		{
			name: "must-change-password",
			mutate: func(t *testing.T, r repo.Repository, userID string, now time.Time) {
				if err := r.SetUserMustChangePassword(context.Background(), userID, true); err != nil {
					t.Fatalf("set must-change: %v", err)
				}
			},
			what: "an account put under a forced password change completed its MFA login",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, r := newTestEnvWithRepo(t)
			env.register(t)
			secret, _ := env.setupAndConfirmMFA(t)
			env.logout(t)

			cl := env.noCookieClient(t)
			pid := env.loginExpectMFAWith(t, cl)

			// Offboard between the two legs — the real sequence.
			u, err := r.GetUserByEmail(context.Background(), testEmail)
			if err != nil || u == nil {
				t.Fatalf("load user: %v", err)
			}
			tc.mutate(t, r, u.ID, time.Now().UTC())

			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				t.Fatalf("generate code: %v", err)
			}
			res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
				"pending_session_id": pid,
				"code":               code,
			})
			body := drain(res)
			if res.StatusCode == http.StatusOK {
				t.Fatalf("%s (status=%d body=%s)", tc.what, res.StatusCode, body)
			}
			if sc := res.Header.Get("Set-Cookie"); sc != "" {
				t.Fatalf("%s: a session cookie was issued (%q)", tc.what, sc)
			}
		})
	}
}

// TestMFAVerify_ActiveAccountStillCompletes is the positive control: the gate
// must not be satisfied by refusing every MFA login.
func TestMFAVerify_ActiveAccountStillCompletes(t *testing.T) {
	env, _ := newTestEnvWithRepo(t)
	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)
	env.logout(t)

	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an active account must still complete its MFA login: %d %s",
			res.StatusCode, drain(res))
	}
}
