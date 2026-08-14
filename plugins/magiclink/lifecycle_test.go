// Regression suite for account lifecycle on the magic-link credential path.
//
// #81 ("honour account lifecycle on every credential path") applied
// domain.User.CanAuthenticate — not banned, not suspended, past any scheduled
// start — across the library: middleware's cookie resolution, the bearer and
// api-key resolvers, oauth2server's grants and its device flow, and
// plugin.RunFederatedLogin for the federated logins. /magic-link/verify was
// missed. It checked `user.Banned` and nothing else.
//
// So an offboarded employee — suspended via SCIM `active:false` or an admin's
// POST /suspend — could still redeem a link mailed before they were
// deprovisioned, and nothing retires outstanding magic links on suspend
// (DeleteUnusedMagicLinksForEmail is called only from emailpassword, on
// password change and reset). Same for a staged account whose start date has
// not arrived.
//
// What that produced, concretely: a 200 disclosing the account's id, email and
// ROLE; a persisted session row for a deprovisioned account; and a
// login.succeeded event, which lockout's onSucceeded uses to CLEAR the failure
// counter. yauth's own middleware re-checks CanAuthenticate when the cookie is
// later USED, so this is not a full authentication bypass for consumers using
// that middleware — but a kill switch that reports success, hands back the
// user's role and mints a session row is not a kill switch, and any consumer
// that establishes its own session from the 200 body is fully exposed.
package magiclink_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/magiclink"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newServerWithRepo mirrors newServer but hands back the repo so a test can
// put the account into a lifecycle state after the link has been issued —
// which is the real sequence: the link is mailed, then the person is
// offboarded.
func newServerWithRepo(t *testing.T) (*httptest.Server, *captureMailer, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	mailer := &captureMailer{}

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(magiclink.New(magiclink.Config{
			Mailer:      mailer,
			LinkBaseURL: "https://example.test/magic",
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, mailer, r
}

// seedAndIssueLink creates an active user and drives /magic-link/send, returning
// the raw token the mailer received.
func seedAndIssueLink(t *testing.T, srv *httptest.Server, mailer *captureMailer, r repo.Repository, email string) (userID, token string) {
	t.Helper()
	now := time.Now().UTC()
	u, err := r.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	res := postJSON(t, c, srv.URL+"/api/auth/magic-link/send", map[string]string{"email": email})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("send: %d %s", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// The send is dispatched off the request goroutine now, so wait for it.
	return u.ID, tokenFromLink(mailer.waitLink(t))
}

func redeem(t *testing.T, srv *httptest.Server, token string) *http.Response {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return postJSON(t, &http.Client{Jar: jar},
		srv.URL+"/api/auth/magic-link/verify", map[string]string{"token": token})
}

func TestVerify_RefusesAccountsThatCannotAuthenticate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(now time.Time) domain.UpdateUser
		what   string
	}{
		{
			name: "suspended",
			mutate: func(now time.Time) domain.UpdateUser {
				susp := &now
				return domain.UpdateUser{SuspendedAt: &susp, UpdatedAt: &now}
			},
			what: "an offboarded (suspended) account redeemed a magic link",
		},
		{
			name: "staged",
			mutate: func(now time.Time) domain.UpdateUser {
				start := now.Add(24 * time.Hour)
				sp := &start
				return domain.UpdateUser{ActivatesAt: &sp, UpdatedAt: &now}
			},
			what: "an account whose start date has not arrived redeemed a magic link",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, mailer, r := newServerWithRepo(t)
			uid, token := seedAndIssueLink(t, srv, mailer, r, "alice@example.com")

			now := time.Now().UTC()
			if _, err := r.UpdateUser(context.Background(), uid, tc.mutate(now)); err != nil {
				t.Fatalf("apply %s: %v", tc.name, err)
			}

			res := redeem(t, srv, token)
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

// TestVerify_ActiveAccountStillRedeems is the positive control: the gate must
// not be satisfied by refusing every redemption.
func TestVerify_ActiveAccountStillRedeems(t *testing.T) {
	srv, mailer, r := newServerWithRepo(t)
	_, token := seedAndIssueLink(t, srv, mailer, r, "alice@example.com")

	res := redeem(t, srv, token)
	body := drain(res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an active account must still redeem its magic link: %d %s", res.StatusCode, body)
	}
	if res.Header.Get("Set-Cookie") == "" {
		t.Fatal("expected a session cookie for a successful redemption")
	}
}
