// Regression suite for account lifecycle on the passkey credential path.
//
// #81 ("honour account lifecycle on every credential path") applied
// domain.User.CanAuthenticate — not banned, not suspended, past any scheduled
// start — across the library: middleware's cookie resolution, the bearer and
// api-key resolvers, oauth2server's grants and its device flow, and
// plugin.RunFederatedLogin for the federated logins. Passkey login checked
// `matchedUser.Banned` and nothing else.
//
// An offboarded employee (SuspendedAt set by SCIM `active:false` or an admin's
// POST /suspend) whose passkey is already on their phone therefore still got a
// 200, a Set-Cookie, a persisted session row, and a body carrying their id,
// email and ROLE. yauth's own middleware re-checks CanAuthenticate when the
// cookie is later used, so this is not a full bypass for consumers on that
// middleware — but a kill switch that reports success and hands back the
// user's role is not a kill switch, and the response shape actively invites a
// consumer to establish its own session from that body.
//
// The gate now lives in completeLogin rather than in handleLoginFinish: that
// is the single choke point through which every passkey session is minted, so
// no future entry point can route around it.
package passkey

import (
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func TestCompleteLogin_RefusesAccountsThatCannotAuthenticate(t *testing.T) {
	now := time.Now().UTC()
	later := now.Add(24 * time.Hour)

	cases := []struct {
		name  string
		apply func(u *domain.User)
		what  string
	}{
		{
			name:  "banned",
			apply: func(u *domain.User) { u.Banned = true },
			what:  "a banned account completed a passkey login",
		},
		{
			name:  "suspended",
			apply: func(u *domain.User) { u.SuspendedAt = &now },
			what:  "an offboarded (suspended) account completed a passkey login",
		},
		{
			name:  "staged",
			apply: func(u *domain.User) { u.ActivatesAt = &later },
			what:  "an account whose start date has not arrived completed a passkey login",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := memrepo.New()
			host := newPipelineHost(r)
			p := newPlugin(t, nil)
			u := seedUser(t, r, "alice@example.com")
			tc.apply(&u)

			out, cookie, err := finish(t, p, host, u)
			if err == nil {
				t.Fatalf("%s: body=%+v", tc.what, out)
			}
			if cookie != "" {
				t.Fatalf("%s: a session cookie was issued (%q)", tc.what, cookie)
			}
			if n := sessionCount(t, r); n != 0 {
				t.Fatalf("%s: %d session row(s) were persisted", tc.what, n)
			}
		})
	}
}

// TestCompleteLogin_ActiveAccountStillSignsIn is the positive control: the
// gate must not be satisfied by refusing every passkey login.
func TestCompleteLogin_ActiveAccountStillSignsIn(t *testing.T) {
	r := memrepo.New()
	host := newPipelineHost(r)
	p := newPlugin(t, nil)
	u := seedUser(t, r, "alice@example.com")

	out, cookie, err := finish(t, p, host, u)
	if err != nil {
		t.Fatalf("an active account must still complete a passkey login: %v", err)
	}
	if out.Body.User == nil || out.Body.User.ID != u.ID {
		t.Fatalf("expected the user in the body, got %+v", out.Body)
	}
	if cookie == "" {
		t.Fatal("expected a session cookie for a successful passkey login")
	}
	if n := sessionCount(t, r); n != 1 {
		t.Fatalf("expected exactly one session row, got %d", n)
	}
}

// TestCompleteLogin_LifecycleIsCheckedBeforeTheEventPipeline pins the ordering.
// A refused login must not emit login.succeeded: lockout's onSucceeded CLEARS
// the failure counter on that event, so emitting it for a deprovisioned
// account would hand an attacker a counter reset.
func TestCompleteLogin_LifecycleIsCheckedBeforeTheEventPipeline(t *testing.T) {
	r := memrepo.New()
	host := newPipelineHost(r)
	p := newPlugin(t, nil)
	u := seedUser(t, r, "alice@example.com")
	susp := time.Now().UTC()
	u.SuspendedAt = &susp

	if _, _, err := finish(t, p, host, u); err == nil {
		t.Fatal("expected the suspended account to be refused")
	}
	for _, ev := range host.seen {
		if ev.Type == events.EventLoginSucceeded {
			t.Fatal("a refused passkey login emitted login.succeeded, which clears " +
				"the lockout failure counter")
		}
	}
}
