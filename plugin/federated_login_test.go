package plugin

// Cover for RunFederatedLogin, the shared login-pipeline step the oauth
// client and the two SSO plugins run before issuing a session. All three
// used to emit login.succeeded with the Decision discarded, AFTER the
// cookie was already written.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// emitOnlyHost implements PluginHost by embedding the interface: every
// method other than Emit and Repo is nil and panics if RunFederatedLogin
// ever reaches for one, which is itself part of the contract. Repo is real
// (memrepo) because the account-lifecycle gate reads the resolved user.
type emitOnlyHost struct {
	PluginHost
	repo repo.Repository
	seen []events.AuthEvent
	on   events.EventType
	dec  events.Decision
}

func (h *emitOnlyHost) Repo() repo.Repository { return h.repo }

func (h *emitOnlyHost) Emit(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
	h.seen = append(h.seen, ev)
	if ev.Type == h.on {
		return h.dec, nil
	}
	return events.Continue(), nil
}

// newEmitHost seeds "user-1" as an ordinary, currently-authenticable
// account so the decision assertions below are about decision handling and
// nothing else. lifecycle, when non-nil, mutates the seeded user first.
func newEmitHost(t *testing.T, lifecycle func(*domain.NewUser)) *emitOnlyHost {
	t.Helper()
	r := memrepo.New()
	now := time.Now().UTC()
	nu := domain.NewUser{
		ID:        "user-1",
		Email:     "alice@example.com",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if lifecycle != nil {
		lifecycle(&nu)
	}
	if _, err := r.CreateUser(context.Background(), nu); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return &emitOnlyHost{repo: r}
}

func status(t *testing.T, err error) int {
	t.Helper()
	var se huma.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("expected a huma status error, got %v", err)
	}
	return se.GetStatus()
}

func run(h *emitOnlyHost, satisfiesMFA bool) error {
	return RunFederatedLogin(context.Background(), h, satisfiesMFA, "user-1", "alice@example.com", nil, "oauth:google")
}

// TestRunFederatedLogin_AllowsCleanLogin: with no interposing handler the
// login proceeds, and both legs of the pipeline were emitted.
func TestRunFederatedLogin_AllowsCleanLogin(t *testing.T) {
	h := newEmitHost(t, nil)
	if err := run(h, true); err != nil {
		t.Fatalf("expected the login to proceed, got %v", err)
	}
	if len(h.seen) != 2 ||
		h.seen[0].Type != events.EventLoginAttempt ||
		h.seen[1].Type != events.EventLoginSucceeded {
		t.Fatalf("expected login.attempt then login.succeeded, got %+v", h.seen)
	}
}

// TestRunFederatedLogin_BlockOnAttempt is the lockout shape: lockout only
// ever answers Block on login.attempt, so without that event a locked
// account would still get a session from an external IdP.
func TestRunFederatedLogin_BlockOnAttempt(t *testing.T) {
	h := newEmitHost(t, nil)
	h.on = events.EventLoginAttempt
	h.dec = events.Block(http.StatusTooManyRequests, "Account locked")
	err := run(h, true)
	if err == nil {
		t.Fatalf("expected the Block to be honoured")
	}
	if got := status(t, err); got != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", got)
	}
	if len(h.seen) != 1 {
		t.Fatalf("a blocked attempt must not go on to emit login.succeeded: %+v", h.seen)
	}
}

// TestRunFederatedLogin_BlockOnSucceeded covers a risk/deny handler that
// blocks once the identity is resolved.
func TestRunFederatedLogin_BlockOnSucceeded(t *testing.T) {
	h := newEmitHost(t, nil)
	h.on = events.EventLoginSucceeded
	h.dec = events.Block(0, "")
	err := run(h, true)
	if err == nil {
		t.Fatalf("expected the Block to be honoured")
	}
	// A Block carrying no status/message still maps to a refusal, never
	// to a session.
	if got := status(t, err); got != http.StatusForbidden {
		t.Fatalf("expected the 403 default, got %d", got)
	}
}

// TestRunFederatedLogin_SatisfiesMFAMarksTheEvent: declaring the IdP the
// second factor must be SAID in the event, not achieved by dropping the
// decision. The marker stands mfa's gate down and lets lockout see a
// completed login.
func TestRunFederatedLogin_SatisfiesMFAMarksTheEvent(t *testing.T) {
	h := newEmitHost(t, nil)
	if err := run(h, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !h.seen[1].MFAVerified() {
		t.Errorf("login.succeeded should carry the mfa-verified marker")
	}

	h = newEmitHost(t, nil)
	if err := run(h, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if h.seen[1].MFAVerified() {
		t.Errorf("satisfiesMFA=false must not claim a verified second factor")
	}
}

// TestRunFederatedLogin_StepUpFailsClosed: a redirect-shaped flow cannot
// carry a {require_mfa, pending_session_id} challenge, so a step-up
// decision must refuse the login rather than fall through to a session.
func TestRunFederatedLogin_StepUpFailsClosed(t *testing.T) {
	h := newEmitHost(t, nil)
	h.on = events.EventLoginSucceeded
	h.dec = events.RequireMfa("user-1", "pending-1")
	err := run(h, false)
	if err == nil {
		t.Fatalf("a step-up decision must not be waved through")
	}
	if got := status(t, err); got != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", got)
	}
}

// TestRunFederatedLogin_RefusesLifecycleStates: every federated callback
// gated on user.Banned alone, so suspension — the documented offboarding
// kill switch — did not hold on ANY SSO path: an offboarded employee could
// sign in with Google or the corporate IdP and receive a full session. The
// refusal is asserted as "no permission to proceed at all": a non-nil error
// means the caller returns it unchanged and never reaches IssueSession.
//
// It must also emit NOTHING. A suspended account is an administrative
// state, not a credential failure, so it must not feed lockout counters or
// appear to observers as a login attempt.
func TestRunFederatedLogin_RefusesLifecycleStates(t *testing.T) {
	suspendedAt := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)

	cases := []struct {
		name      string
		lifecycle func(*domain.NewUser)
	}{
		{"banned", func(u *domain.NewUser) { u.Banned = true }},
		{"suspended", func(u *domain.NewUser) { u.SuspendedAt = &suspendedAt }},
		{"staged", func(u *domain.NewUser) { u.ActivatesAt = &future }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newEmitHost(t, tc.lifecycle)
			err := run(h, true)
			if err == nil {
				t.Fatalf("%s account was allowed to complete a federated login", tc.name)
			}
			if got := status(t, err); got != http.StatusForbidden {
				t.Errorf("expected 403, got %d", got)
			}
			if len(h.seen) != 0 {
				t.Errorf("a lifecycle refusal must emit no auth events, got %+v", h.seen)
			}
		})
	}
}

// TestRunFederatedLogin_RefusesMissingUser: the callbacks pass an id they
// just created or read, so "user is gone" means the account vanished
// underneath the flow. Fail closed.
func TestRunFederatedLogin_RefusesMissingUser(t *testing.T) {
	h := &emitOnlyHost{repo: memrepo.New()}
	err := run(h, true)
	if err == nil {
		t.Fatalf("a login for a non-existent user must be refused")
	}
	if got := status(t, err); got != http.StatusForbidden {
		t.Errorf("expected 403, got %d", got)
	}
	if len(h.seen) != 0 {
		t.Errorf("expected no auth events, got %+v", h.seen)
	}
}
