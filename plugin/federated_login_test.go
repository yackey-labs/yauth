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

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/events"
)

// emitOnlyHost implements PluginHost by embedding the interface: every
// method other than Emit is nil and panics if RunFederatedLogin ever
// reaches for one, which is itself part of the contract.
type emitOnlyHost struct {
	PluginHost
	seen []events.AuthEvent
	on   events.EventType
	dec  events.Decision
}

func (h *emitOnlyHost) Emit(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
	h.seen = append(h.seen, ev)
	if ev.Type == h.on {
		return h.dec, nil
	}
	return events.Continue(), nil
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
	h := &emitOnlyHost{}
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
	h := &emitOnlyHost{
		on:  events.EventLoginAttempt,
		dec: events.Block(http.StatusTooManyRequests, "Account locked"),
	}
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
	h := &emitOnlyHost{
		on:  events.EventLoginSucceeded,
		dec: events.Block(0, ""),
	}
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
	h := &emitOnlyHost{}
	if err := run(h, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !h.seen[1].MFAVerified() {
		t.Errorf("login.succeeded should carry the mfa-verified marker")
	}

	h = &emitOnlyHost{}
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
	h := &emitOnlyHost{
		on:  events.EventLoginSucceeded,
		dec: events.RequireMfa("user-1", "pending-1"),
	}
	err := run(h, false)
	if err == nil {
		t.Fatalf("a step-up decision must not be waved through")
	}
	if got := status(t, err); got != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", got)
	}
}
