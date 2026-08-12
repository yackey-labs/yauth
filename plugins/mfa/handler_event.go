package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// pendingSessionTTL is the lifetime of an mfa_pending:<uuid> challenge
// row. Long enough for a user to reach for their phone, short enough
// that an abandoned login does not linger.
const pendingSessionTTL = 5 * time.Minute

// pendingSessionKeyPrefix is the namespace used for MFA pending-session
// records inside the shared challenge repository.
const pendingSessionKeyPrefix = "mfa_pending:"

// loginEventHandler intercepts login.succeeded events. If the
// authenticating user has a verified TOTP secret, it creates an
// mfa_pending:<uuid> challenge row and returns a RequireMfa decision
// so the upstream plugin returns {require_mfa, pending_session_id}
// instead of issuing a real session.
//
// It is registered as a pipeline GATE (host.RegisterEventGate), so it
// always runs before observers such as lockout, whatever order the
// plugins were registered in. That ordering is load-bearing: while a
// challenge is outstanding the login has not completed, and lockout must
// not clear its failure counter yet.
type loginEventHandler struct {
	repo              repo.Repository
	encryptionKey     [32]byte
	pendingSessionTTL time.Duration
}

// Handle implements events.Handler.
func (h *loginEventHandler) Handle(ctx context.Context, ev events.AuthEvent) (events.Decision, error) {
	if ev.Type != events.EventLoginSucceeded {
		return events.Continue(), nil
	}
	if ev.UserID == nil || *ev.UserID == "" {
		return events.Continue(), nil
	}
	// Completing a challenge emits its own login.succeeded — that is how
	// lockout learns the login actually finished. Opening a fresh
	// challenge for it would hand the client require_mfa forever, so the
	// marker is the loop breaker. Only an in-process plugin can set it;
	// no request field is ever unmarshalled into an AuthEvent.
	if ev.MFAVerified() {
		return events.Continue(), nil
	}

	verified := true
	totp, err := h.repo.GetTOTPByUserID(ctx, *ev.UserID, &verified)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return events.Continue(), nil
		}
		return events.Continue(), err
	}
	if totp == nil {
		return events.Continue(), nil
	}

	pendingID := uuid.NewString()
	ttl := h.pendingSessionTTL
	if ttl == 0 {
		ttl = pendingSessionTTL
	}
	if err := h.repo.SetChallenge(ctx, pendingSessionKeyPrefix+pendingID, *ev.UserID, ttl); err != nil {
		return events.Continue(), err
	}

	return events.RequireMfa(*ev.UserID, pendingID), nil
}
