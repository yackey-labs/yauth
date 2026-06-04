package lockout

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// loginEventHandler is the events.Handler the lockout plugin registers
// with the host. It intercepts login.attempt to short-circuit a login
// request when an account is currently locked, increments the failure
// counter on login.failed, and resets it on login.succeeded.
type loginEventHandler struct {
	cfg  Config
	host plugin.PluginHost
}

// Handle implements events.Handler.
func (h *loginEventHandler) Handle(ctx context.Context, e events.AuthEvent) (events.Decision, error) {
	switch e.Type {
	case events.EventLoginAttempt:
		return h.onAttempt(ctx, e)
	case events.EventLoginFailed:
		return h.onFailed(ctx, e)
	case events.EventLoginSucceeded:
		return h.onSucceeded(ctx, e)
	}
	return events.Continue(), nil
}

// resolveUserID maps an event onto the user ID the lockout state is keyed
// on. Most events carry UserID directly; login.attempt carries only Email
// (the password compare hasn't happened yet) so we look the user up.
func (h *loginEventHandler) resolveUserID(ctx context.Context, e events.AuthEvent) (string, bool) {
	if e.UserID != nil && *e.UserID != "" {
		return *e.UserID, true
	}
	if e.Email == nil || *e.Email == "" {
		return "", false
	}
	u, err := h.host.Repo().GetUserByEmail(ctx, *e.Email)
	if err != nil || u == nil {
		return "", false
	}
	return u.ID, true
}

// onAttempt blocks the login if the user already has an active lock.
func (h *loginEventHandler) onAttempt(ctx context.Context, e events.AuthEvent) (events.Decision, error) {
	uid, ok := h.resolveUserID(ctx, e)
	if !ok {
		return events.Continue(), nil
	}
	lock, err := h.host.Repo().GetAccountLockByUserID(ctx, uid)
	if err != nil || lock == nil {
		return events.Continue(), nil
	}
	if lock.LockedUntil != nil && lock.LockedUntil.UTC().After(time.Now().UTC()) {
		return events.Block(http.StatusTooManyRequests, "Account locked"), nil
	}
	// If the lock window has elapsed, clear it lazily and reset counter
	// so this login can proceed clean — but only when AutoUnlock is on.
	// AutoUnlock=false means an admin must POST /unlock; the cooldown
	// timer alone is not enough to clear the lock.
	if lock.LockedUntil != nil {
		if !h.cfg.autoUnlock() {
			return events.Block(http.StatusTooManyRequests, "Account locked"), nil
		}
		now := time.Now().UTC()
		_ = h.host.Repo().AutoUnlockAccount(ctx, lock.ID, now)
		_ = h.host.Repo().ResetAccountLockFailedCount(ctx, lock.ID, now)
	}
	return events.Continue(), nil
}

// onFailed increments the failed counter and triggers a lock when the
// threshold is reached.
func (h *loginEventHandler) onFailed(ctx context.Context, e events.AuthEvent) (events.Decision, error) {
	uid, ok := h.resolveUserID(ctx, e)
	if !ok {
		return events.Continue(), nil
	}
	repo := h.host.Repo()
	now := time.Now().UTC()

	lock, err := repo.GetAccountLockByUserID(ctx, uid)
	if errors.Is(err, yautherr.ErrNotFound) {
		// First failure: create a fresh lock row with FailedCount=1.
		created, cErr := repo.CreateAccountLock(ctx, domain.NewAccountLock{
			ID:          uuid.NewString(),
			UserID:      uid,
			FailedCount: 1,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
		if cErr != nil {
			return events.Continue(), nil
		}
		// If MaxAttempts == 1, lock immediately.
		if 1 >= h.cfg.MaxAttempts {
			_ = h.applyLock(ctx, created.ID, 0, now)
		}
		return events.Continue(), nil
	}
	if err != nil || lock == nil {
		return events.Continue(), nil
	}

	if err := repo.IncrementAccountLockFailedCount(ctx, lock.ID, now); err != nil {
		return events.Continue(), nil
	}
	newCount := lock.FailedCount + 1
	if newCount >= h.cfg.MaxAttempts {
		_ = h.applyLock(ctx, lock.ID, lock.LockCount, now)
	}
	return events.Continue(), nil
}

// onSucceeded clears the failure counter and any active lock.
func (h *loginEventHandler) onSucceeded(ctx context.Context, e events.AuthEvent) (events.Decision, error) {
	uid, ok := h.resolveUserID(ctx, e)
	if !ok {
		return events.Continue(), nil
	}
	repo := h.host.Repo()
	lock, err := repo.GetAccountLockByUserID(ctx, uid)
	if err != nil || lock == nil {
		return events.Continue(), nil
	}
	now := time.Now().UTC()
	_ = repo.ResetAccountLockFailedCount(ctx, lock.ID, now)
	if lock.LockedUntil != nil {
		_ = repo.AutoUnlockAccount(ctx, lock.ID, now)
	}
	return events.Continue(), nil
}

// applyLock writes the locked_until / lock_count update for the supplied
// lock row, given the previous lock_count. The new lock_count is
// previous+1 (capped by len(LockoutDurations)). The chosen step is
// truncated by Config.MaxLockoutDuration so a misconfigured ladder
// cannot lock an account beyond the policy ceiling.
func (h *loginEventHandler) applyLock(ctx context.Context, lockID string, prevLockCount int, now time.Time) error {
	idx := prevLockCount
	if idx >= len(h.cfg.LockoutDurations) {
		idx = len(h.cfg.LockoutDurations) - 1
	}
	if idx < 0 {
		idx = 0
	}
	step := h.cfg.LockoutDurations[idx]
	if h.cfg.MaxLockoutDuration > 0 && step > h.cfg.MaxLockoutDuration {
		step = h.cfg.MaxLockoutDuration
	}
	until := now.Add(step)
	reason := "too many failed login attempts"
	state := domain.LockState{
		LockedUntil:  &until,
		LockedReason: &reason,
		LockCount:    prevLockCount + 1,
	}
	return h.host.Repo().SetAccountLockState(ctx, lockID, state, now)
}

// logf writes a single formatted line to stderr. Used by the default
// LoggingMailer. Centralising the writer makes tests easier later.
func logf(format string, args ...any) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, args...))
}
