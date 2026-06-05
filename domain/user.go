package domain

import "time"

// User is a registered account.
type User struct {
	ID            string
	Email         string
	DisplayName   *string
	EmailVerified bool
	Role          string
	Banned        bool
	BannedReason  *string
	BannedUntil   *time.Time
	// SuspendedAt globally disables the account (offboarding) — distinct from
	// Banned, which is for security incidents. A suspended user cannot log in,
	// receive tokens, or pass auth resolution; the account is retained.
	SuspendedAt     *time.Time
	SuspendedReason *string
	// ActivatesAt schedules a start: while it is in the future the user is
	// "staged" and cannot authenticate yet (onboarding ahead of a start date).
	ActivatesAt *time.Time
	// MustChangePassword marks a credential that was provisioned out-of-band
	// (admin/seed/bootstrap) and must be rotated by the user before it is
	// trusted — the "forced password change on first sign-in" primitive. yauth
	// surfaces it on the resolved AuthUser and clears it automatically when the
	// user changes or resets their password; it does NOT itself block
	// authentication. Enforcement (gate/redirect) is the consuming app's choice.
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Staged reports whether the user has a scheduled start still in the future.
func (u User) Staged(now time.Time) bool {
	return u.ActivatesAt != nil && now.Before(*u.ActivatesAt)
}

// CanAuthenticate reports whether the user may currently sign in or receive
// tokens: not banned, not suspended, and past any scheduled start.
func (u User) CanAuthenticate(now time.Time) bool {
	return !u.Banned && u.SuspendedAt == nil && !u.Staged(now)
}

// NewUser is the input for creating a user.
type NewUser struct {
	ID                 string
	Email              string
	DisplayName        *string
	EmailVerified      bool
	Role               string
	Banned             bool
	BannedReason       *string
	BannedUntil        *time.Time
	SuspendedAt        *time.Time
	SuspendedReason    *string
	ActivatesAt        *time.Time
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// UpdateUser is a partial update payload; nil fields are unchanged.
type UpdateUser struct {
	Email           *string
	DisplayName     **string
	EmailVerified   *bool
	Role            *string
	Banned          *bool
	BannedReason    **string
	BannedUntil     **time.Time
	SuspendedAt     **time.Time
	SuspendedReason **string
	ActivatesAt     **time.Time
	UpdatedAt       *time.Time
}
