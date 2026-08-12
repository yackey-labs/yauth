package domain

import "time"

// TOTPSecret is a per-user time-based one-time-password seed.
type TOTPSecret struct {
	ID              string
	UserID          string
	EncryptedSecret string
	Verified        bool
	CreatedAt       time.Time

	// LastUsedStep is the RFC 6238 time-step counter (unix seconds /
	// period) of the most recent code accepted for this secret, or nil if
	// none has been accepted yet.
	//
	// RFC 6238 §5.2: "The verifier MUST NOT accept the second attempt of
	// the OTP after the successful validation has been issued for the first
	// OTP." A TOTP code is otherwise valid for its whole 30-second window —
	// and, with the customary one-step skew, the neighbouring windows too —
	// so a code phished or shoulder-surfed mid-window can simply be
	// replayed. Refusing any step at or below this one closes that: a code
	// buys exactly one authentication.
	LastUsedStep *int64
}

// NewTOTPSecret is the input for creating a TOTP secret.
type NewTOTPSecret struct {
	ID              string
	UserID          string
	EncryptedSecret string
	Verified        bool
	CreatedAt       time.Time

	// LastUsedStep seeds TOTPSecret.LastUsedStep. Enrolment sets it to the
	// step of the code that CONFIRMED the secret, so the very code that
	// proved possession cannot then be replayed to log in.
	LastUsedStep *int64
}

// BackupCode is a single-use MFA recovery code.
type BackupCode struct {
	ID        string
	UserID    string
	CodeHash  string
	Used      bool
	CreatedAt time.Time
}

// NewBackupCode is the input for creating a backup code.
type NewBackupCode struct {
	ID        string
	UserID    string
	CodeHash  string
	Used      bool
	CreatedAt time.Time
}
