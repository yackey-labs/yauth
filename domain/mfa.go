package domain

import "time"

// TOTPSecret is a per-user time-based one-time-password seed.
type TOTPSecret struct {
	ID              string
	UserID          string
	EncryptedSecret string
	Verified        bool
	CreatedAt       time.Time
}

// NewTOTPSecret is the input for creating a TOTP secret.
type NewTOTPSecret struct {
	ID              string
	UserID          string
	EncryptedSecret string
	Verified        bool
	CreatedAt       time.Time
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
