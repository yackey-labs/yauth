package domain

import (
	"encoding/json"
	"time"
)

// WebauthnCredential is a registered WebAuthn / passkey credential.
type WebauthnCredential struct {
	ID         string
	UserID     string
	Name       string
	AAGUID     *string
	DeviceName *string
	Credential json.RawMessage
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// NewWebauthnCredential is the input for registering a WebAuthn credential.
type NewWebauthnCredential struct {
	ID         string
	UserID     string
	Name       string
	AAGUID     *string
	DeviceName *string
	Credential json.RawMessage
	CreatedAt  time.Time
}
