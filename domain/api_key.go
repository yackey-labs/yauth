package domain

import (
	"encoding/json"
	"time"
)

// APIKey is a long-lived bearer credential identified by prefix.
type APIKey struct {
	ID         string
	UserID     string
	KeyPrefix  string
	KeyHash    string
	Name       string
	Scopes     json.RawMessage
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	CreatedAt  time.Time
}

// NewAPIKey is the input for creating an API key.
type NewAPIKey struct {
	ID        string
	UserID    string
	KeyPrefix string
	KeyHash   string
	Name      string
	Scopes    json.RawMessage
	ExpiresAt *time.Time
	CreatedAt time.Time
}
