package domain

import (
	"encoding/json"
	"time"
)

// Webhook is a registered outbound webhook endpoint.
type Webhook struct {
	ID        string
	URL       string
	Secret    string
	Events    json.RawMessage
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewWebhook is the input for registering a webhook.
type NewWebhook struct {
	ID        string
	URL       string
	Secret    string
	Events    json.RawMessage
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UpdateWebhook is a partial update payload; nil fields are unchanged.
type UpdateWebhook struct {
	URL       *string
	Secret    *string
	Events    *json.RawMessage
	Active    *bool
	UpdatedAt *time.Time
}

// WebhookDelivery is a single attempt to deliver a webhook event.
type WebhookDelivery struct {
	ID           string
	WebhookID    string
	EventType    string
	Payload      json.RawMessage
	StatusCode   *int16
	ResponseBody *string
	Success      bool
	Attempt      int
	CreatedAt    time.Time
}

// NewWebhookDelivery is the input for recording a webhook delivery attempt.
type NewWebhookDelivery struct {
	ID           string
	WebhookID    string
	EventType    string
	Payload      json.RawMessage
	StatusCode   *int16
	ResponseBody *string
	Success      bool
	Attempt      int
	CreatedAt    time.Time
}

// ScheduledWebhookRetry is a persisted webhook retry waiting for its
// not_before deadline. The dispatcher's claimer atomically reserves due
// rows, runs them, and deletes them — so the queue survives a process
// restart instead of being lost to in-memory time.AfterFunc timers.
type ScheduledWebhookRetry struct {
	ID        string
	WebhookID string
	EventType string
	Payload   []byte
	Attempt   int
	NotBefore time.Time
	CreatedAt time.Time
}

// NewScheduledWebhookRetry is the input for persisting a retry row.
type NewScheduledWebhookRetry struct {
	ID        string
	WebhookID string
	EventType string
	Payload   []byte
	Attempt   int
	NotBefore time.Time
	CreatedAt time.Time
}
