package events

import (
	"context"
	"time"
)

// EventType identifies the kind of AuthEvent.
type EventType string

const (
	EventUserRegistered  EventType = "user.registered"
	EventLoginAttempt    EventType = "login.attempt"
	EventLoginSucceeded  EventType = "login.succeeded"
	EventLoginFailed     EventType = "login.failed"
	EventLogout          EventType = "logout"
	EventSessionCreated  EventType = "session.created"
	EventSessionRevoked  EventType = "session.revoked"
	EventPasswordChanged EventType = "password.changed"
	EventPasswordReset   EventType = "password.reset"
	EventEmailVerified   EventType = "email.verified"
	EventUserBanned      EventType = "user.banned"
	EventUserUnbanned    EventType = "user.unbanned"
	EventUserSuspended   EventType = "user.suspended"
	EventUserUnsuspended EventType = "user.unsuspended"
)

// AuthEvent is an authentication lifecycle event handed to plugins/handlers.
type AuthEvent struct {
	Type      EventType
	UserID    *string
	SessionID *string
	Email     *string
	IPAddress *string
	Method    *string
	Reason    *string
	Metadata  map[string]any
	Timestamp time.Time
}

// DecisionKind tags the variant of a Decision.
type DecisionKind int

const (
	DecisionKindContinue DecisionKind = iota
	DecisionKindBlock
	DecisionKindRequireMfa
)

// Decision is the result of an event handler. Use the Continue/Block/RequireMfa
// constructors; the zero value is Continue.
type Decision struct {
	Kind             DecisionKind
	BlockStatus      int
	BlockMessage     string
	UserID           string
	PendingSessionID string
}

// Continue tells the pipeline to proceed.
func Continue() Decision { return Decision{Kind: DecisionKindContinue} }

// Block aborts the request with the given HTTP status and message.
func Block(status int, message string) Decision {
	return Decision{Kind: DecisionKindBlock, BlockStatus: status, BlockMessage: message}
}

// RequireMfa pauses login pending MFA verification.
func RequireMfa(userID, pendingSessionID string) Decision {
	return Decision{Kind: DecisionKindRequireMfa, UserID: userID, PendingSessionID: pendingSessionID}
}

// Handler reacts to AuthEvents and returns a Decision.
type Handler interface {
	Handle(ctx context.Context, event AuthEvent) (Decision, error)
}
