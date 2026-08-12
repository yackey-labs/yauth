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

// MetaMFAVerified is the AuthEvent.Metadata key marking a login.succeeded
// emitted AFTER a second factor was verified — i.e. a login that is
// COMPLETE, not merely password-verified.
//
// EventLoginSucceeded means "the primary credential checked out". For an
// MFA-enrolled user the login only completes later, when the challenge is
// answered (mfa's /mfa/verify, bearer's /token/mfa). Those completion
// points emit a second login.succeeded carrying this marker so that:
//
//   - handlers that clear per-login state — lockout's failure counter —
//     see the login that actually completed, and
//   - the MFA gate recognises its own completion and steps aside instead
//     of opening a fresh challenge, which would loop forever.
//
// Metadata is built in Go by the emitting plugin; no request field is ever
// unmarshalled into an AuthEvent, so a caller cannot set the marker.
const MetaMFAVerified = "mfa_verified"

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

// MFAVerified reports whether e carries the MetaMFAVerified marker — i.e.
// whether it is the completion of a stepped-up login rather than the
// password-verified event that opened the challenge.
func (e AuthEvent) MFAVerified() bool {
	v, ok := e.Metadata[MetaMFAVerified].(bool)
	return ok && v
}

// MFACompleted returns the Metadata map that marks a login.succeeded as the
// completion of a second-factor challenge. Emitters use it so the key is
// never spelled out by hand.
func MFACompleted() map[string]any {
	return map[string]any{MetaMFAVerified: true}
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
