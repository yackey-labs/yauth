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

// MetaAdministrativeRefusal is the AuthEvent.Metadata key marking a
// login.failed that refused the request WITHOUT ever comparing a credential
// — the account does not exist, is banned, suspended, staged, has no password
// row at all, or has an unverified email.
//
// It exists because a login.failed used to mean two very different things to
// the lockout plugin, which increments its failure counter on every one that
// resolves to a user. A wrong password is evidence of guessing; being
// suspended is not. Conflating them turned /login into a remote off switch:
// an account provisioned by SCIM/SSO/passkey/magic-link has no password row,
// so five unauthenticated POSTs with a junk password against a NAMED address
// locked that user out of every login path they actually use — and there is
// no password for them to reset their way back with. The mirror image locked
// a suspended account so that lifting the suspension did not restore it.
//
// plugin.RunFederatedLogin already states this invariant (it emits nothing at
// all for a lifecycle refusal, precisely so administrative states "must not
// feed lockout counters"); the marker lets the password paths, which must
// still emit for audit and webhook observers, say the same thing.
//
// Deliberately NOT named with the word "credential": audit_events.go redacts
// any metadata key containing "credential" (also "code", "key", "secret",
// "token"), so such a name would land in every login.failed audit row as
// "[redacted]" and the reason for the row would be lost.
//
// Metadata is built in Go by the emitting plugin; no request field is ever
// unmarshalled into an AuthEvent, so a caller cannot set the marker to make
// their own guessing free.
const MetaAdministrativeRefusal = "administrative_refusal"

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

// AdministrativeRefusal reports whether e carries the
// MetaAdministrativeRefusal marker — i.e. whether the refusal it records was
// an administrative or "no credential to compare" outcome rather than a
// failed credential. Handlers that count failures (lockout) must ignore
// these; observers that merely record them (audit, webhooks) still see them.
func (e AuthEvent) AdministrativeRefusal() bool {
	v, ok := e.Metadata[MetaAdministrativeRefusal].(bool)
	return ok && v
}

// AdministrativeRefusal returns the Metadata map that marks a login.failed as
// a refusal where no credential was compared. Emitters use it so the key is
// never spelled out by hand.
func AdministrativeRefusal() map[string]any {
	return map[string]any{MetaAdministrativeRefusal: true}
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
