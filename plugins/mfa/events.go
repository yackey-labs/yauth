package mfa

import (
	"context"
	"net/http"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugin"
)

// loginMethod is the events.AuthEvent Method for the second leg of a
// stepped-up login driven by this plugin's own /mfa/verify. The bearer
// plugin keeps its own method on /token/mfa — each emitter names itself.
const loginMethod = "mfa"

// emitMFAFailed reports a wrong second factor as a login.failed so lockout
// counts MFA brute force the way it counts password brute force. Before
// this, a 6-digit code faced no limit at all: the plugin has no rate
// limiter of its own, and no event ever reached one.
//
// Fire-and-forget by design: the caller's response is already fixed at the
// opaque 401, so a Block decision must not be allowed to change it (that
// would tell an attacker when the threshold was crossed). The lock still
// takes effect at the next /login or /token, which is where lockout blocks.
//
// Only called with a userID resolved from a CONSUMED pending session — an
// attacker cannot drive another account's counter without first passing
// that account's password.
func emitMFAFailed(ctx context.Context, host plugin.PluginHost, userID string) {
	if host == nil || userID == "" {
		return
	}
	uid := userID
	method := loginMethod
	reason := "bad-mfa-code"
	_, _ = host.Emit(ctx, events.AuthEvent{
		Type:   events.EventLoginFailed,
		UserID: &uid,
		Method: &method,
		Reason: &reason,
	})
}

// decBlockStatus / decBlockMessage map a Block decision onto an HTTP
// response the same way the email-password and bearer login paths do, so a
// lockout 429 reads identically wherever a login is finished.
func decBlockStatus(d events.Decision) int {
	if d.BlockStatus == 0 {
		return http.StatusForbidden
	}
	return d.BlockStatus
}

func decBlockMessage(d events.Decision) string {
	if d.BlockMessage == "" {
		return "request blocked"
	}
	return d.BlockMessage
}

// mfaCompletedEvent builds the login.succeeded that marks a stepped-up
// login as COMPLETE. The MetaMFAVerified marker both tells observers the
// login really finished and tells this plugin's own gate to stand down
// instead of opening another challenge.
func mfaCompletedEvent(userID, email string, ip *string, method string) events.AuthEvent {
	uid := userID
	m := method
	ev := events.AuthEvent{
		Type:      events.EventLoginSucceeded,
		UserID:    &uid,
		IPAddress: ip,
		Method:    &m,
		Metadata:  events.MFACompleted(),
	}
	if email != "" {
		e := email
		ev.Email = &e
	}
	return ev
}
