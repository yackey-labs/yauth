package bearer

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
)

// --- doubles -------------------------------------------------------------

// stubHandler is an events.Handler driven by a closure, standing in for the
// mfa / lockout plugins' handlers.
type stubHandler struct {
	fn func(context.Context, events.AuthEvent) (events.Decision, error)
}

func (s stubHandler) Handle(ctx context.Context, ev events.AuthEvent) (events.Decision, error) {
	return s.fn(ctx, ev)
}

// requireMfaOn returns a handler that answers login.succeeded with a
// RequireMfa decision carrying pendingID — what plugins/mfa does for a
// TOTP-enrolled user. Like the real gate it stands down for the marked
// completion event; that marker is what stops the challenge repeating.
func requireMfaOn(pendingID string) stubHandler {
	return stubHandler{fn: func(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
		if ev.Type == events.EventLoginSucceeded && ev.UserID != nil && !ev.MFAVerified() {
			return events.RequireMfa(*ev.UserID, pendingID), nil
		}
		return events.Continue(), nil
	}}
}

// requireMfaAlways is a deliberately broken gate: it ignores the completion
// marker and demands a second factor even for the event saying one was just
// verified. Nothing in-tree behaves this way — it stands in for a
// third-party handler that would otherwise leave the client in an infinite
// challenge loop.
func requireMfaAlways(pendingID string) stubHandler {
	return stubHandler{fn: func(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
		if ev.Type == events.EventLoginSucceeded && ev.UserID != nil {
			return events.RequireMfa(*ev.UserID, pendingID), nil
		}
		return events.Continue(), nil
	}}
}

// stubVerifier stands in for the mfa plugin's plugin.MFAVerifier. It models
// the real contract: the pending session is consumed on the FIRST use,
// whether or not the code was right.
type stubVerifier struct {
	userID  string
	pending string
	code    string
	spent   bool
}

func (v *stubVerifier) VerifyPendingChallenge(_ context.Context, pendingSessionID, code string) (string, bool, error) {
	if v.spent || pendingSessionID != v.pending {
		return "", false, nil
	}
	v.spent = true
	if code != v.code {
		return "", false, nil
	}
	return v.userID, true, nil
}

var _ plugin.MFAVerifier = (*stubVerifier)(nil)

// eventTypes lists the event types the host saw, in order.
func (h *fakeHost) eventTypes() []events.EventType {
	out := make([]events.EventType, 0, len(h.emitted))
	for _, e := range h.emitted {
		out = append(out, e.Type)
	}
	return out
}

func (h *fakeHost) lastReason() string {
	for i := len(h.emitted) - 1; i >= 0; i-- {
		if h.emitted[i].Reason != nil {
			return *h.emitted[i].Reason
		}
	}
	return ""
}

func decodeIssue(t *testing.T, body []byte) issueResponse {
	t.Helper()
	var out issueResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	return out
}

// --- the bug this file exists for ---------------------------------------

// TestToken_MFARequired_IssuesNoTokens is the regression test for the MFA
// bypass: a TOTP-enrolled account used to receive a full token pair from
// /token on the password alone, because bearer emitted no auth events at
// all. It must now answer with the step-up body and mint nothing.
func TestToken_MFARequired_IssuesNoTokens(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "correct horse battery staple")
	h.host.RegisterEventGate(requireMfaOn("pending-abc"))

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"correct horse battery staple"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	body := decodeIssue(t, resp.Body.Bytes())
	if !body.RequireMfa || body.PendingSessionID != "pending-abc" {
		t.Fatalf("expected require_mfa+pending_session_id, got %+v", body)
	}
	if body.AccessToken != "" || body.RefreshToken != "" {
		t.Fatalf("MFA step-up must issue NO tokens, got %+v", body)
	}
	if len(fr.refreshTokens) != 0 {
		t.Fatalf("MFA step-up persisted %d refresh tokens; want 0", len(fr.refreshTokens))
	}
}

// TestToken_NoMFA_BodyUnchanged pins the backwards-compatible contract: with
// no handler interposing, one /token call still returns exactly
// access_token + refresh_token + token_type + expires_in and nothing else.
func TestToken_NoMFA_BodyUnchanged(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]bool{"access_token": true, "refresh_token": true, "token_type": true, "expires_in": true}
	if len(raw) != len(want) {
		t.Fatalf("unexpected keys in success body: %v", raw)
	}
	for k := range raw {
		if !want[k] {
			t.Fatalf("unexpected key %q in success body: %v", k, raw)
		}
	}
}

// TestTokenMFA_CompletesChallenge walks the whole native flow: /token hands
// back a pending session, /token/mfa exchanges it plus a code for a usable
// token pair.
func TestTokenMFA_CompletesChallenge(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventGate(requireMfaOn("pending-abc"))
	h.host.RegisterMFAVerifier(&stubVerifier{userID: user.ID, pending: "pending-abc", code: "123456"})

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	pending := decodeIssue(t, resp.Body.Bytes()).PendingSessionID

	resp = h.do(t, "POST", "/token/mfa", `{"pending_session_id":"`+pending+`","code":"123456"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var tr tokenResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &tr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if tr.AccessToken == "" || tr.RefreshToken == "" || tr.TokenType != "Bearer" {
		t.Fatalf("expected a full token pair, got %+v", tr)
	}
	if tr.ExpiresIn != int(h.cfg.AccessTTL.Seconds()) {
		t.Fatalf("expires_in mismatch: %d", tr.ExpiresIn)
	}
	parsed, err := verifyAccessToken(h.cfg.JWTSecret, tr.AccessToken, h.cfg)
	if err != nil {
		t.Fatalf("verify access: %v", err)
	}
	if parsed.UserID != user.ID {
		t.Fatalf("sub mismatch: got %q want %q", parsed.UserID, user.ID)
	}
	if len(fr.refreshTokens) != 1 {
		t.Fatalf("expected exactly one refresh token row, got %d", len(fr.refreshTokens))
	}
}

// TestTokenMFA_WrongCodeBurnsChallenge covers both failure modes the
// exchange has to reject: a wrong code, and the replay of a pending session
// that has already been spent.
func TestTokenMFA_WrongCodeBurnsChallenge(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventGate(requireMfaOn("pending-abc"))
	h.host.RegisterMFAVerifier(&stubVerifier{userID: user.ID, pending: "pending-abc", code: "123456"})

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	pending := decodeIssue(t, resp.Body.Bytes()).PendingSessionID

	resp = h.do(t, "POST", "/token/mfa", `{"pending_session_id":"`+pending+`","code":"000000"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: expected 401, got %d body=%s", resp.Code, resp.Body.String())
	}
	// The challenge is single-use: the right code no longer works either.
	resp = h.do(t, "POST", "/token/mfa", `{"pending_session_id":"`+pending+`","code":"123456"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("replay: expected 401, got %d body=%s", resp.Code, resp.Body.String())
	}
	if len(fr.refreshTokens) != 0 {
		t.Fatalf("a failed challenge minted %d refresh tokens; want 0", len(fr.refreshTokens))
	}
}

// TestTokenMFA_EmitsCompletion proves the second leg emits the marked
// login.succeeded that observers (lockout's clear, audit, webhooks) need to
// see a login as finished — and that it is marked, so the MFA gate stands
// down instead of re-challenging.
func TestTokenMFA_EmitsCompletion(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventGate(requireMfaOn("pending-abc"))
	h.host.RegisterMFAVerifier(&stubVerifier{userID: user.ID, pending: "pending-abc", code: "123456"})

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	pending := decodeIssue(t, resp.Body.Bytes()).PendingSessionID

	before := len(h.host.emitted)
	resp = h.do(t, "POST", "/token/mfa", `{"pending_session_id":"`+pending+`","code":"123456"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var completion *events.AuthEvent
	for i := before; i < len(h.host.emitted); i++ {
		e := h.host.emitted[i]
		if e.Type == events.EventLoginSucceeded {
			completion = &h.host.emitted[i]
		}
	}
	if completion == nil {
		t.Fatalf("no login.succeeded emitted on MFA completion; lockout would never clear")
	}
	if !completion.MFAVerified() {
		t.Fatalf("completion event is missing the mfa_verified marker: %+v", completion.Metadata)
	}
	if completion.UserID == nil || *completion.UserID != user.ID {
		t.Fatalf("completion must carry the user id, got %+v", completion)
	}
}

// TestTokenMFA_NoInfiniteChallengeLoop: a handler that ignores the
// completion marker must NOT be able to hand the client another challenge.
// The exchange fails closed instead — no tokens, no second pending session.
func TestTokenMFA_NoInfiniteChallengeLoop(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventGate(requireMfaAlways("pending-abc"))
	h.host.RegisterMFAVerifier(&stubVerifier{userID: user.ID, pending: "pending-abc", code: "123456"})

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	pending := decodeIssue(t, resp.Body.Bytes()).PendingSessionID

	resp = h.do(t, "POST", "/token/mfa", `{"pending_session_id":"`+pending+`","code":"123456"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected a closed 403, got %d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "pending_session_id") {
		t.Fatalf("the exchange handed back another challenge — that is the loop: %s", resp.Body.String())
	}
	if len(fr.refreshTokens) != 0 {
		t.Fatalf("failed-closed exchange minted %d refresh tokens; want 0", len(fr.refreshTokens))
	}
}

// TestTokenMFA_HonoursBlockOnCompletion: a Block on the completion event
// (e.g. the account was locked meanwhile) must stop the token pair.
func TestTokenMFA_HonoursBlockOnCompletion(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventGate(requireMfaOn("pending-abc"))
	h.host.RegisterMFAVerifier(&stubVerifier{userID: user.ID, pending: "pending-abc", code: "123456"})

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	pending := decodeIssue(t, resp.Body.Bytes()).PendingSessionID

	h.host.RegisterEventHandler(stubHandler{fn: func(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
		if ev.Type == events.EventLoginSucceeded && ev.MFAVerified() {
			return events.Block(http.StatusTooManyRequests, "Account locked"), nil
		}
		return events.Continue(), nil
	}})

	resp = h.do(t, "POST", "/token/mfa", `{"pending_session_id":"`+pending+`","code":"123456"}`, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", resp.Code, resp.Body.String())
	}
	if len(fr.refreshTokens) != 0 {
		t.Fatalf("blocked completion minted %d refresh tokens; want 0", len(fr.refreshTokens))
	}
}

// TestTokenMFA_UnknownPendingSession rejects an id that was never issued.
func TestTokenMFA_UnknownPendingSession(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterMFAVerifier(&stubVerifier{userID: user.ID, pending: "pending-abc", code: "123456"})

	resp := h.do(t, "POST", "/token/mfa", `{"pending_session_id":"nope","code":"123456"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestTokenMFA_FailsClosedWithoutVerifier: no mfa plugin loaded means no
// verifier, and the exchange must refuse rather than wave the caller
// through.
func TestTokenMFA_FailsClosedWithoutVerifier(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")

	resp := h.do(t, "POST", "/token/mfa", `{"pending_session_id":"pending-abc","code":"123456"}`, nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
	if len(fr.refreshTokens) != 0 {
		t.Fatalf("expected no tokens minted, got %d", len(fr.refreshTokens))
	}
}

// TestTokenMFA_RequiresBothFields keeps the business-400 shape.
func TestTokenMFA_RequiresBothFields(t *testing.T) {
	h, _, _ := newHarness(t)
	resp := h.do(t, "POST", "/token/mfa", `{"pending_session_id":"pending-abc"}`, nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestTokenMFA_ReRunsAccountGates: a ban landing between the two legs must
// stop the exchange, and a must_change_password user must not escape the
// gate through the MFA leg either.
func TestTokenMFA_ReRunsAccountGates(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventGate(requireMfaOn("pending-abc"))
	h.host.RegisterMFAVerifier(&stubVerifier{userID: user.ID, pending: "pending-abc", code: "123456"})

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	pending := decodeIssue(t, resp.Body.Bytes()).PendingSessionID

	u := fr.users[user.ID]
	u.Banned = true
	fr.users[user.ID] = u

	resp = h.do(t, "POST", "/token/mfa", `{"pending_session_id":"`+pending+`","code":"123456"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("banned: expected 403, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestTokenMFA_MustChangePasswordBlocked(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterMFAVerifier(&stubVerifier{userID: user.ID, pending: "pending-abc", code: "123456"})
	if err := fr.SetUserMustChangePassword(context.Background(), user.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}

	resp := h.do(t, "POST", "/token/mfa", `{"pending_session_id":"pending-abc","code":"123456"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), middleware.MustChangePasswordDetail) {
		t.Fatalf("expected must-change detail, got %s", resp.Body.String())
	}
}

// --- lockout / audit: the events themselves ------------------------------

// TestToken_EmitsLoginFailed_BadPassword is the regression test for the
// lockout bypass: without a login.failed event, /token was an unthrottled
// password oracle.
func TestToken_EmitsLoginFailed_BadPassword(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "right-password")

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"wrong"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
	got := h.host.eventTypes()
	want := []events.EventType{events.EventLoginAttempt, events.EventLoginFailed}
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
	if r := h.host.lastReason(); r != "bad-password" {
		t.Fatalf("login.failed reason = %q, want bad-password", r)
	}
	last := h.host.emitted[len(h.host.emitted)-1]
	if last.UserID == nil || *last.UserID != user.ID {
		t.Fatalf("login.failed must carry the user id, got %+v", last)
	}
	if last.Method == nil || *last.Method != loginMethod {
		t.Fatalf("login.failed method = %+v, want %q", last.Method, loginMethod)
	}
}

// TestToken_EmitsLoginFailed_UnknownUser keeps the enumeration defence: an
// unknown address still emits (so lockout/audit see the attempt) and still
// answers with the same opaque 401.
func TestToken_EmitsLoginFailed_UnknownUser(t *testing.T) {
	h, _, _ := newHarness(t)

	resp := h.do(t, "POST", "/token", `{"email":"nobody@example.com","password":"wrong"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "invalid email or password") {
		t.Fatalf("expected the opaque 401 detail, got %s", resp.Body.String())
	}
	if r := h.host.lastReason(); r != "user-not-found" {
		t.Fatalf("login.failed reason = %q, want user-not-found", r)
	}
}

// TestToken_BlockDecisionOnAttempt proves a locked account is now stopped at
// /token — with the correct password — exactly as it is at /login.
func TestToken_BlockDecisionOnAttempt(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventHandler(stubHandler{fn: func(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
		if ev.Type == events.EventLoginAttempt {
			return events.Block(http.StatusTooManyRequests, "Account locked"), nil
		}
		return events.Continue(), nil
	}})

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "Account locked") {
		t.Fatalf("expected the block message, got %s", resp.Body.String())
	}
	if len(fr.refreshTokens) != 0 {
		t.Fatalf("blocked login minted %d refresh tokens; want 0", len(fr.refreshTokens))
	}
}

// TestToken_BlockDecisionOnFailure lets a handler turn the Nth bad password
// into its own status (lockout's 429) instead of the plain 401.
func TestToken_BlockDecisionOnFailure(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventHandler(stubHandler{fn: func(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
		if ev.Type == events.EventLoginFailed {
			return events.Block(http.StatusTooManyRequests, "Account locked"), nil
		}
		return events.Continue(), nil
	}})

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"nope"}`, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestToken_BadPassword_NoLoginSucceeded: the step-up decision must never be
// reachable without the password. A caller that fails the password sees the
// plain 401 and no login.succeeded is emitted, so nothing can leak that the
// account has a second factor.
func TestToken_BadPassword_NoLoginSucceeded(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	h.host.RegisterEventGate(requireMfaOn("pending-abc"))

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"wrong"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
	if strings.Contains(resp.Body.String(), "pending_session_id") || strings.Contains(resp.Body.String(), "require_mfa") {
		t.Fatalf("bad password leaked the MFA step-up: %s", resp.Body.String())
	}
	for _, e := range h.host.emitted {
		if e.Type == events.EventLoginSucceeded {
			t.Fatalf("login.succeeded emitted for a failed password")
		}
	}
}
