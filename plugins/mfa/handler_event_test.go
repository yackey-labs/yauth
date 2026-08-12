package mfa

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// enrolledUser gives r a user with a VERIFIED TOTP secret. The gate only
// checks that such a row exists — it never decrypts it — so the ciphertext
// can be arbitrary.
func enrolledUser(t *testing.T, r *memrepo.Repo) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	userID := uuid.NewString()
	if _, err := r.CreateUser(ctx, domain.NewUser{
		ID: userID, Email: "alice@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := r.CreateTOTP(ctx, domain.NewTOTPSecret{
		ID: uuid.NewString(), UserID: userID,
		EncryptedSecret: "not-a-real-secret",
		Verified:        true, CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateTOTP: %v", err)
	}
	return userID
}

func succeeded(userID string) events.AuthEvent {
	uid := userID
	return events.AuthEvent{Type: events.EventLoginSucceeded, UserID: &uid}
}

// TestLoginGate_ChallengesPasswordVerifiedLogin is the baseline: a
// login.succeeded that only means "password verified" must be turned into a
// challenge.
func TestLoginGate_ChallengesPasswordVerifiedLogin(t *testing.T) {
	r := memrepo.New()
	userID := enrolledUser(t, r)
	h := &loginEventHandler{repo: r, pendingSessionTTL: time.Minute}

	dec, err := h.Handle(context.Background(), succeeded(userID))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if dec.Kind != events.DecisionKindRequireMfa || dec.PendingSessionID == "" {
		t.Fatalf("expected a RequireMfa decision with a pending session, got %+v", dec)
	}
}

// TestLoginGate_StandsDownForItsOwnCompletion is the loop guard. Completing
// a challenge emits its own login.succeeded so that lockout clears; if the
// gate treated that like any other one it would mint a fresh challenge and
// the client would step up forever.
func TestLoginGate_StandsDownForItsOwnCompletion(t *testing.T) {
	r := memrepo.New()
	userID := enrolledUser(t, r)
	h := &loginEventHandler{repo: r, pendingSessionTTL: time.Minute}

	ev := succeeded(userID)
	ev.Metadata = events.MFACompleted()

	dec, err := h.Handle(context.Background(), ev)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if dec.Kind != events.DecisionKindContinue {
		t.Fatalf("the gate re-challenged its own completion — that is the infinite loop: %+v", dec)
	}
	if dec.PendingSessionID != "" {
		t.Fatalf("a completion event minted a pending session: %+v", dec)
	}
}

// TestLoginGate_MarkerMustBeBoolTrue: a stray metadata value of another
// type (or false) must NOT be read as "already verified" — the gate fails
// closed and still challenges.
func TestLoginGate_MarkerMustBeBoolTrue(t *testing.T) {
	r := memrepo.New()
	userID := enrolledUser(t, r)
	h := &loginEventHandler{repo: r, pendingSessionTTL: time.Minute}

	for name, v := range map[string]any{
		"string": "true",
		"false":  false,
		"number": 1,
		"nil":    nil,
	} {
		ev := succeeded(userID)
		ev.Metadata = map[string]any{events.MetaMFAVerified: v}
		dec, err := h.Handle(context.Background(), ev)
		if err != nil {
			t.Fatalf("%s: Handle: %v", name, err)
		}
		if dec.Kind != events.DecisionKindRequireMfa {
			t.Fatalf("%s: a non-true marker skipped the second factor: %+v", name, dec)
		}
	}
}

// TestLoginGate_IgnoresOtherEvents keeps the gate narrow.
func TestLoginGate_IgnoresOtherEvents(t *testing.T) {
	r := memrepo.New()
	userID := enrolledUser(t, r)
	h := &loginEventHandler{repo: r, pendingSessionTTL: time.Minute}

	for _, typ := range []events.EventType{
		events.EventLoginAttempt, events.EventLoginFailed, events.EventLogout,
	} {
		ev := succeeded(userID)
		ev.Type = typ
		dec, err := h.Handle(context.Background(), ev)
		if err != nil {
			t.Fatalf("%s: Handle: %v", typ, err)
		}
		if dec.Kind != events.DecisionKindContinue {
			t.Fatalf("%s: unexpected decision %+v", typ, dec)
		}
	}
}
