package scim

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
)

// seedScimUser creates a user via the SCIM API and returns its id.
func seedScimUser(t *testing.T, app *testApp, email string) string {
	t.Helper()
	resp := app.do(t, "POST", usersPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":  []string{CoreUserSchema},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("seed user %s: %d", email, resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	return m["id"].(string)
}

// TestScim_ActiveFalse_GloballySuspends proves that SCIM active:false drives a
// global suspension (instant lockout) — not just an org membership status flip.
func TestScim_PatchActiveFalse_GloballySuspends(t *testing.T) {
	app := newTestApp(t)
	uid := seedScimUser(t, app, "deprov@x.com")

	patch := app.do(t, "PATCH", userPath(app.orgA.orgID, uid), app.orgA.apiKey, map[string]any{
		"schemas":    []string{PatchOpSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	})
	if patch.StatusCode != http.StatusOK {
		t.Fatalf("patch active:false status %d", patch.StatusCode)
	}
	patch.Body.Close()

	u, err := app.repo.GetUserByID(context.Background(), uid)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.SuspendedAt == nil {
		t.Fatalf("expected global suspended_at set after active:false")
	}
	if u.SuspendedReason == nil || *u.SuspendedReason != scimSuspendReason {
		t.Fatalf("expected suspended_reason=%q, got %v", scimSuspendReason, u.SuspendedReason)
	}

	// active:true clears the SCIM-originated suspension.
	patch = app.do(t, "PATCH", userPath(app.orgA.orgID, uid), app.orgA.apiKey, map[string]any{
		"schemas":    []string{PatchOpSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}},
	})
	if patch.StatusCode != http.StatusOK {
		t.Fatalf("patch active:true status %d", patch.StatusCode)
	}
	patch.Body.Close()

	u, err = app.repo.GetUserByID(context.Background(), uid)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.SuspendedAt != nil {
		t.Fatalf("expected suspension cleared after active:true, got %v", u.SuspendedAt)
	}
}

// TestScim_ActiveTrue_DoesNotClearAdminSuspend proves the offboarding footgun is
// closed: an admin's manual suspension (non-SCIM reason) is NOT silently undone
// by a routine SCIM sync where active defaults to true.
func TestScim_PutActiveTrue_DoesNotClearAdminSuspend(t *testing.T) {
	app := newTestApp(t)
	uid := seedScimUser(t, app, "vip@x.com")

	// Admin manually offboards with a non-SCIM reason.
	now := time.Now().UTC()
	nowPtr := &now
	reason := "terminated by security"
	reasonPtr := &reason
	if _, err := app.repo.UpdateUser(context.Background(), uid, domain.UpdateUser{
		SuspendedAt:     &nowPtr,
		SuspendedReason: &reasonPtr,
		UpdatedAt:       &now,
	}); err != nil {
		t.Fatalf("admin suspend: %v", err)
	}

	// Routine SCIM PUT profile sync — no active field → defaults to true.
	put := app.do(t, "PUT", userPath(app.orgA.orgID, uid), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreUserSchema},
		"userName":    "vip@x.com",
		"emails":      []map[string]any{{"value": "vip@x.com", "primary": true}},
		"displayName": "VIP Renamed",
	})
	if put.StatusCode != http.StatusOK {
		t.Fatalf("put status %d", put.StatusCode)
	}
	put.Body.Close()

	u, err := app.repo.GetUserByID(context.Background(), uid)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.SuspendedAt == nil {
		t.Fatalf("admin suspension was silently cleared by SCIM sync — footgun!")
	}
	if u.SuspendedReason == nil || *u.SuspendedReason != reason {
		t.Fatalf("expected admin reason preserved, got %v", u.SuspendedReason)
	}
}
