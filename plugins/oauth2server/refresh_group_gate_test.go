package oauth2server_test

// client.EnforceGroupAssignment is the Okta-style "is this person entitled to
// this application" gate. It is applied at /oauth/authorize (authorize.go) and,
// since the device flow was fixed, at the device approval leg — but NOT in
// grantRefreshToken (token.go), which is the leg every long-lived integration
// actually runs.
//
// grantRefreshToken re-checks a great deal on each rotation: the client
// binding, reuse, expiry, the consented scope ceiling and
// domain.User.CanAuthenticate. The one thing it never re-asks is the question
// the gate exists to answer. So removing a leaver from the assigned group —
// the per-application control an admin reaches for precisely when they do NOT
// want to ban the account outright — stops nothing: the RP keeps exchanging
// its refresh token for access tokens and id_tokens carrying the groups claim
// for that application for up to the refresh TTL (30 days), and every rotation
// pushes the window forward, so the entitlement is effectively permanent.
//
// The refusal must also be a no-op on the family: re-adding the user has to
// restore the RP without a full re-authorization, and a policy refusal that
// revoked the family would turn "removed from a group by mistake" into a
// forced re-consent for every user of the app. Hence the assertion below that
// the row is NOT revoked.
//
// POSITIVE CONTROLS: the same rotation must succeed while the user IS
// assigned, and a client that never opted into the gate must be completely
// unaffected by the same group removal.

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/auth"
)

// grantWithRefresh runs the authorization-code flow to completion and returns
// the refresh token the client would store.
func (h *harness) grantWithRefresh(t *testing.T, userCookie, clientID, clientSecret, verifier string) string {
	t.Helper()
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "openid groups", challenge, "st", "n")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	status, body := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("authorization_code exchange: status=%d body=%v", status, body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("authorization_code exchange returned no refresh_token: %v", body)
	}
	return rt
}

func (h *harness) refreshGrant(t *testing.T, clientID, clientSecret, refreshToken string) (int, map[string]any) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	return h.postForm(t, "/api/auth/oauth/token", form, "", "")
}

// TestRefresh_RefusedAfterGroupRemoval is the regression.
func TestRefresh_RefusedAfterGroupRemoval(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, adminCookie := h.seedUser(t, "rg-admin@idp.test", "admin")
	uid, userCookie := h.seedUser(t, "rg-user@idp.test", "user")
	// A colleague of the leaver who stays assigned — the positive control for
	// the very same client.
	stayID, stayCookie := h.seedUser(t, "rg-stays@idp.test", "user")

	clientID, clientSecret, _ := h.createClient(t, adminCookie, `{
		"name":"gated",
		"redirect_uris":["https://app.example/callback"],
		"grant_types":["authorization_code","refresh_token"],
		"scopes":["openid","groups"],
		"is_public":false,
		"token_endpoint_auth_method":"client_secret_post",
		"enforce_group_assignment":true
	}`)
	groupID := h.seedAssignedGroup(t, clientID)
	if err := h.repo.AddGroupMember(ctx, groupID, uid, now); err != nil {
		t.Fatalf("add group member: %v", err)
	}
	if err := h.repo.AddGroupMember(ctx, groupID, stayID, now); err != nil {
		t.Fatalf("add colleague to group: %v", err)
	}

	refreshToken := h.grantWithRefresh(t, userCookie, clientID, clientSecret, "group-gate-verifier-43-chars-long-enough-ok")
	stayRefresh := h.grantWithRefresh(t, stayCookie, clientID, clientSecret, "group-gate-colleague-verifier-43-chars-ok-x")

	// POSITIVE CONTROL: while assigned, rotation works.
	status, body := h.refreshGrant(t, clientID, clientSecret, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("control: an assigned user must be able to rotate, got %d %v", status, body)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" {
		t.Fatalf("control: rotation returned no refresh_token: %v", body)
	}

	// The leaver is removed from the application's group — not banned, not
	// suspended: this is the per-application control.
	if err := h.repo.RemoveGroupMember(ctx, groupID, uid); err != nil {
		t.Fatalf("remove group member: %v", err)
	}

	status, body = h.refreshGrant(t, clientID, clientSecret, rotated)
	if _, ok := body["access_token"]; ok {
		t.Errorf("an unassigned user's refresh token still minted an access token for the gated application: status=%d body=%v", status, body)
	}
	if _, ok := body["id_token"]; ok {
		t.Errorf("an unassigned user's refresh token still minted an id_token (groups claim included) for the gated application: %v", body)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("expected invalid_grant after the group removal, got status=%d body=%v", status, body)
	}

	// The refusal must NOT burn the family: re-adding the user has to restore
	// the RP without a full re-authorization.
	stored, err := h.repo.GetRefreshTokenByHash(ctx, auth.HashToken(rotated))
	if err != nil {
		t.Fatalf("look up presented refresh token: %v", err)
	}
	if stored.Revoked {
		t.Errorf("the policy refusal revoked the presented refresh token; re-assigning the user must restore the client without a full re-authorization")
	}

	// POSITIVE CONTROL: the colleague who is STILL assigned keeps rotating on
	// the very same gated client, so the gate cannot pass by refusing everyone.
	status, body = h.refreshGrant(t, clientID, clientSecret, stayRefresh)
	if status != http.StatusOK {
		t.Fatalf("control: a still-assigned user must be able to rotate, got %d %v", status, body)
	}
	if _, ok := body["access_token"]; !ok {
		t.Fatalf("control: still-assigned user got no access token: %v", body)
	}
}

// TestRefresh_UnaffectedWhenGateOff is the second POSITIVE CONTROL: a client
// that never set enforce_group_assignment must see no behaviour change at all
// when the same user is removed from the same group.
func TestRefresh_UnaffectedWhenGateOff(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, adminCookie := h.seedUser(t, "ug-admin@idp.test", "admin")
	uid, userCookie := h.seedUser(t, "ug-user@idp.test", "user")

	clientID, clientSecret, _ := h.createClient(t, adminCookie, `{
		"name":"ungated",
		"redirect_uris":["https://app.example/callback"],
		"grant_types":["authorization_code","refresh_token"],
		"scopes":["openid","groups"],
		"is_public":false,
		"token_endpoint_auth_method":"client_secret_post"
	}`)
	groupID := h.seedAssignedGroup(t, clientID)
	if err := h.repo.AddGroupMember(ctx, groupID, uid, now); err != nil {
		t.Fatalf("add group member: %v", err)
	}

	refreshToken := h.grantWithRefresh(t, userCookie, clientID, clientSecret, "ungated-verifier-43-characters-long-enough-x")

	if err := h.repo.RemoveGroupMember(ctx, groupID, uid); err != nil {
		t.Fatalf("remove group member: %v", err)
	}
	status, body := h.refreshGrant(t, clientID, clientSecret, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("a client without enforce_group_assignment must be unaffected by group membership, got %d %v", status, body)
	}
	if _, ok := body["access_token"]; !ok {
		t.Fatalf("ungated client got no access token on rotation: %v", body)
	}
}
