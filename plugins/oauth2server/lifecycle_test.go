package oauth2server_test

// The OAuth2 token endpoint gated the resolved user on user.Banned alone,
// so suspension — the documented offboarding kill switch, which does revoke
// sessions and refresh tokens — did not stop an authorization code, a device
// code or a refresh token from being exchanged for a fresh access token.
// introspect.go already used domain.User.CanAuthenticate, so the three mint
// paths were minting tokens introspection would report inactive.
//
// Each case asserts the refusal by its consequence: NO token of any kind in
// the response.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
)

// suspend globally disables the account, exactly as
// POST /admin/users/{id}/suspend does.
func suspend(t *testing.T, h *harness, userID string) {
	t.Helper()
	now := time.Now().UTC()
	nowPtr := &now
	reason := "offboarded"
	reasonPtr := &reason
	if _, err := h.repo.UpdateUser(context.Background(), userID, domain.UpdateUser{
		SuspendedAt:     &nowPtr,
		SuspendedReason: &reasonPtr,
		UpdatedAt:       &now,
	}); err != nil {
		t.Fatalf("suspend: %v", err)
	}
}

// assertNoTokens fails when the response carries any credential.
func assertNoTokens(t *testing.T, status int, body map[string]any) {
	t.Helper()
	if status == http.StatusOK {
		t.Fatalf("expected a refusal, got 200 %v", body)
	}
	for _, k := range []string{"access_token", "refresh_token", "id_token"} {
		if v, ok := body[k]; ok && v != "" {
			t.Fatalf("refusal still issued %s: %v", k, body)
		}
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("expected error=invalid_grant, got %v", body["error"])
	}
}

// TestAuthorizationCodeGrant_SuspendedUser_NoTokens: the code was minted
// while the user was active — suspension between consent and exchange must
// still stop the exchange.
func TestAuthorizationCodeGrant_SuspendedUser_NoTokens(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	userID, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"demo","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code","refresh_token"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	verifier := "suspend-code-verifier-43-chars-long-enough-ok"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "read", challenge, "s-susp", "")

	suspend(t, h, userID)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	status, out := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	assertNoTokens(t, status, out)
}

// TestRefreshTokenGrant_SuspendedUser_NoTokens: rotation re-reads the user,
// so suspension stops an OAuth2 refresh token at the next exchange rather
// than at its expiry.
func TestRefreshTokenGrant_SuspendedUser_NoTokens(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	userID, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"demo","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code","refresh_token"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, clientSecret, _ := h.createClient(t, adminCookie, body)

	verifier := "suspend-refresh-verifier-43-chars-long-enough"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "read", challenge, "r-susp", "")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	status, first := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("first token: %d %v", status, first)
	}
	refresh, _ := first["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token to test with: %v", first)
	}

	suspend(t, h, userID)

	rform := url.Values{}
	rform.Set("grant_type", "refresh_token")
	rform.Set("refresh_token", refresh)
	rform.Set("client_id", clientID)
	rform.Set("client_secret", clientSecret)
	status, out := h.postForm(t, "/api/auth/oauth/token", rform, "", "")
	assertNoTokens(t, status, out)
}

// TestDeviceCodeGrant_SuspendedUser_NoTokens: a device approval can be
// minutes or hours old, so the account state is re-checked at redemption.
func TestDeviceCodeGrant_SuspendedUser_NoTokens(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	userID, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"tv","redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"scopes":["read"],"is_public":true,"token_endpoint_auth_method":"none"}`
	clientID, _, _ := h.createClient(t, adminCookie, body)

	df := url.Values{}
	df.Set("client_id", clientID)
	df.Set("scope", "read")
	status, da := h.postForm(t, "/api/auth/oauth/device/code", df, "", "")
	if status != http.StatusOK {
		t.Fatalf("device_authorization: %d %v", status, da)
	}
	deviceCode := da["device_code"].(string)
	userCode := da["user_code"].(string)

	approval, _ := json.Marshal(map[string]any{"user_code": userCode})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth/device", strings.NewReader(string(approval)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("device approve: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("device approve status=%d", res.StatusCode)
	}

	suspend(t, h, userID)

	pf := url.Values{}
	pf.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	pf.Set("device_code", deviceCode)
	pf.Set("client_id", clientID)
	status, out := h.postForm(t, "/api/auth/oauth/token", pf, "", "")
	assertNoTokens(t, status, out)
}
