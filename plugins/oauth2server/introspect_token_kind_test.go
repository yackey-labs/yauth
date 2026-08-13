// Regression suite for token-kind confusion at the introspection endpoint.
//
// verifyAccessJWT verified the signature and nothing else. Every JWT this
// deployment mints is signed by the same key — access tokens, id_tokens, DCR
// registration-access tokens — so introspection answered
// `{"active":true,"token_type":"access_token"}` for all three, with
// `token_type` hard-coded at the response struct rather than derived from the
// token.
//
// That matters because RFC 7662 introspection is exactly how a resource server
// that cannot verify the signature itself decides whether to honour a
// credential. An id_token is handed to the relying party and, in the
// authorization-code flow, reaches the browser; a registration-access token
// goes to whoever called DCR. Either one presented to such a resource server
// used to come back as a live access token for the user — and with no `scope`
// and no `client_id` in the response, the RS could not even scope-limit what
// it then granted.
//
// The bearer resolver has required a positive `token_use` since #85
// (verifyAsymAccessToken). This suite pins the same gate on the introspection
// and revocation paths, which share verifyAccessJWT.
package oauth2server_test

import (
	"net/http"
	"net/url"
	"testing"
)

// mintIDTokenAndAccessToken runs a real openid authorization-code flow and
// returns both artifacts, so each case introspects a token the server actually
// issued rather than a hand-rolled fixture.
func mintIDTokenAndAccessToken(t *testing.T, h *harness) (clientID, clientSecret, idToken, accessToken string) {
	t.Helper()
	_, adminCookie := h.seedUser(t, "kind-admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "kind-alice@idp.test", "user")

	body := `{"name":"kindcheck","redirect_uris":["https://app.example/callback"],` +
		`"grant_types":["authorization_code","refresh_token"],"scopes":["openid"],` +
		`"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, clientSecret, _ = h.createClient(t, adminCookie, body)

	verifier := "introspect-kind-verifier-43-chars-here-okay"
	code := h.authorizeAndConsent(t, userCookie, clientID,
		"https://app.example/callback", "openid", pkceS256(verifier), "state-kind", "")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	status, tok := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, tok)
	}

	idToken, _ = tok["id_token"].(string)
	accessToken, _ = tok["access_token"].(string)
	if idToken == "" {
		t.Fatal("flow did not return an id_token; the openid scope should have produced one")
	}
	if accessToken == "" {
		t.Fatal("flow did not return an access_token")
	}
	return clientID, clientSecret, idToken, accessToken
}

// TestIntrospect_IDToken_ReportsInactive is the headline case: the id_token
// the client legitimately holds must not introspect as an access token.
func TestIntrospect_IDToken_ReportsInactive(t *testing.T) {
	h := newHarness(t)
	clientID, clientSecret, idToken, _ := mintIDTokenAndAccessToken(t, h)

	form := url.Values{}
	form.Set("token", idToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	status, body := h.postForm(t, "/api/auth/oauth/introspect", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("introspect: %d %v", status, body)
	}
	if active, _ := body["active"].(bool); active {
		t.Fatalf("an id_token introspected as a live access token (%v): a resource server "+
			"authorizing by introspection would honour a credential the browser holds", body)
	}
}

// TestIntrospect_AccessToken_StillReportsActive is the positive control. The
// gate must not be satisfied by reporting everything inactive.
func TestIntrospect_AccessToken_StillReportsActive(t *testing.T) {
	h := newHarness(t)
	clientID, clientSecret, _, accessToken := mintIDTokenAndAccessToken(t, h)

	form := url.Values{}
	form.Set("token", accessToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	status, body := h.postForm(t, "/api/auth/oauth/introspect", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("introspect: %d %v", status, body)
	}
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("a genuine access token must still introspect as active, got %v", body)
	}
	if tt, _ := body["token_type"].(string); tt != "access_token" {
		t.Fatalf("expected token_type=access_token, got %q", tt)
	}
}

// TestRevoke_IDToken_IsNotHonoured covers the sibling caller of
// verifyAccessJWT. Revocation writes a jti into the deny list; accepting a
// foreign token kind there lets a caller burn a jti that was never an access
// token, and (paired with the missing token-to-client binding) do it for a
// token they do not own.
func TestRevoke_IDToken_IsNotHonoured(t *testing.T) {
	h := newHarness(t)
	clientID, clientSecret, idToken, accessToken := mintIDTokenAndAccessToken(t, h)

	form := url.Values{}
	form.Set("token", idToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	// RFC 7009 §2.2 requires 200 for an unrecognised token, so the status is
	// not the assertion — the effect is.
	if status, _ := h.postForm(t, "/api/auth/oauth/revoke", form, "", ""); status != http.StatusOK {
		t.Fatalf("revoke should still answer 200 for an unrecognised token, got %d", status)
	}

	// The access token shares the id_token's `sub` and `aud`. If revocation
	// had honoured the id_token, it would have denied a jti; either way the
	// genuine access token must be untouched.
	iform := url.Values{}
	iform.Set("token", accessToken)
	iform.Set("client_id", clientID)
	iform.Set("client_secret", clientSecret)
	status, body := h.postForm(t, "/api/auth/oauth/introspect", iform, "", "")
	if status != http.StatusOK {
		t.Fatalf("introspect: %d %v", status, body)
	}
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("revoking an id_token must not disturb the real access token, got %v", body)
	}
}
