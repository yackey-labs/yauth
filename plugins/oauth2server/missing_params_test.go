package oauth2server_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// An invalid_request that lists every parameter the handler checks, whichever
// one is actually absent, points whoever is debugging at the wrong thing. This
// cost real time against an oauth2-proxy client that sent a perfectly good
// client_id and redirect_uri but no code_challenge: the reply named all three,
// so it read as a broken client registration.
//
// These tests pin the description to the parameters that are genuinely missing.
// The error CODE is asserted alongside every case — RFC 6749 §5.2 makes that
// the machine-readable field, and it must stay invalid_request.

// authorizeErr issues GET /oauth/authorize with q as the query string, as an
// authenticated user (the handler refuses anonymous callers before it looks at
// any parameter), and returns the RFC 6749 error code and description.
func authorizeErr(t *testing.T, h *harness, cookie string, q url.Values) (status int, code, desc string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer res.Body.Close()
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode authorize error: %v", err)
	}
	return res.StatusCode, body.Error, body.Description
}

func TestAuthorizeMissingParamsNamesOnlyWhatIsMissing(t *testing.T) {
	h := newHarness(t)
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	const (
		clientID    = "some-client-id"
		redirectURI = "https://app.example/callback"
		challenge   = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)

	for _, tc := range []struct {
		name    string
		params  map[string]string
		wantDsc string
	}{
		{
			// The reported case: two good parameters, one absent, and the old
			// message implicated all three.
			"only code_challenge is absent",
			map[string]string{"client_id": clientID, "redirect_uri": redirectURI},
			"code_challenge is required",
		},
		{
			"only client_id is absent",
			map[string]string{"redirect_uri": redirectURI, "code_challenge": challenge},
			"client_id is required",
		},
		{
			"only redirect_uri is absent",
			map[string]string{"client_id": clientID, "code_challenge": challenge},
			"redirect_uri is required",
		},
		{
			"two absent are listed as two",
			map[string]string{"client_id": clientID},
			"redirect_uri and code_challenge are required",
		},
		{
			// Listing all three is still right when all three are missing.
			"all three absent",
			map[string]string{},
			"client_id, redirect_uri and code_challenge are required",
		},
		{
			// Empty-valued parameters are absent parameters; the check has
			// always been literal emptiness and stays that way.
			"a present-but-empty parameter counts as missing",
			map[string]string{"client_id": clientID, "redirect_uri": redirectURI, "code_challenge": ""},
			"code_challenge is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{"response_type": {"code"}}
			for k, v := range tc.params {
				q.Set(k, v)
			}
			status, code, desc := authorizeErr(t, h, userCookie, q)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
			if code != "invalid_request" {
				t.Fatalf("error = %q, want invalid_request", code)
			}
			if desc != tc.wantDsc {
				t.Fatalf("error_description = %q, want %q", desc, tc.wantDsc)
			}
		})
	}
}

func TestTokenAuthCodeMissingParamsNamesOnlyWhatIsMissing(t *testing.T) {
	h := newHarness(t)

	const (
		code        = "an-authorization-code"
		redirectURI = "https://app.example/callback"
		verifier    = "this-is-a-43-character-pkce-verifier-string-x"
	)

	for _, tc := range []struct {
		name    string
		params  map[string]string
		wantDsc string
	}{
		{
			"only code_verifier is absent",
			map[string]string{"code": code, "redirect_uri": redirectURI},
			"code_verifier is required",
		},
		{
			"only code is absent",
			map[string]string{"redirect_uri": redirectURI, "code_verifier": verifier},
			"code is required",
		},
		{
			"two absent are listed as two",
			map[string]string{"redirect_uri": redirectURI},
			"code and code_verifier are required",
		},
		{
			"all three absent",
			map[string]string{},
			"code, redirect_uri and code_verifier are required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"grant_type": {"authorization_code"}}
			for k, v := range tc.params {
				form.Set(k, v)
			}
			// No client credentials: the parameter check runs before client
			// authentication, so this never reaches the repository.
			status, body := h.postForm(t, "/api/auth/oauth/token", form, "", "")
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %v)", status, body)
			}
			if got, _ := body["error"].(string); got != "invalid_request" {
				t.Fatalf("error = %q, want invalid_request", got)
			}
			if got, _ := body["error_description"].(string); got != tc.wantDsc {
				t.Fatalf("error_description = %q, want %q", got, tc.wantDsc)
			}
		})
	}
}
