package oauth2server_test

// A client's registration row constrained nothing once the flow left
// /oauth/authorize.
//
// Three faces of one defect, all of them reachable over the wire on the routes
// registered in routes_huma.go:
//
//   - The device flow never looked at the client at all on the approval leg.
//     handleDeviceVerify (device.go) fetched the pending device-code row by
//     user_code, checked its expiry, and called UpdateDeviceCodeStatus. The
//     application-assignment gate — client.EnforceGroupAssignment plus
//     Repo().UserInAssignedGroup, the Okta-style "is this user entitled to this
//     app" check that handleAuthorize applies at authorize.go:132 — had exactly
//     one production caller, and the device path was not it. So a user who was
//     refused at /oauth/authorize with access_denied could take the same
//     client_id round the back through POST /oauth/device/code (which requires
//     no client authentication) and POST /oauth/device, and the token endpoint
//     would hand them an access_token and an id_token carrying the groups claim
//     for an application they are explicitly not assigned to. The approving user
//     is never even shown the client name or the scopes, contra RFC 8628 §5.4 —
//     they type a code, and the server approves blind. Second consequence: the
//     device path writes no Consent row, and backchannel_logout.go fans out over
//     ListConsentsByUserID, so the device session is invisible to the
//     ban/suspend logout fan-out and survives it.
//
//   - grant_types was decorative. It is written by the admin create endpoint, by
//     DCR and by the federation handshake, read back only for display, and
//     advertised statically in the RFC 8414 metadata document. The token
//     dispatcher (token.go:112) switches on the grant_type the CALLER asked for
//     and never consults the row, and authenticateClient takes no grant
//     argument. A confidential client registered for authorization_code only —
//     including the guided-federation client — could therefore POST
//     grant_type=client_credentials and mint itself a token whose sub is its own
//     client_id.
//
//   - The scope ceiling was void precisely where there is no human to hold it.
//     clientScopesAllowed (authorize.go:383) deliberately returns true whenever
//     the client registered no scopes, because /authorize and /device/code still
//     route through a person. grantClientCredentials (token.go:341) calls that
//     same helper directly under a comment asserting "there is no resource owner
//     on this grant, so registration IS the grant". An empty registration is the
//     common case — createClientRequest.Scopes is omitempty and rawJSON(nil)
//     marshals to null — so such a client could ask for scope=admin and get an
//     access token whose "scope" claim, the claim every downstream resource
//     server authorizes on, said admin.
//
// Every refusal below is paired with a positive control on the same harness, so
// a fix that simply breaks the device flow, client_credentials, or the empty
// registration outright cannot pass.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
)

// deviceApprove performs the user-facing POST /oauth/device (the leg a person
// hits after typing the user_code into the verification page) behind a session
// cookie, and returns the status plus decoded body.
func (h *harness) deviceApprove(t *testing.T, cookie, userCode string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"user_code": userCode})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth/device", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("device approve: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// deviceCode runs POST /oauth/device/code and returns status + body.
func (h *harness) deviceCode(t *testing.T, clientID, scope string) (int, map[string]any) {
	t.Helper()
	f := url.Values{}
	f.Set("client_id", clientID)
	if scope != "" {
		f.Set("scope", scope)
	}
	return h.postForm(t, "/api/auth/oauth/device/code", f, "", "")
}

// devicePoll runs the token endpoint's device_code grant.
func (h *harness) devicePoll(t *testing.T, clientID, deviceCode string) (int, map[string]any) {
	t.Helper()
	f := url.Values{}
	f.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	f.Set("device_code", deviceCode)
	f.Set("client_id", clientID)
	return h.postForm(t, "/api/auth/oauth/token", f, "", "")
}

// seedAssignedGroup creates an org + group and assigns the group to clientID,
// returning the group id. The client's assignment gate is only meaningful when
// at least one group is assigned to it.
func (h *harness) seedAssignedGroup(t *testing.T, clientID string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	org, err := h.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	g, err := h.repo.CreateGroup(ctx, domain.NewGroup{
		ID: uuid.NewString(), OrganizationID: org.ID, Name: "eng", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := h.repo.AssignClientGroup(ctx, clientID, g.ID, now); err != nil {
		t.Fatalf("assign group: %v", err)
	}
	return g.ID
}

// TestDeviceVerify_EnforceGroupAssignment_Denied is the discriminating test for
// the device flow's missing app-assignment gate. The SAME client, the SAME
// user: refused at /oauth/authorize, and today waved through at /oauth/device.
//
// The assertion that matters is not the status of the approval call — it is
// that no approved device-code row exists afterwards, which is proved by
// polling the token endpoint and demanding authorization_pending with no
// access_token and no id_token.
//
// POSITIVE CONTROL: once the user is added to the assigned group, the very same
// device flow must run to completion and mint tokens. A "fix" that disables the
// device grant fails here.
func TestDeviceVerify_EnforceGroupAssignment_Denied(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()

	_, adminCookie := h.seedUser(t, "dv-admin@idp.test", "admin")
	uid, userCookie := h.seedUser(t, "dv-user@idp.test", "user")

	clientID, _, _ := h.createClient(t, adminCookie, `{
		"name":"tv",
		"redirect_uris":["https://app.example/callback"],
		"grant_types":["urn:ietf:params:oauth:grant-type:device_code","authorization_code"],
		"scopes":["openid","email","groups","read"],
		"is_public":true,
		"token_endpoint_auth_method":"none",
		"enforce_group_assignment":true
	}`)
	groupID := h.seedAssignedGroup(t, clientID)

	// Baseline: the gate demonstrably works on the authorization-code path, so
	// the device result below is a gap in coverage, not a mis-seeded fixture.
	verifier := "device-gate-verifier-43-chars-long-enough-ok"
	challenge := pkceS256(verifier)
	if status, body := h.getAuthorize(t, userCookie, clientID, challenge); body["error"] != "access_denied" {
		t.Fatalf("precondition: /authorize should refuse the unassigned user, got status=%d body=%v", status, body)
	}

	// 1) Device authorization: no client authentication is required here.
	status, da := h.deviceCode(t, clientID, "openid email groups")
	if status != http.StatusOK {
		t.Fatalf("device/code: status=%d body=%v", status, da)
	}
	deviceCode, _ := da["device_code"].(string)
	userCode, _ := da["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device/code returned no codes: %v", da)
	}

	// 2) The unassigned user approves. The app-assignment gate must refuse.
	// Reported, not fatal, so the credential assertions below still run and the
	// failure output shows the whole exploit rather than only its first step.
	astatus, abody := h.deviceApprove(t, userCookie, userCode)
	if abody["error"] != "access_denied" {
		t.Errorf("device approval by an unassigned user must be refused with access_denied, got status=%d body=%v", astatus, abody)
	}

	// 3) The thing that actually matters: no approved device code exists, so the
	// poll still reports authorization_pending and hands out no credential.
	pstatus, pbody := h.devicePoll(t, clientID, deviceCode)
	if _, ok := pbody["access_token"]; ok {
		t.Fatalf("an unassigned user's device approval minted an access token: status=%d body=%v", pstatus, pbody)
	}
	if _, ok := pbody["id_token"]; ok {
		t.Fatalf("an unassigned user's device approval minted an id_token: %v", pbody)
	}
	if pbody["error"] != "authorization_pending" {
		t.Fatalf("expected the device code to remain pending, got status=%d body=%v", pstatus, pbody)
	}

	// POSITIVE CONTROL: assign the user, and the identical flow completes.
	if err := h.repo.AddGroupMember(context.Background(), groupID, uid, now); err != nil {
		t.Fatalf("add group member: %v", err)
	}
	status, da2 := h.deviceCode(t, clientID, "openid email groups")
	if status != http.StatusOK {
		t.Fatalf("control device/code: %d %v", status, da2)
	}
	dc2, _ := da2["device_code"].(string)
	uc2, _ := da2["user_code"].(string)
	if s, b := h.deviceApprove(t, userCookie, uc2); s != http.StatusOK {
		t.Fatalf("control: an assigned user must be able to approve a device, got %d %v", s, b)
	}
	s, b := h.devicePoll(t, clientID, dc2)
	if s != http.StatusOK {
		t.Fatalf("control device exchange: %d %v", s, b)
	}
	if _, ok := b["access_token"]; !ok {
		t.Fatalf("control: assigned user's device flow produced no access_token: %v", b)
	}
}

// TestDeviceApproval_WritesConsent_ForBackchannelLogout proves the second
// consequence of the device path never touching the client row: it records no
// Consent, and backchannel_logout.go targets clients by fanning out over
// ListConsentsByUserID. A device session therefore survives the ban/suspend
// logout fan-out that every authorization-code client receives.
//
// POSITIVE CONTROL: the authorization-code flow for a second client on the same
// harness writes its consent row, so this test cannot pass by ListConsents
// being broken for everyone.
func TestDeviceApproval_WritesConsent_ForBackchannelLogout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	_, adminCookie := h.seedUser(t, "dc-admin@idp.test", "admin")
	uid, userCookie := h.seedUser(t, "dc-user@idp.test", "user")

	deviceClient, _, _ := h.createClient(t, adminCookie, `{"name":"tv2","redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"scopes":["openid","read"],"is_public":true,"token_endpoint_auth_method":"none"}`)

	status, da := h.deviceCode(t, deviceClient, "openid read")
	if status != http.StatusOK {
		t.Fatalf("device/code: %d %v", status, da)
	}
	dcode, _ := da["device_code"].(string)
	ucode, _ := da["user_code"].(string)
	if s, b := h.deviceApprove(t, userCookie, ucode); s != http.StatusOK {
		t.Fatalf("device approve: %d %v", s, b)
	}
	if s, b := h.devicePoll(t, deviceClient, dcode); s != http.StatusOK {
		t.Fatalf("device exchange: %d %v", s, b)
	}

	// POSITIVE CONTROL: an authorization-code client on the same harness does
	// record its grant, so ListConsentsByUserID is demonstrably working.
	codeClient, codeSecret, _ := h.createClient(t, adminCookie, `{"name":"web","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["openid","read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`)
	verifier := "consent-fanout-verifier-43-chars-here-okay-x"
	challenge := pkceS256(verifier)
	code := h.authorizeAndConsent(t, userCookie, codeClient, "https://app.example/callback", "openid read", challenge, "s", "")
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", codeClient)
	form.Set("client_secret", codeSecret)
	form.Set("code_verifier", verifier)
	if s, b := h.postForm(t, "/api/auth/oauth/token", form, "", ""); s != http.StatusOK {
		t.Fatalf("control auth-code token: %d %v", s, b)
	}

	consents, err := h.repo.ListConsentsByUserID(ctx, uid)
	if err != nil {
		t.Fatalf("list consents: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range consents {
		seen[c.ClientID] = true
	}
	if !seen[codeClient] {
		t.Fatalf("control: the authorization-code client recorded no consent row; fan-out lookup is broken, not the device path (%v)", seen)
	}
	if !seen[deviceClient] {
		t.Fatalf("device approval recorded no consent row, so backchannel logout will never notify client %s: consents=%v", deviceClient, seen)
	}
}

// TestDeviceAuth_GrantNotRegistered proves the device-authorization endpoint
// ignores the client's registered grant_types: a client registered for
// authorization_code only can still open a device authorization.
//
// The assertion is on the credential, not the status: no device_code may be
// handed back.
//
// POSITIVE CONTROL: a client that DID register the device grant still gets its
// device_code from the same endpoint.
func TestDeviceAuth_GrantNotRegistered(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "dg-admin@idp.test", "admin")

	webOnly, _, _ := h.createClient(t, adminCookie, `{"name":"web-only","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["read"],"is_public":true,"token_endpoint_auth_method":"none"}`)

	status, b := h.deviceCode(t, webOnly, "read")
	if _, ok := b["device_code"]; ok {
		t.Fatalf("a client registered for authorization_code only was issued a device_code: status=%d body=%v", status, b)
	}
	if b["error"] != "unauthorized_client" {
		t.Fatalf("expected unauthorized_client from /oauth/device/code, got status=%d body=%v", status, b)
	}

	// POSITIVE CONTROL: the device grant still works for a client that registered it.
	tv, _, _ := h.createClient(t, adminCookie, `{"name":"tv3","redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"scopes":["read"],"is_public":true,"token_endpoint_auth_method":"none"}`)
	s, cb := h.deviceCode(t, tv, "read")
	if s != http.StatusOK {
		t.Fatalf("control device/code: %d %v", s, cb)
	}
	if _, ok := cb["device_code"]; !ok {
		t.Fatalf("control: a device-registered client got no device_code: %v", cb)
	}
}

// TestClientCredentials_GrantNotRegistered proves the token dispatcher never
// consults the client row: a confidential client registered for
// authorization_code only mints itself a client_credentials token whose sub is
// its own client_id — no resource owner anywhere in the loop.
//
// POSITIVE CONTROL: a client that registered client_credentials still gets its
// token from the same endpoint.
func TestClientCredentials_GrantNotRegistered(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "cg-admin@idp.test", "admin")

	webID, webSecret, _ := h.createClient(t, adminCookie, `{"name":"web-app","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", webID)
	form.Set("client_secret", webSecret)
	form.Set("scope", "read")
	status, b := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if _, ok := b["access_token"]; ok {
		t.Fatalf("a client registered for authorization_code only minted a client_credentials access token: status=%d body=%v", status, b)
	}
	if b["error"] != "unauthorized_client" {
		t.Fatalf("expected unauthorized_client, got status=%d body=%v", status, b)
	}

	// POSITIVE CONTROL: registration honoured, grant works.
	m2mID, m2mSecret, _ := h.createClient(t, adminCookie, `{"name":"m2m-ok","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_basic"}`)
	cform := url.Values{}
	cform.Set("grant_type", "client_credentials")
	cform.Set("scope", "read")
	s, cb := h.postForm(t, "/api/auth/oauth/token", cform, m2mID, m2mSecret)
	if s != http.StatusOK {
		t.Fatalf("control client_credentials: %d %v", s, cb)
	}
	if _, ok := cb["access_token"]; !ok {
		t.Fatalf("control: registered client_credentials client got no token: %v", cb)
	}
}

// TestClientCredentials_EmptyScopeRegistration_Rejected proves the void ceiling:
// a confidential client created with NO scopes key at all — which is what the
// console sends when the field is left blank, and what rawJSON(nil) stores as
// null — can name any scope it likes on client_credentials and receive an
// access token whose "scope" claim says so.
//
// The assertion reaches into the signed JWT, because the scope claim is what
// downstream resource servers authorize on; a 200 with a cosmetically empty
// response body would still be a live escalation if the claim carried "admin".
//
// POSITIVE CONTROLS: (1) the same scope-less client asking for NOTHING still
// gets its (scope-less) token, and (2) a client that registered "read" and asks
// for "read" still gets a token carrying it.
func TestClientCredentials_EmptyScopeRegistration_Rejected(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "cs-admin@idp.test", "admin")

	// No "scopes" key at all — the omitempty / rawJSON(nil) shape.
	noScopeID, noScopeSecret, _ := h.createClient(t, adminCookie, `{"name":"m2m-unscoped","redirect_uris":[],"grant_types":["client_credentials"],"is_public":false,"token_endpoint_auth_method":"client_secret_basic"}`)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "admin billing:write")
	status, b := h.postForm(t, "/api/auth/oauth/token", form, noScopeID, noScopeSecret)
	if at, ok := b["access_token"].(string); ok {
		claims := parseClaims(t, at)
		t.Fatalf("a client registered for no scopes minted a token with scope=%q (response scope=%v, status=%d)", claims["scope"], b["scope"], status)
	}
	if b["error"] != "invalid_scope" {
		t.Fatalf("expected invalid_scope, got status=%d body=%v", status, b)
	}

	// POSITIVE CONTROL 1: asking for nothing still works — an unscoped client is
	// not locked out of the grant, it is just held to its (empty) registration.
	bare := url.Values{}
	bare.Set("grant_type", "client_credentials")
	s, cb := h.postForm(t, "/api/auth/oauth/token", bare, noScopeID, noScopeSecret)
	if s != http.StatusOK {
		t.Fatalf("control: unscoped client requesting no scope must still get a token, got %d %v", s, cb)
	}
	if _, ok := cb["access_token"]; !ok {
		t.Fatalf("control: no access_token for the scope-less request: %v", cb)
	}

	// POSITIVE CONTROL 2: a registered scope is still grantable.
	readID, readSecret, _ := h.createClient(t, adminCookie, `{"name":"m2m-read","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_basic"}`)
	rf := url.Values{}
	rf.Set("grant_type", "client_credentials")
	rf.Set("scope", "read")
	s, rb := h.postForm(t, "/api/auth/oauth/token", rf, readID, readSecret)
	if s != http.StatusOK {
		t.Fatalf("control registered-scope client_credentials: %d %v", s, rb)
	}
	claims := parseClaims(t, rb["access_token"].(string))
	if claims["scope"] != "read" {
		t.Fatalf("control: expected scope claim \"read\", got %v", claims["scope"])
	}
}

// TestDCRClient_CanStillRefresh is the REGRESSION GUARD that locks the
// implicit-refresh rule. dcr.go defaults a self-registered client's grant_types
// to ["authorization_code"] with NO refresh_token, and the admin create endpoint
// stores null when the console omits the field. Enforcing grant_types strictly,
// without treating authorization_code as implying refresh_token and an absent
// registration as {authorization_code, refresh_token}, would sign out every
// DCR-registered client at its next rotation.
//
// This test passes today and must keep passing.
func TestDCRClient_CanStillRefresh(t *testing.T) {
	h := newDCRHarness(t, true)
	adminCookie := h.adminCookie(t)
	_, userCookie := h.seedUser(t, "dcr-refresh-user@idp.test", "user")

	// DCR sends no grant_types → dcr.go stores ["authorization_code"] only.
	status, reg := h.register(t, `{"redirect_uris":["https://app.example/callback"],"client_name":"dcr-refresh","scope":"openid read"}`, adminCookie)
	if status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, reg)
	}
	clientID, _ := reg["client_id"].(string)
	if gts, ok := reg["grant_types"].([]any); ok {
		for _, g := range gts {
			if g == "refresh_token" {
				t.Fatalf("precondition: DCR was expected to register authorization_code only, got %v", gts)
			}
		}
	}

	verifier := "dcr-refresh-verifier-43-characters-long-okay"
	challenge := pkceS256(verifier)
	code := h.authzAndConsent(t, userCookie, clientID, "https://app.example/callback", "openid read", challenge, "s")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/callback")
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	s, tok := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if s != http.StatusOK {
		t.Fatalf("dcr auth-code token: %d %v", s, tok)
	}
	refresh, _ := tok["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("dcr client got no refresh token: %v", tok)
	}

	rf := url.Values{}
	rf.Set("grant_type", "refresh_token")
	rf.Set("refresh_token", refresh)
	rf.Set("client_id", clientID)
	s, rb := h.postForm(t, "/api/auth/oauth/token", rf, "", "")
	if s != http.StatusOK {
		t.Fatalf("a DCR-registered client (authorization_code only) must still be able to refresh, got %d %v", s, rb)
	}
	if _, ok := rb["access_token"]; !ok {
		t.Fatalf("refresh returned no access_token: %v", rb)
	}
}

// parseClaims decodes a signed JWT without verification, for claim assertions.
func parseClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return parsed.Claims.(jwt.MapClaims)
}
