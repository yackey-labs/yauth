package ssooidc

// login_binding_test.go — the SSO login state is server-side only, so a
// finished-but-undelivered /sso/callback URL is a portable credential for
// "become whoever authenticated at the IdP". This is the same defect as
// plugins/oauth's (see plugins/oauth/login_binding_test.go); it is written out
// separately here because it is a separate code path with a separate state
// table, and fixing one plugin does not fix the other.
//
// registerSsoLogin (handlers_login.go) resolves the connection, mints
// state/nonce/PKCE verifier, writes an SsoLoginState row via CreateSsoLoginState
// and 302s to the IdP. Nothing is written to the browser — the doc comment on
// that handler says so in as many words ("No cookie is set (state is
// server-side via CreateSsoLoginState)"). registerSsoCallback, registered for
// BOTH GET and POST in plugin.go, reads code+state off the query string or the
// form body, calls ConsumeSsoLoginState, exchanges the code, verifies the
// id_token against the stored nonce, JIT-provisions and then Set-Cookies a
// session on whatever browser made the request.
//
// Every one of those checks is about the IdP's answer, not about the browser
// asking. The PKCE verifier and the nonce both come out of the state row the
// ATTACKER created, so they are consistent with the attacker's own code and
// pass. The victim's browser is simply the one that shows up.
//
// So: the attacker starts a login, authenticates at the IdP as themselves,
// stops at the callback URL, and mails it to the victim. The victim's browser
// ends up holding a session for the attacker's account at what is itself an
// identity provider — every downstream relying party then signs the victim in
// as the attacker, and any credential the victim goes on to enrol is enrolled
// on the attacker's account.
//
// The fixture is the TLS posture (setupForLoginSecure with secure=true) for the
// reason spelled out there: a binding cookie has to survive an IdP's cross-site
// form_post, which needs SameSite=None, which needs Secure. Each test pairs the
// refusal with a positive control so a fix cannot pass by refusing everything.

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// ssoBrowser is a distinct browser: its own cookie jar, and a transport that
// trusts the fixture's TLS certificate. Redirects are not followed so each leg
// is asserted on its own.
func ssoBrowser(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar:           jar,
		Transport:     srv.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// beginLoginOn runs GET /sso/login on the given browser and returns the state
// and nonce the plugin minted. The flow now exists server-side and belongs, as
// far as the server is concerned, to nobody.
func beginLoginOn(t *testing.T, srv *httptest.Server, cl *http.Client, slug string) (state, nonce string) {
	t.Helper()
	resp, err := cl.Get(srv.URL + "/sso/login?org=" + slug)
	if err != nil {
		t.Fatalf("sso login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("sso login: expected 302, got %d %s", resp.StatusCode, body)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("sso login location: %v", err)
	}
	state, nonce = loc.Query().Get("state"), loc.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("sso login: no state/nonce in %s", loc)
	}
	return state, nonce
}

// callbackOn delivers the IdP's GET redirect to the given browser.
func callbackOn(t *testing.T, srv *httptest.Server, cl *http.Client, state string) *http.Response {
	t.Helper()
	resp, err := cl.Get(srv.URL + "/sso/callback?" + url.Values{
		"code":  []string{"x"},
		"state": []string{state},
	}.Encode())
	if err != nil {
		t.Fatalf("sso callback: %v", err)
	}
	return resp
}

// postCallbackOn delivers the same code+state the way an IdP using
// response_mode=form_post does — and the way an attacker delivers it, as an
// auto-submitting cross-site form.
func postCallbackOn(t *testing.T, srv *httptest.Server, cl *http.Client, state string) *http.Response {
	t.Helper()
	form := url.Values{"code": {"x"}, "state": {state}}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/sso/callback", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build form_post: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("sso form_post callback: %v", err)
	}
	return resp
}

func ssoSessionCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// liveSessions counts every session row in the store. The federated user is
// JIT-provisioned by the callback itself, so "no session anywhere" is the
// cleanest statement of "no login happened".
func liveSessions(t *testing.T, r repo.Repository) int {
	t.Helper()
	_, total, err := r.ListSessions(context.Background(), domain.ListSessionsFilters{Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	return int(total)
}

// --- the defect -----------------------------------------------------------

// TestSsoLoginCSRF_ReplayedCallbackRefused is the exploit on the GET callback.
// The attacker's browser starts the flow and finishes at the IdP; the victim's
// browser is the one that presents the callback.
func TestSsoLoginCSRF_ReplayedCallbackRefused(t *testing.T) {
	_, srv, r, _, idp := setupForLoginSecure(t, true)

	attacker := ssoBrowser(t, srv)
	state, nonce := beginLoginOn(t, srv, attacker, "acme")
	idp.overrideNonce = nonce // the id_token the IdP will mint for the attacker

	victim := ssoBrowser(t, srv)
	resp := callbackOn(t, srv, victim, state)
	defer resp.Body.Close()

	if v := ssoSessionCookie(resp); v != "" {
		t.Fatalf("sso login CSRF succeeded: the victim's browser was handed a session cookie for the attacker's federated identity (status %d)", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
		t.Fatalf("sso login CSRF succeeded: callback in a foreign browser returned %d", resp.StatusCode)
	}
	if n := liveSessions(t, r); n != 0 {
		t.Fatalf("sso login CSRF left %d session row(s), want 0", n)
	}
}

// TestSsoLoginCSRF_FormPostReplayRefused is the same attack on the POST twin —
// the leg an IdP with response_mode=form_post actually uses, and the leg where
// a binding cookie set with the session cookie's own SameSite would silently
// fail to arrive.
func TestSsoLoginCSRF_FormPostReplayRefused(t *testing.T) {
	_, srv, r, _, idp := setupForLoginSecure(t, true)

	attacker := ssoBrowser(t, srv)
	state, nonce := beginLoginOn(t, srv, attacker, "acme")
	idp.overrideNonce = nonce

	victim := ssoBrowser(t, srv)
	resp := postCallbackOn(t, srv, victim, state)
	defer resp.Body.Close()

	if v := ssoSessionCookie(resp); v != "" {
		t.Fatalf("sso form_post login CSRF succeeded: the victim's browser was handed a session cookie for the attacker's federated identity (status %d)", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
		t.Fatalf("sso form_post login CSRF succeeded: callback in a foreign browser returned %d", resp.StatusCode)
	}
	if n := liveSessions(t, r); n != 0 {
		t.Fatalf("sso form_post login CSRF left %d session row(s), want 0", n)
	}
}

// --- positive controls ----------------------------------------------------

// TestSsoLoginBinding_SameBrowserLoginStillCompletes is the control that stops
// a fix from simply refusing every callback: one browser, one jar, /sso/login →
// /sso/callback still signs in and still JIT-provisions.
func TestSsoLoginBinding_SameBrowserLoginStillCompletes(t *testing.T) {
	_, srv, r, _, idp := setupForLoginSecure(t, true)

	cl := ssoBrowser(t, srv)
	state, nonce := beginLoginOn(t, srv, cl, "acme")
	idp.overrideNonce = nonce

	resp := callbackOn(t, srv, cl, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("legitimate same-browser sso login: expected 200, got %d %s", resp.StatusCode, body)
	}
	if ssoSessionCookie(resp) == "" {
		t.Fatalf("legitimate same-browser sso login set no session cookie")
	}
	if n := liveSessions(t, r); n != 1 {
		t.Fatalf("legitimate same-browser sso login wrote %d session rows, want 1", n)
	}
}

// TestSsoLoginBinding_FormPostSameBrowserStillCompletes is the same control on
// the form_post leg — the flow starts and finishes in ONE jar, only the
// delivery method changes.
func TestSsoLoginBinding_FormPostSameBrowserStillCompletes(t *testing.T) {
	_, srv, r, _, idp := setupForLoginSecure(t, true)

	cl := ssoBrowser(t, srv)
	state, nonce := beginLoginOn(t, srv, cl, "acme")
	idp.overrideNonce = nonce

	resp := postCallbackOn(t, srv, cl, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("legitimate same-browser sso form_post login: expected 200, got %d %s", resp.StatusCode, body)
	}
	if ssoSessionCookie(resp) == "" {
		t.Fatalf("legitimate same-browser sso form_post login set no session cookie")
	}
	if n := liveSessions(t, r); n != 1 {
		t.Fatalf("legitimate same-browser sso form_post login wrote %d session rows, want 1", n)
	}
}

// TestSsoLoginBinding_LegacyStateRowStillRedeems pins rolling-deploy safety. A
// row written by the PREVIOUS binary belongs to a browser that was sent to the
// IdP before any binding existed, so nothing was ever written to it; those
// callbacks must keep working for the rest of the state TTL. A binding enforced
// on every callback rather than only on the flows this binary started would
// refuse every in-flight login at deploy time.
func TestSsoLoginBinding_LegacyStateRowStillRedeems(t *testing.T) {
	_, srv, r, conn, idp := setupForLoginSecure(t, true)
	ctx := context.Background()

	// Written by hand exactly as the old binary wrote it: a bare random
	// state, no browser-side companion of any kind.
	verifier, err := generateRandom(48)
	if err != nil {
		t.Fatalf("generateRandom: %v", err)
	}
	nonce, err := generateRandom(32)
	if err != nil {
		t.Fatalf("generateRandom: %v", err)
	}
	now := time.Now().UTC()
	if err := r.CreateSsoLoginState(ctx, domain.NewSsoLoginState{
		State:        "legacy-unbound-sso-state",
		ConnectionID: conn.ID,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		CreatedAt:    now,
		ExpiresAt:    now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateSsoLoginState: %v", err)
	}
	idp.overrideNonce = nonce

	cl := ssoBrowser(t, srv)
	resp := callbackOn(t, srv, cl, "legacy-unbound-sso-state")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("a state row from the previous binary no longer redeems: %d %s", resp.StatusCode, body)
	}
	if n := liveSessions(t, r); n != 1 {
		t.Fatalf("legacy state row produced %d session rows, want 1", n)
	}
}

// --- the cookie itself ----------------------------------------------------

// beginLoginRaw is beginLoginOn returning the raw Set-Cookie lines as well, so
// a test can assert on the wire bytes instead of on what Go's cookiejar kept.
func beginLoginRaw(t *testing.T, srv *httptest.Server, cl *http.Client, slug string) (setCookie []string, state, nonce string) {
	t.Helper()
	resp, err := cl.Get(srv.URL + "/sso/login?org=" + slug)
	if err != nil {
		t.Fatalf("sso login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("sso login: expected 302, got %d %s", resp.StatusCode, body)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("sso login location: %v", err)
	}
	return resp.Header.Values("Set-Cookie"), loc.Query().Get("state"), loc.Query().Get("nonce")
}

// TestSsoLoginBinding_LoginCookieIsSameSiteNoneSecure asserts the header bytes.
// Go's cookiejar ignores SameSite entirely, so the form_post positive control
// above would pass just as happily against a SameSite=Lax cookie — which a real
// browser will not send on an IdP's cross-site form_post POST, breaking every
// such login in production while this suite stayed green.
func TestSsoLoginBinding_LoginCookieIsSameSiteNoneSecure(t *testing.T) {
	_, srv, _, _, _ := setupForLoginSecure(t, true)

	cl := ssoBrowser(t, srv)
	lines, state, _ := beginLoginRaw(t, srv, cl, "acme")
	if !auth.IsBoundLoginState(state) {
		t.Fatalf("/sso/login minted an unbound state %q on a cookie_secure deployment", state)
	}
	name := auth.LoginBindingCookieName(state)
	var line string
	for _, l := range lines {
		if strings.HasPrefix(l, name+"=") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("/sso/login minted a bound state but set no binding cookie: %v", lines)
	}
	if !strings.Contains(line, "SameSite=None") {
		t.Fatalf("binding cookie is not SameSite=None (%q) — it would not arrive on an IdP form_post", line)
	}
	if !strings.Contains(line, "Secure") {
		t.Fatalf("binding cookie is not Secure (%q) — browsers reject SameSite=None without it", line)
	}
	if !strings.Contains(line, "HttpOnly") {
		t.Fatalf("binding cookie is not HttpOnly (%q)", line)
	}
}

// TestSsoLoginBinding_CookieClearedOnBothExits pins that the binding cookie is
// single-use like the state row it guards — expired on the success path AND on
// the refusal path, so no browser carries a dead binding for the rest of the
// state TTL.
func TestSsoLoginBinding_CookieClearedOnBothExits(t *testing.T) {
	_, srv, _, _, idp := setupForLoginSecure(t, true)

	// Success exit.
	cl := ssoBrowser(t, srv)
	state, nonce := beginLoginOn(t, srv, cl, "acme")
	idp.overrideNonce = nonce
	resp := callbackOn(t, srv, cl, state)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legitimate callback: %d", resp.StatusCode)
	}
	assertSsoBindingCleared(t, resp, state, "success")

	// Refusal exit.
	owner := ssoBrowser(t, srv)
	state2, nonce2 := beginLoginOn(t, srv, owner, "acme")
	idp.overrideNonce = nonce2
	victim := ssoBrowser(t, srv)
	resp2 := callbackOn(t, srv, victim, state2)
	resp2.Body.Close()
	assertSsoBindingCleared(t, resp2, state2, "refusal")
}

func assertSsoBindingCleared(t *testing.T, resp *http.Response, state, exit string) {
	t.Helper()
	name := auth.LoginBindingCookieName(state)
	if name == "" {
		t.Fatalf("%s exit: state %q is not bound, nothing to clear", exit, state)
	}
	for _, c := range resp.Cookies() {
		if c.Name != name {
			continue
		}
		if c.MaxAge >= 0 {
			t.Fatalf("%s exit: binding cookie %q was not expired (MaxAge=%d)", exit, name, c.MaxAge)
		}
		return
	}
	t.Fatalf("%s exit: no Set-Cookie expiring the binding cookie %q (headers: %v)",
		exit, name, resp.Header.Values("Set-Cookie"))
}

// --- the modes ------------------------------------------------------------

// TestSsoLoginBinding_AutoIsOffOnPlainHTTP is honest documentation, not a wish.
// Under "auto" a deployment with cookie_secure=false mints an UNBOUND state,
// sets no cookie, and the replay still succeeds — a binding cookie there could
// only be SameSite=Lax, which a browser will not send on an IdP's form_post, so
// enforcing it would refuse every such login rather than protect anyone.
func TestSsoLoginBinding_AutoIsOffOnPlainHTTP(t *testing.T) {
	_, srv, r, _, idp := setupForLoginModes(t, false, "auto")

	attacker := ssoBrowser(t, srv)
	lines, state, nonce := beginLoginRaw(t, srv, attacker, "acme")
	idp.overrideNonce = nonce
	if auth.IsBoundLoginState(state) {
		t.Fatalf("auto minted a BOUND state %q on a plain-HTTP deployment", state)
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "yauth_lb_") {
			t.Fatalf("auto set a binding cookie on a plain-HTTP deployment: %q", l)
		}
	}

	victim := ssoBrowser(t, srv)
	resp := callbackOn(t, srv, victim, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("auto on plain HTTP: expected the replay to STILL succeed (the documented gap), got %d %s", resp.StatusCode, body)
	}
	if n := liveSessions(t, r); n != 1 {
		t.Fatalf("auto on plain HTTP wrote %d session rows, want 1", n)
	}
}

// TestSsoLoginBinding_RequiredEnforcesOnPlainHTTP is the escape hatch in the
// other direction: an operator whose TLS terminates at a proxy sets "required"
// and gets the binding regardless of the local cookie posture. The paired
// positive control keeps a fix from passing by refusing everything.
func TestSsoLoginBinding_RequiredEnforcesOnPlainHTTP(t *testing.T) {
	_, srv, r, _, idp := setupForLoginModes(t, false, "required")

	owner := ssoBrowser(t, srv)
	state, nonce := beginLoginOn(t, srv, owner, "acme")
	idp.overrideNonce = nonce
	if !auth.IsBoundLoginState(state) {
		t.Fatalf("required minted an unbound state %q", state)
	}

	victim := ssoBrowser(t, srv)
	resp := callbackOn(t, srv, victim, state)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
		t.Fatalf("required did not enforce on plain HTTP: replay returned %d", resp.StatusCode)
	}
	if ssoSessionCookie(resp) != "" {
		t.Fatalf("required: the victim's browser was handed a session cookie anyway")
	}
	if n := liveSessions(t, r); n != 0 {
		t.Fatalf("required: replay left %d session rows, want 0", n)
	}

	// POSITIVE CONTROL: the browser that started the flow still finishes it,
	// which also proves the refusal did not burn the single-use state row.
	resp2 := callbackOn(t, srv, owner, state)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("required refused the browser that STARTED the flow: %d %s", resp2.StatusCode, body)
	}
	if n := liveSessions(t, r); n != 1 {
		t.Fatalf("owner's completed login wrote %d session rows, want 1", n)
	}
}

// TestSsoLoginBinding_RefusalNamesTheKnob pins the operator-facing half of the
// contract: the 400 must name plugins.sso_oidc.login_state_binding so whoever
// reads the support ticket learns the escape hatch from the response.
func TestSsoLoginBinding_RefusalNamesTheKnob(t *testing.T) {
	_, srv, _, _, idp := setupForLoginSecure(t, true)

	attacker := ssoBrowser(t, srv)
	state, nonce := beginLoginOn(t, srv, attacker, "acme")
	idp.overrideNonce = nonce

	victim := ssoBrowser(t, srv)
	resp := callbackOn(t, srv, victim, state)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "plugins.sso_oidc.login_state_binding") {
		t.Fatalf("the refusal does not name the knob: %s", body)
	}
}

// TestSsoLoginBinding_MalformedStateDoesNotPanic is the remote-crash guard.
// /sso/callback is public and unauthenticated, and `state` is entirely
// caller-chosen; the binding helpers slice it, so anything that assumed a
// length would be a one-request denial of service.
func TestSsoLoginBinding_MalformedStateDoesNotPanic(t *testing.T) {
	_, srv, _, _, _ := setupForLoginSecure(t, true)
	cl := ssoBrowser(t, srv)

	for _, state := range []string{"b", "b.", "b.A", "b..", auth.BoundStatePrefix + strings.Repeat("A", 42)} {
		resp := callbackOn(t, srv, cl, state)
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("callback with state=%q returned %d — a malformed state must not be a server error", state, resp.StatusCode)
		}
	}
}
