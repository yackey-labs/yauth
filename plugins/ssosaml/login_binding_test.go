// login_binding_test.go — the SP-initiated SAML flow was never bound to the
// browser that started it.
//
// PR #124 closed federated login CSRF / session fixation for plugins/oauth and
// plugins/ssooidc by putting a secret in the browser at mint time and deriving
// the public state from it (auth/login_binding.go). plugins/ssosaml was not
// migrated: /sso/saml/login minted a RelayState with generateRandom(32), wrote
// the SsoLoginState row and 302'd to the IdP without writing anything to the
// browser, and the ACS consumed whatever RelayState arrived, on whatever
// browser presented it. The row records which connection and which
// AuthnRequest; it does not record which browser.
//
// The attack is the one that file already describes, over the SAML bindings.
// An attacker starts a login at the victim's yauth, authenticates at the IdP as
// THEMSELVES, and stops holding a signed SAMLResponse plus the matching
// RelayState. Delivered to a victim's browser as an auto-submitting form POST
// to /sso/saml/acs, the server consumes the state, validates a genuinely
// IdP-signed assertion for the ATTACKER, and Set-Cookies the attacker's session
// into the VICTIM's browser. yauth is itself an IdP, so from there every
// downstream relying party signs the victim in as the attacker, and anything
// the victim goes on to enrol — a passkey, a second factor — is enrolled on the
// attacker's account.
//
// Signature checking does not help: the assertion IS validly signed, by the
// real IdP, for the attacker's own identity. The XSW, replay and clock-skew
// hardening in #125 does not help either, because nothing here is malformed or
// replayed — the response is used exactly once, by the wrong browser.
//
// SAML is in fact the case auth/login_binding.go was shaped for. Its comment
// explains SameSite=None+Secure because "an IdP using response_mode=form_post
// returns by making the browser POST cross-site to the callback"; the SAML
// HTTP-POST binding is that, always, not as an option.
package ssosaml

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// peekLoginState reads the state row without spending it. The repository
// deliberately exposes only a single-use ConsumeSsoLoginState, so the row is
// consumed and re-inserted — the same trick beginLogin already uses.
func peekLoginState(t *testing.T, f *e2eFixture, relayState string) *domain.SsoLoginState {
	t.Helper()
	st, err := f.repo.ConsumeSsoLoginState(context.Background(), relayState)
	if err != nil || st == nil {
		t.Fatalf("login state row missing: err=%v state=%v", err, st)
	}
	if err := f.repo.CreateSsoLoginState(context.Background(), domain.NewSsoLoginState{
		State:        st.State,
		ConnectionID: st.ConnectionID,
		PKCEVerifier: st.PKCEVerifier,
		RedirectURL:  st.RedirectURL,
		CreatedAt:    st.CreatedAt,
		ExpiresAt:    st.ExpiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

// boundE2E builds the fixture with binding forced on. "required" rather than
// "auto" so the test does not depend on the fake host's CookieSecure, matching
// how the ssooidc suite pins the same behaviour on plain HTTP.
func boundE2E(t *testing.T) *e2eFixture {
	t.Helper()
	return newE2E(t, func(c *Config) { c.LoginStateBinding = auth.LoginStateBindingRequired })
}

// samlBeginBound runs /sso/saml/login and returns the RelayState plus every
// Set-Cookie the redirect carried.
func samlBeginBound(t *testing.T, f *e2eFixture, cl *http.Client) (relayState string, cookies []*http.Cookie) {
	t.Helper()
	resp, err := cl.Get(f.srv.URL + "/sso/saml/login?connection_id=" + f.conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: status=%d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	rs := loc.Query().Get("RelayState")
	if rs == "" {
		t.Fatal("login: no RelayState in redirect")
	}
	return rs, resp.Cookies()
}

// TestSamlLoginBinding_StateIsBoundAtMint is the primary refusal. Until the fix
// the RelayState carries no binding marker and no cookie is written, so there
// is nothing tying the flow to a browser at all.
func TestSamlLoginBinding_StateIsBoundAtMint(t *testing.T) {
	f := boundE2E(t)
	relayState, cookies := samlBeginBound(t, f, newNoRedirectClient())

	if !auth.IsBoundLoginState(relayState) {
		t.Fatalf("RelayState %q is not browser-bound: /sso/saml/login minted it with no tie to the "+
			"browser, so a completed SAMLResponse+RelayState pair can be redeemed in ANY browser — "+
			"login CSRF / session fixation, the hole #124 closed for oauth and ssooidc", relayState)
	}

	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == auth.LoginBindingCookieName(relayState) {
			found = c
		}
	}
	if found == nil {
		t.Fatal("no login-binding cookie was written by /sso/saml/login")
	}
	if !found.HttpOnly {
		t.Fatal("binding cookie must be HttpOnly")
	}
}

// TestSamlLoginBinding_CookieIsSameSiteNoneOnSecure is the SAML-specific
// requirement, and the one most likely to be got wrong.
//
// The IdP returns via the HTTP-POST binding — the browser POSTs cross-site to
// /sso/saml/acs — and a Lax cookie is NOT sent on a cross-site POST. A Lax
// binding cookie would therefore refuse every real-browser SAML login while
// passing every Go test, because net/http's cookiejar ignores SameSite
// entirely. Browsers only honour None together with Secure, which is exactly
// why "auto" declines to bind on a deployment that is not issuing Secure
// cookies.
func TestSamlLoginBinding_CookieIsSameSiteNoneOnSecure(t *testing.T) {
	f := newE2E(t, func(c *Config) { c.LoginStateBinding = auth.LoginStateBindingRequired })
	f.host.secure = true

	relayState, cookies := samlBeginBound(t, f, newNoRedirectClient())
	for _, c := range cookies {
		if c.Name != auth.LoginBindingCookieName(relayState) {
			continue
		}
		if c.SameSite != http.SameSiteNoneMode {
			t.Fatalf("binding cookie SameSite=%v, want None: the ACS is reached by a cross-site POST, "+
				"so anything else is never sent and every real login breaks", c.SameSite)
		}
		if !c.Secure {
			t.Fatal("SameSite=None without Secure is rejected outright by browsers")
		}
		return
	}
	t.Fatal("no login-binding cookie on the Secure deployment")
}

// TestSamlLoginBinding_ForeignBrowserRefused is the attack itself, end to end:
// the flow is begun in one browser and the assertion is delivered in another.
func TestSamlLoginBinding_ForeignBrowserRefused(t *testing.T) {
	f := boundE2E(t)

	attacker := newNoRedirectClient()
	relayState, _ := samlBeginBound(t, f, attacker)

	st := peekLoginState(t, f, relayState)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, relayState)

	// The victim's browser has never seen this flow, so it holds no binding
	// cookie — exactly the state of a browser handed a completed callback URL.
	victim := newNoRedirectClient()
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {relayState}}
	resp, err := victim.PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Fatal("ACS issued a session to a browser that never started the login: an attacker who " +
				"completes a SAML login as themselves can hand the signed response to a victim and " +
				"plant their own session in the victim's browser")
		}
	}
	if resp.StatusCode < 400 {
		t.Fatalf("ACS accepted a foreign-browser assertion: status=%d", resp.StatusCode)
	}
}

// TestSamlLoginBinding_SameBrowserStillCompletes is the positive control. The
// refusal above is only correct if the ordinary login is untouched — and this is
// the assertion that would catch "reject everything" as a fix.
func TestSamlLoginBinding_SameBrowserStillCompletes(t *testing.T) {
	f := boundE2E(t)

	browser := newNoRedirectClient()
	relayState, cookies := samlBeginBound(t, f, browser)

	st := peekLoginState(t, f, relayState)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, relayState)

	req, err := http.NewRequest(http.MethodPost, f.srv.URL+"/sso/saml/acs",
		strings.NewReader(url.Values{"SAMLResponse": {respB64}, "RelayState": {relayState}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Replay the browser's own cookies, which is what a real browser does on
	// the IdP's cross-site POST when the cookie is SameSite=None.
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		t.Fatalf("the browser that STARTED the login was refused: status=%d", resp.StatusCode)
	}
	var session string
	for _, c := range resp.Cookies() {
		if c.Name == "yauth_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no session issued to the originating browser")
	}
}

// TestSamlLoginBinding_UnboundStateStillRedeems is the rolling-deploy and
// IdP-initiated guarantee, and it is why enforcement is decided at MINT time
// rather than at the ACS.
//
// A state row written by the previous binary carries no "b." prefix, and an
// unsolicited IdP-initiated response carries no state this server minted at
// all. Neither can be expected to present a cookie. If the ACS checked config
// instead of the state's own prefix, this deploy would sign out every in-flight
// login and break every IdP-initiated deployment — so an unbound state must
// pass through untouched even while binding is REQUIRED.
func TestSamlLoginBinding_UnboundStateStillRedeems(t *testing.T) {
	f := boundE2E(t)

	// A row exactly as the previous binary would have written it: a plain
	// random RelayState with no binding marker.
	legacyState, err := generateRandom(32)
	if err != nil {
		t.Fatal(err)
	}
	if auth.IsBoundLoginState(legacyState) {
		t.Skip("generated state accidentally looks bound")
	}
	now := time.Now().UTC()
	if err := f.repo.CreateSsoLoginState(context.Background(), domain.NewSsoLoginState{
		State:        legacyState,
		ConnectionID: f.conn.ID,
		PKCEVerifier: "id-legacy-request",
		CreatedAt:    now,
		ExpiresAt:    now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	respB64, _ := f.idp.signedResponseFor(t, f.sp, "id-legacy-request", legacyState)

	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs",
		url.Values{"SAMLResponse": {respB64}, "RelayState": {legacyState}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("an unbound (legacy / IdP-initiated) state was refused by the binding check: status=%d; "+
			"enforcement must be read off the state minted earlier, never off config at the ACS", resp.StatusCode)
	}
}

// TestSamlLoginBinding_OffMintsAnUnboundState pins the escape hatch. A
// deployment that cannot carry the cookie must be able to turn this off, and
// the knob has to actually do so.
func TestSamlLoginBinding_OffMintsAnUnboundState(t *testing.T) {
	f := newE2E(t, func(c *Config) { c.LoginStateBinding = auth.LoginStateBindingOff })
	relayState, cookies := samlBeginBound(t, f, newNoRedirectClient())

	if auth.IsBoundLoginState(relayState) {
		t.Fatal("binding is off but the state was minted bound")
	}
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "yauth_lb_") {
			t.Fatalf("binding is off but a binding cookie %q was written", c.Name)
		}
	}
}
