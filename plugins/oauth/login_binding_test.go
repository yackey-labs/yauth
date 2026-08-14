package oauth_test

// login_binding_test.go — nothing in plugins/oauth ties a federated login to
// the browser that started it, so a finished-but-undelivered callback URL is a
// portable credential for "become whoever authenticated at the IdP".
//
// The state is entirely server-side. registerAuthorize (handlers.go) mints a
// random state, writes an OAuthState row through host.Repo().CreateOAuthState
// and 302s to the provider; it writes NOTHING to the browser. registerCallback
// — registered for GET and for POST (plugin.go Routes) — reads code+state off
// the query string or the form body, calls ConsumeOAuthState, exchanges the
// code and hands off to completeLogin, which calls auth.IssueSession and
// http.SetCookie on whatever browser happened to make the callback request.
// The row it consumed says which provider and which redirect; it does not say
// which browser.
//
// PKCE (already merged, see pkce_test.go) does not touch this. It binds the
// CODE to a verifier this server holds, and in the attack below the code, the
// state row and the verifier are all consistently the ATTACKER's — the S256
// check passes exactly as designed. The victim's browser is simply the one
// that shows up at the callback.
//
// The attack, end to end:
//
//  1. the attacker opens /oauth/{provider}/authorize in their OWN browser and
//     authenticates at the IdP as THEMSELVES;
//  2. the IdP redirects to .../callback?code=…&state=…, and the attacker STOPS
//     there — that URL is now a single-use credential for their own account;
//  3. the attacker delivers it to a victim (a link, an <img>, or an
//     auto-submitting form aimed at the POST twin);
//  4. yauth consumes the state, exchanges the code, fetches the ATTACKER's
//     identity, and writes a session cookie for the ATTACKER's account into the
//     VICTIM's browser.
//
// yauth is itself an IdP, so the victim now holds an attacker-owned session at
// the authorization server: every downstream relying party signs them in
// silently as the attacker, and any passkey or second factor they then enrol
// lands on the attacker's account while they believe they are hardening their
// own.
//
// The fixture is the TLS posture (newStackOnSecure with secure=true), because
// that is the only posture in which any cookie-based binding can exist: the
// cookie must survive an IdP's cross-site form_post, which needs SameSite=None,
// which browsers only honour with Secure, and Go's cookiejar will not send a
// Secure cookie over http://. The IdP is pkce_test.go's PKCE-enforcing fake, so
// these tests keep proving that the code binding is intact and untouched.
//
// Every refusal below is paired with a positive control — same-browser GET,
// same-browser form_post, two concurrent flows in one jar, and a state row
// written by a previous binary — so a "fix" that simply refuses more callbacks
// cannot pass.

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/oauth"
)

// attackerInfo is the identity the provider asserts for every flow in this
// file. Naming it the attacker is the point: whichever browser completes a
// callback ends up holding a session for THIS account.
func attackerInfo() oauth.UserInfo {
	return oauth.UserInfo{
		ProviderUserID: "attacker-remote",
		Email:          "attacker@evil.example",
		EmailVerified:  true,
		Name:           "Attacker",
	}
}

// newSecureStack is the TLS fixture these tests run on: cookie_secure=true and
// an https listener, i.e. every real deployment of yauth.
func newSecureStack(t *testing.T) (*stack, *pkceIDP) {
	t.Helper()
	idp := newPKCEIdP(t)
	s := newStackOnSecure(t, idp.srv, attackerInfo(), nil, true)
	return s, idp
}

// browserOn is newBrowser with the fixture's transport, so it trusts the
// httptest TLS certificate. Each call is a genuinely separate browser: its own
// cookie jar, no shared state with any other.
func browserOn(t *testing.T, s *stack) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar:           jar,
		Transport:     s.srv.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// runFlowUpToCallback performs steps 1-2 of the attack on the given browser:
// /authorize, then the IdP's redirect, returning the callback URL WITHOUT
// requesting it. At this instant the flow is complete except for delivery.
func runFlowUpToCallback(t *testing.T, s *stack, cl *http.Client) *url.URL {
	t.Helper()
	loc, _ := beginAuthorize(t, s, cl)
	return driveIDP(t, cl, loc)
}

// postCallback delivers code+state to the POST twin of the callback as an
// IdP's response_mode=form_post would: an auto-submitting cross-site form with
// an application/x-www-form-urlencoded body.
func postCallback(t *testing.T, s *stack, cl *http.Client, code, state string) *http.Response {
	t.Helper()
	form := url.Values{"code": {code}, "state": {state}}
	req, err := http.NewRequest(http.MethodPost,
		s.srv.URL+"/api/auth/oauth/fake/callback", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build form_post: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("form_post callback: %v", err)
	}
	return res
}

// sessionCookie returns the session cookie value the response set, or "".
func sessionCookie(res *http.Response) string {
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// sessionRows counts live session rows for a user without destroying them, so
// a test can assert "none yet" and later "exactly one".
func sessionRows(t *testing.T, s *stack, userID string) int {
	t.Helper()
	rows, _, err := s.repo.ListSessions(context.Background(), domain.ListSessionsFilters{
		UserID: &userID, Limit: 100,
	})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	return len(rows)
}

// --- the defect -----------------------------------------------------------

// TestOAuthLoginCSRF_ReplayedCallbackRefused is the exploit itself on the GET
// callback. The attacker finishes their own login at the IdP but never delivers
// the callback; the victim's browser makes the request instead.
//
// The assertions are about state, not about a status code: no session cookie
// written into the victim's browser, no session row for the attacker's account,
// and the victim's jar still anonymous afterwards.
func TestOAuthLoginCSRF_ReplayedCallbackRefused(t *testing.T) {
	s, _ := newSecureStack(t)
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	attacker := browserOn(t, s)
	cbURL := runFlowUpToCallback(t, s, attacker)

	// The victim clicks the attacker's link.
	victim := browserOn(t, s)
	res, err := victim.Get(cbURL.String())
	if err != nil {
		t.Fatalf("victim callback: %v", err)
	}
	defer res.Body.Close()

	if v := sessionCookie(res); v != "" {
		t.Fatalf("login CSRF succeeded: the victim's browser was handed a session cookie for the attacker's account (status %d)", res.StatusCode)
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusFound {
		t.Fatalf("login CSRF succeeded: callback in a foreign browser returned %d (%s)", res.StatusCode, drainBody(res))
	}
	if n := sessionRows(t, s, att.ID); n != 0 {
		t.Fatalf("login CSRF left %d session row(s) for the attacker's account, want 0", n)
	}

	// And the victim's browser is still anonymous.
	sres, err := victim.Get(s.srv.URL + "/api/auth/session")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	sres.Body.Close()
	if sres.StatusCode == http.StatusOK {
		t.Fatalf("the victim's browser holds a signed-in session after the replayed callback")
	}
}

// TestOAuthLoginCSRF_FormPostReplayRefused is the same attack against the POST
// twin, which is how an IdP using response_mode=form_post returns and therefore
// how the attack is delivered as an auto-submitting cross-site form. It is a
// separate case because it is the leg where a naively-configured binding cookie
// (SameSite=Lax) would silently not arrive, and a fix that only appears to work
// on the GET leg must not pass.
func TestOAuthLoginCSRF_FormPostReplayRefused(t *testing.T) {
	s, _ := newSecureStack(t)
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	attacker := browserOn(t, s)
	cbURL := runFlowUpToCallback(t, s, attacker)
	code, state := cbURL.Query().Get("code"), cbURL.Query().Get("state")
	if code == "" || state == "" {
		t.Fatalf("callback URL carried no code/state: %s", cbURL)
	}

	victim := browserOn(t, s)
	res := postCallback(t, s, victim, code, state)
	defer res.Body.Close()

	if v := sessionCookie(res); v != "" {
		t.Fatalf("form_post login CSRF succeeded: the victim's browser was handed a session cookie for the attacker's account (status %d)", res.StatusCode)
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusFound {
		t.Fatalf("form_post login CSRF succeeded: callback in a foreign browser returned %d (%s)", res.StatusCode, drainBody(res))
	}
	if n := sessionRows(t, s, att.ID); n != 0 {
		t.Fatalf("form_post login CSRF left %d session row(s) for the attacker's account, want 0", n)
	}
}

// TestOAuthLoginCSRF_RefusalDoesNotConsumeStateRow pins the ORDERING of the
// check. A refused delivery must not burn the state row, or the refusal becomes
// a denial-of-service on the person whose flow it is: the attacker's own
// browser — the one that legitimately started this flow — must still be able to
// finish it afterwards.
//
// It also states the rule positively. The callback is not being refused because
// the URL was reused; it is being refused because the browser presenting it did
// not start the flow.
func TestOAuthLoginCSRF_RefusalDoesNotConsumeStateRow(t *testing.T) {
	s, _ := newSecureStack(t)
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	owner := browserOn(t, s)
	cbURL := runFlowUpToCallback(t, s, owner)

	// Somebody else tries first and is refused.
	stranger := browserOn(t, s)
	res, err := stranger.Get(cbURL.String())
	if err != nil {
		t.Fatalf("stranger callback: %v", err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusFound {
		t.Fatalf("callback in a foreign browser returned %d — the state row was consumed by the wrong browser", res.StatusCode)
	}
	if n := sessionRows(t, s, att.ID); n != 0 {
		t.Fatalf("refused callback still issued %d session row(s)", n)
	}

	// The browser that actually started the flow finishes it.
	res2, err := owner.Get(cbURL.String())
	if err != nil {
		t.Fatalf("owner callback: %v", err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("the browser that STARTED the flow was refused after a stranger's attempt: %d (%s)",
			res2.StatusCode, drainBody(res2))
	}
	if sessionCookie(res2) == "" {
		t.Fatalf("the browser that started the flow completed without a session cookie")
	}
	if n := sessionRows(t, s, att.ID); n != 1 {
		t.Fatalf("owner's completed login wrote %d session rows, want 1", n)
	}
}

// --- positive controls ----------------------------------------------------

// TestOAuthLoginBinding_SameBrowserLoginStillCompletes is the indispensable
// control: one browser, one jar, /authorize → IdP → GET /callback still signs
// in. The cheapest wrong fix refuses every callback, and it would pass every
// test above.
func TestOAuthLoginBinding_SameBrowserLoginStillCompletes(t *testing.T) {
	s, _ := newSecureStack(t)
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	cl := browserOn(t, s)
	cbURL := runFlowUpToCallback(t, s, cl)

	res, err := cl.Get(cbURL.String())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("legitimate same-browser login: expected 200, got %d (%s)", res.StatusCode, drainBody(res))
	}
	if sessionCookie(res) == "" {
		t.Fatalf("legitimate same-browser login set no session cookie")
	}
	if n := sessionRows(t, s, att.ID); n != 1 {
		t.Fatalf("legitimate same-browser login wrote %d session rows, want 1", n)
	}
}

// TestOAuthLoginBinding_FormPostSameBrowserStillCompletes is the same control
// on the form_post leg, which is the one a binding cookie can most easily break
// (an IdP's POST is cross-site, so a Lax cookie would not be sent). The flow
// starts and finishes in ONE jar; only the delivery method differs.
func TestOAuthLoginBinding_FormPostSameBrowserStillCompletes(t *testing.T) {
	s, _ := newSecureStack(t)
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	cl := browserOn(t, s)
	cbURL := runFlowUpToCallback(t, s, cl)

	res := postCallback(t, s, cl, cbURL.Query().Get("code"), cbURL.Query().Get("state"))
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("legitimate same-browser form_post login: expected 200, got %d (%s)", res.StatusCode, drainBody(res))
	}
	if sessionCookie(res) == "" {
		t.Fatalf("legitimate same-browser form_post login set no session cookie")
	}
	if n := sessionRows(t, s, att.ID); n != 1 {
		t.Fatalf("legitimate same-browser form_post login wrote %d session rows, want 1", n)
	}
}

// TestOAuthLoginBinding_ConcurrentFlowsInOneBrowserBothComplete is the
// multi-tab regression. Two logins started in the SAME browser — two tabs, or
// two providers — and finished in reverse order must BOTH complete. A binding
// implemented as a single fixed-name cookie would have the second /authorize
// clobber the first, and the older tab would then be refused; that is a real
// user-visible breakage, not a hypothetical one.
func TestOAuthLoginBinding_ConcurrentFlowsInOneBrowserBothComplete(t *testing.T) {
	s, _ := newSecureStack(t)
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	cl := browserOn(t, s)
	first := runFlowUpToCallback(t, s, cl)
	second := runFlowUpToCallback(t, s, cl)

	// Finish the SECOND tab first, then go back to the first.
	res2, err := cl.Get(second.String())
	if err != nil {
		t.Fatalf("second tab callback: %v", err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("second concurrent tab: expected 200, got %d", res2.StatusCode)
	}

	res1, err := cl.Get(first.String())
	if err != nil {
		t.Fatalf("first tab callback: %v", err)
	}
	defer res1.Body.Close()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("the FIRST of two concurrent logins in one browser was refused: %d (%s) — a single fixed-name binding cookie clobbers itself",
			res1.StatusCode, drainBody(res1))
	}
	if sessionCookie(res1) == "" {
		t.Fatalf("the first concurrent login completed without a session cookie")
	}
	if n := sessionRows(t, s, att.ID); n != 2 {
		t.Fatalf("two concurrent logins wrote %d session rows, want 2", n)
	}
}

// TestOAuthLoginBinding_LegacyStateRowStillRedeems pins rolling-deploy safety.
// A state row written by the PREVIOUS binary belongs to a browser that was sent
// to the IdP before any binding existed, so nothing was ever written to it.
// Those callbacks must still complete for the rest of the state TTL — a binding
// that is enforced on every callback rather than only on the flows it actually
// started would sign every in-flight user out at deploy time.
func TestOAuthLoginBinding_LegacyStateRowStillRedeems(t *testing.T) {
	s, idp := newSecureStack(t)
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")
	ctx := context.Background()

	legacy := "login||"
	now := time.Now().UTC()
	if err := s.repo.CreateOAuthState(ctx, domain.NewOAuthState{
		State:       "legacy-unbound-state",
		Provider:    "fake",
		RedirectURL: &legacy,
		ExpiresAt:   now.Add(5 * time.Minute),
		CreatedAt:   now,
	}); err != nil {
		t.Fatalf("CreateOAuthState: %v", err)
	}

	// A browser that never visited this binary's /authorize, exactly as the
	// in-flight user's browser looks.
	cl := browserOn(t, s)
	authz := idp.srv.URL + "/oauth/authorize?state=legacy-unbound-state&redirect_uri=" +
		url.QueryEscape(s.srv.URL+"/api/auth/oauth/fake/callback")
	cb := driveIDP(t, cl, mustParse(t, authz))

	res, err := cl.Get(cb.String())
	if err != nil {
		t.Fatalf("legacy callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a state row from the previous binary no longer redeems: %d (%s)", res.StatusCode, drainBody(res))
	}
	if n := sessionRows(t, s, att.ID); n != 1 {
		t.Fatalf("legacy state row produced %d session rows, want 1", n)
	}
}

// --- the cookie itself ----------------------------------------------------

// authorizeCookies runs /authorize and returns the raw Set-Cookie header lines
// alongside the provider URL it redirected to, so a test can assert on the wire
// bytes rather than on what Go's cookiejar chose to keep — and still drive the
// rest of the flow through the real authorization URL, PKCE challenge and all.
func authorizeCookies(t *testing.T, s *stack, cl *http.Client) (setCookie []string, loc *url.URL) {
	t.Helper()
	res, err := cl.Get(s.srv.URL + "/api/auth/oauth/fake/authorize")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d", res.StatusCode)
	}
	loc, err = res.Location()
	if err != nil {
		t.Fatalf("authorize location: %v", err)
	}
	if loc.Query().Get("state") == "" {
		t.Fatalf("authorize: no state in %s", loc)
	}
	return res.Header.Values("Set-Cookie"), loc
}

// bindingCookieLine returns the Set-Cookie line for the binding cookie of the
// given state, or "".
func bindingCookieLine(lines []string, state string) string {
	name := auth.LoginBindingCookieName(state)
	if name == "" {
		return ""
	}
	for _, l := range lines {
		if strings.HasPrefix(l, name+"=") {
			return l
		}
	}
	return ""
}

// TestOAuthLoginBinding_AuthorizeCookieIsSameSiteNoneSecure asserts the wire
// bytes, and it is not decoration. Go's net/http/cookiejar ignores SameSite
// entirely, so the form_post positive controls above would pass just as happily
// against a SameSite=Lax cookie — which a real browser would refuse to send on
// an IdP's cross-site form_post POST, breaking every form_post login in
// production while the suite stayed green. The only place that can be caught is
// here, in the header.
func TestOAuthLoginBinding_AuthorizeCookieIsSameSiteNoneSecure(t *testing.T) {
	s, _ := newSecureStack(t)
	cl := browserOn(t, s)

	lines, loc := authorizeCookies(t, s, cl)
	state := loc.Query().Get("state")
	if !auth.IsBoundLoginState(state) {
		t.Fatalf("/authorize minted an unbound state %q on a cookie_secure deployment", state)
	}
	line := bindingCookieLine(lines, state)
	if line == "" {
		t.Fatalf("/authorize minted a bound state but set no binding cookie: %v", lines)
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
	// Scoped to the mount's real path, not the handler's post-StripPrefix one:
	// a cookie at Path=/oauth/fake/authorize would never come back.
	if !strings.Contains(line, "Path=/") {
		t.Fatalf("binding cookie has no usable Path (%q)", line)
	}
}

// TestOAuthLoginBinding_CookieClearedOnBothExits pins that the binding cookie
// is single-use like the state row it guards: expired on the success path AND
// on the refusal path, so a browser is not left carrying a dead binding for the
// rest of the state TTL.
func TestOAuthLoginBinding_CookieClearedOnBothExits(t *testing.T) {
	s, _ := newSecureStack(t)
	seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	// Success exit.
	cl := browserOn(t, s)
	cb := runFlowUpToCallback(t, s, cl)
	state := cb.Query().Get("state")
	res, err := cl.Get(cb.String())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("legitimate callback: %d", res.StatusCode)
	}
	assertBindingCleared(t, res, state, "success")

	// Refusal exit: a different browser presents the same shape.
	cl2 := browserOn(t, s)
	cb2 := runFlowUpToCallback(t, s, cl2)
	state2 := cb2.Query().Get("state")
	victim := browserOn(t, s)
	res2, err := victim.Get(cb2.String())
	if err != nil {
		t.Fatalf("victim callback: %v", err)
	}
	res2.Body.Close()
	assertBindingCleared(t, res2, state2, "refusal")
}

func assertBindingCleared(t *testing.T, res *http.Response, state, exit string) {
	t.Helper()
	name := auth.LoginBindingCookieName(state)
	if name == "" {
		t.Fatalf("%s exit: state %q is not bound, nothing to clear", exit, state)
	}
	for _, c := range res.Cookies() {
		if c.Name != name {
			continue
		}
		if c.MaxAge >= 0 {
			t.Fatalf("%s exit: binding cookie %q was not expired (MaxAge=%d)", exit, name, c.MaxAge)
		}
		return
	}
	t.Fatalf("%s exit: no Set-Cookie expiring the binding cookie %q (headers: %v)",
		exit, name, res.Header.Values("Set-Cookie"))
}

// --- the modes ------------------------------------------------------------

// TestOAuthLoginBinding_AutoIsOffOnPlainHTTP is honest documentation, not a
// wish. Under "auto" a deployment with cookie_secure=false mints an UNBOUND
// state, sets no cookie, and the replay still succeeds — because a binding
// cookie there could only be SameSite=Lax, which a browser will not send on an
// IdP's form_post, so enforcing it would refuse every such login instead of
// protecting anyone. Operators who terminate TLS elsewhere and still want the
// binding set "required"; the case below proves that works.
func TestOAuthLoginBinding_AutoIsOffOnPlainHTTP(t *testing.T) {
	idp := newPKCEIdP(t)
	s := newStackOnBinding(t, idp.srv, attackerInfo(), nil, false, "auto")
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	attacker := browserOn(t, s)
	lines, loc := authorizeCookies(t, s, attacker)
	state := loc.Query().Get("state")
	if auth.IsBoundLoginState(state) {
		t.Fatalf("auto minted a BOUND state %q on a plain-HTTP deployment", state)
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "yauth_lb_") {
			t.Fatalf("auto set a binding cookie on a plain-HTTP deployment: %q", l)
		}
	}

	cb := driveIDP(t, attacker, loc)
	victim := browserOn(t, s)
	res, err := victim.Get(cb.String())
	if err != nil {
		t.Fatalf("victim callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("auto on plain HTTP: expected the replay to STILL succeed (that is the documented gap), got %d", res.StatusCode)
	}
	if n := sessionRows(t, s, att.ID); n != 1 {
		t.Fatalf("auto on plain HTTP wrote %d session rows, want 1", n)
	}
}

// TestOAuthLoginBinding_RequiredEnforcesOnPlainHTTP is the escape hatch in the
// other direction: an operator whose TLS terminates at a proxy sets "required"
// and gets the binding regardless of the local cookie posture.
func TestOAuthLoginBinding_RequiredEnforcesOnPlainHTTP(t *testing.T) {
	idp := newPKCEIdP(t)
	s := newStackOnBinding(t, idp.srv, attackerInfo(), nil, false, "required")
	att := seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	attacker := browserOn(t, s)
	_, loc := authorizeCookies(t, s, attacker)
	if state := loc.Query().Get("state"); !auth.IsBoundLoginState(state) {
		t.Fatalf("required minted an unbound state %q", state)
	}

	cb := driveIDP(t, attacker, loc)

	victim := browserOn(t, s)
	res, err := victim.Get(cb.String())
	if err != nil {
		t.Fatalf("victim callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusFound {
		t.Fatalf("required did not enforce on plain HTTP: replay returned %d", res.StatusCode)
	}
	if sessionCookie(res) != "" {
		t.Fatalf("required: the victim's browser was handed a session cookie anyway")
	}
	if n := sessionRows(t, s, att.ID); n != 0 {
		t.Fatalf("required: replay left %d session rows, want 0", n)
	}

	// POSITIVE CONTROL for this mode: the browser that started it still wins.
	// Its jar holds a non-Secure Lax cookie, which Go's client sends over http.
	res2, err := attacker.Get(cb.String())
	if err != nil {
		t.Fatalf("owner callback: %v", err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("required refused the browser that STARTED the flow: %d (%s)", res2.StatusCode, drainBody(res2))
	}
}

// TestOAuthLoginBinding_RefusalNamesTheKnob pins the operator-facing half of
// the contract from the Risk analysis: the 400 body must name
// plugins.oauth.login_state_binding, so whoever reads the support ticket learns
// the escape hatch from the response instead of going looking for it.
func TestOAuthLoginBinding_RefusalNamesTheKnob(t *testing.T) {
	s, _ := newSecureStack(t)
	seedLinkedUser(t, s, "attacker@evil.example", "attacker-remote")

	attacker := browserOn(t, s)
	cb := runFlowUpToCallback(t, s, attacker)
	victim := browserOn(t, s)
	res, err := victim.Get(cb.String())
	if err != nil {
		t.Fatalf("victim callback: %v", err)
	}
	body := drainBody(res)
	if !strings.Contains(body, "plugins.oauth.login_state_binding") {
		t.Fatalf("the refusal does not name the knob: %s", body)
	}
}

// TestOAuthLoginBinding_MalformedStateDoesNotPanic is the remote-crash guard.
// `state` is fully attacker-controlled on a public unauthenticated route, and
// the binding helpers slice it; anything that assumed a length would be a
// one-request denial of service. Every shape below must come back as an
// ordinary 4xx.
func TestOAuthLoginBinding_MalformedStateDoesNotPanic(t *testing.T) {
	s, _ := newSecureStack(t)
	cl := browserOn(t, s)

	for _, state := range []string{"b", "b.", "b.A", "b..", auth.BoundStatePrefix + strings.Repeat("A", 42)} {
		res, err := cl.Get(s.srv.URL + "/api/auth/oauth/fake/callback?code=x&state=" + url.QueryEscape(state))
		if err != nil {
			t.Fatalf("callback with state=%q: %v", state, err)
		}
		res.Body.Close()
		if res.StatusCode >= 500 {
			t.Fatalf("callback with state=%q returned %d — a malformed state must not be a server error", state, res.StatusCode)
		}
	}
}
