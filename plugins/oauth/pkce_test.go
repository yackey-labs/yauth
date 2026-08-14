package oauth_test

// pkce_test.go — plugins/oauth runs the authorization-code flow with no PKCE
// on either leg, so an authorization code is a bearer value that anybody can
// redeem.
//
// registerAuthorize builds the redirect as
// `prov.Config().AuthCodeURL(state, oauth2.AccessTypeOffline)` and
// registerCallback redeems it as `prov.Config().Exchange(ctx, code)` — no
// code_challenge goes out, no code_verifier comes back, and grep finds no
// mention of S256 anywhere under plugins/oauth. The sibling relying party does
// it correctly (plugins/ssooidc/handlers_login.go generates a verifier, sends
// oauth2.S256ChallengeOption on the way out and oauth2.VerifierOption on the
// way back).
//
// What the missing binding costs, exactly: the ONLY thing tying a callback to
// the browser that started the flow is the `state` row, and the code is checked
// against nothing at all. So an attacker who obtains a victim's authorization
// code — a query-string value that leaks through browser history, an access
// log, a Referer off the landing page, or a proxy — replays it against a state
// row of their OWN. ConsumeOAuthState succeeds (the row is theirs), Exchange
// succeeds (nothing is compared), FetchUserInfo returns the VICTIM's identity,
// and completeLogin calls auth.IssueSession for the victim and writes the
// cookie onto the ATTACKER's browser. That is a full account takeover from a
// leaked URL.
//
// The tests below run against an IdP that behaves like a real one: it records
// the code_challenge presented at /authorize and refuses the token request with
// invalid_grant when the code_verifier does not match it. Against today's
// plugin no challenge is ever recorded, so the injection sails through.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/oauth"
)

// --- an IdP that enforces PKCE -------------------------------------------

// pkceIDP is newProviderServer's stricter twin. /authorize mints a distinct
// code per request and remembers the code_challenge that came with it (empty
// when the client sent none, which is exactly what a non-PKCE client looks
// like on the wire); /token then requires a code_verifier whose S256 hash
// matches, and answers invalid_grant when it does not — RFC 7636 §4.6.
type pkceIDP struct {
	srv *httptest.Server

	mu         sync.Mutex
	challenge  map[string]string // code -> code_challenge seen at /authorize
	method     map[string]string // code -> code_challenge_method
	seq        int
	rejections int // token requests refused for a bad/missing verifier
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newPKCEIdP(t *testing.T) *pkceIDP {
	t.Helper()
	idp := &pkceIDP{
		challenge: map[string]string{},
		method:    map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		state, redirect := q.Get("state"), q.Get("redirect_uri")
		if state == "" || redirect == "" {
			http.Error(w, "missing state/redirect_uri", http.StatusBadRequest)
			return
		}
		u, err := url.Parse(redirect)
		if err != nil {
			http.Error(w, "bad redirect", http.StatusBadRequest)
			return
		}
		idp.mu.Lock()
		idp.seq++
		code := fmt.Sprintf("code-%d", idp.seq)
		idp.challenge[code] = q.Get("code_challenge")
		idp.method[code] = q.Get("code_challenge_method")
		idp.mu.Unlock()

		rq := u.Query()
		rq.Set("code", code)
		rq.Set("state", state)
		u.RawQuery = rq.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.FormValue("code")
		verifier := r.FormValue("code_verifier")

		idp.mu.Lock()
		want, known := idp.challenge[code]
		if known && want != "" && s256(verifier) != want {
			idp.rejections++
			idp.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "PKCE verification failed",
			})
			return
		}
		idp.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-" + code,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// challengeFor reports the code_challenge (and method) the plugin presented
// when the given code was issued.
func (i *pkceIDP) challengeFor(code string) (string, string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.challenge[code], i.method[code]
}

// rejectionCount reports how many token requests the IdP refused for a
// bad/missing code_verifier.
func (i *pkceIDP) rejectionCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.rejections
}

// --- browser helpers ------------------------------------------------------

// newBrowser is a second cookie-jarred client, so the attacker's browser and
// the victim's browser are genuinely distinct: the whole claim is that the
// victim's session cookie must not land on the attacker's jar.
func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// beginAuthorize performs GET /oauth/fake/authorize on the given browser and
// returns the provider URL it was redirected to plus the minted state. It
// stops there — the state row is now live and bound to nobody.
func beginAuthorize(t *testing.T, s *stack, cl *http.Client) (*url.URL, string) {
	t.Helper()
	res, err := cl.Get(s.srv.URL + "/api/auth/oauth/fake/authorize")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d", res.StatusCode)
	}
	loc, err := res.Location()
	if err != nil {
		t.Fatalf("authorize location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatalf("authorize: no state in %s", loc)
	}
	return loc, state
}

// driveIDP follows the provider's own redirect back to /callback and returns
// that callback URL WITHOUT requesting it — this is the moment the code exists
// in a URL and can leak.
func driveIDP(t *testing.T, cl *http.Client, authorizeLoc *url.URL) *url.URL {
	t.Helper()
	res, err := cl.Get(authorizeLoc.String())
	if err != nil {
		t.Fatalf("provider authorize: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("provider authorize: expected 302, got %d", res.StatusCode)
	}
	cb, err := res.Location()
	if err != nil {
		t.Fatalf("provider redirect: %v", err)
	}
	return cb
}

// seedLinkedUser creates the victim: a real user row already linked to the
// provider identity the fake FetchUserInfo returns, so completeLogin takes the
// "already linked" branch and issues a session for THAT user.
func seedLinkedUser(t *testing.T, s *stack, email, providerUserID string) domain.User {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	u, err := s.repo.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: email, EmailVerified: true, Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.repo.CreateOAuthAccount(ctx, domain.NewOAuthAccount{
		ID: uuid.NewString(), UserID: u.ID, Provider: "fake", ProviderUserID: providerUserID,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateOAuthAccount: %v", err)
	}
	return u
}

func victimInfo() oauth.UserInfo {
	return oauth.UserInfo{
		ProviderUserID: "victim-remote",
		Email:          "victim@corp.example",
		EmailVerified:  true,
		Name:           "Victim",
	}
}

// --- the defect -----------------------------------------------------------

// TestOAuthAuthorize_SendsPKCEChallenge is the first leg on its own: the
// redirect the browser is handed must carry a code_challenge, because without
// one the token endpoint has nothing to bind the code to. It is asserted
// against the IdP's own record of the request, not against the URL string, so
// it stays true however the challenge is plumbed.
func TestOAuthAuthorize_SendsPKCEChallenge(t *testing.T) {
	idp := newPKCEIdP(t)
	s := newStackOn(t, idp.srv, victimInfo(), nil)

	cl := newBrowser(t)
	loc, _ := beginAuthorize(t, s, cl)
	cb := driveIDP(t, cl, loc)

	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("provider returned no code: %s", cb)
	}
	challenge, method := idp.challengeFor(code)
	if challenge == "" {
		t.Fatalf("/authorize sent no code_challenge, so the authorization code is bound to nothing: %s", loc)
	}
	if method != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", method)
	}
}

// TestOAuthCallback_RefusesInjectedAuthorizationCode is the takeover itself.
//
//  1. the attacker opens /authorize in their own browser and STOPS at the 302,
//     keeping a live state row bound to nobody;
//  2. the victim starts a real login and their authorization code reaches the
//     callback URL, where it leaks (history, log, Referer, proxy);
//  3. the attacker submits the victim's code with the attacker's state.
//
// With the code bound to a verifier the token endpoint answers invalid_grant
// and the callback can only 502. The assertions are about state, not status:
// no session row for the victim and no session cookie on the attacker's jar.
func TestOAuthCallback_RefusesInjectedAuthorizationCode(t *testing.T) {
	idp := newPKCEIdP(t)
	s := newStackOn(t, idp.srv, victimInfo(), nil)
	victim := seedLinkedUser(t, s, "victim@corp.example", "victim-remote")

	// 1. attacker's own, unfinished flow.
	attacker := newBrowser(t)
	_, attackerState := beginAuthorize(t, s, attacker)

	// 2. victim's real flow, up to (not including) the callback request.
	victimBrowser := newBrowser(t)
	vloc, _ := beginAuthorize(t, s, victimBrowser)
	victimCallback := driveIDP(t, victimBrowser, vloc)
	victimCode := victimCallback.Query().Get("code")
	if victimCode == "" {
		t.Fatalf("victim callback carried no code: %s", victimCallback)
	}

	// 3. the injection.
	res, err := attacker.Get(s.srv.URL + "/api/auth/oauth/fake/callback?code=" +
		url.QueryEscape(victimCode) + "&state=" + url.QueryEscape(attackerState))
	if err != nil {
		t.Fatalf("injected callback: %v", err)
	}
	defer res.Body.Close()

	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Fatalf("code injection minted a session cookie for the victim on the attacker's browser (status %d)", res.StatusCode)
		}
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusFound {
		t.Fatalf("code injection succeeded: status %d (%s)", res.StatusCode, drainBody(res))
	}
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 from the refused code exchange, got %d (%s)", res.StatusCode, drainBody(res))
	}
	if idp.rejectionCount() == 0 {
		t.Errorf("the token endpoint never had to refuse anything: the exchange carried no code_verifier to check")
	}

	n, err := s.repo.DeleteUserSessions(context.Background(), victim.ID)
	if err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}
	if n != 0 {
		t.Fatalf("code injection left %d session row(s) for the victim", n)
	}

	// The attacker's browser is still anonymous.
	sres, err := attacker.Get(s.srv.URL + "/api/auth/session")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	sres.Body.Close()
	if sres.StatusCode == http.StatusOK {
		t.Fatalf("attacker's browser holds a session after the injection")
	}
}

// --- positive controls ----------------------------------------------------

// TestOAuthPKCE_LegitimateLoginStillCompletes is the control that stops the
// cheap wrong fix (send a challenge, never send the verifier — which would
// break every login against a PKCE-enforcing IdP). The victim's own flow, run
// end to end on one browser, must still produce a session.
func TestOAuthPKCE_LegitimateLoginStillCompletes(t *testing.T) {
	idp := newPKCEIdP(t)
	s := newStackOn(t, idp.srv, victimInfo(), nil)
	victim := seedLinkedUser(t, s, "victim@corp.example", "victim-remote")

	cl := newBrowser(t)
	loc, _ := beginAuthorize(t, s, cl)
	cb := driveIDP(t, cl, loc)

	res, err := cl.Get(cb.String())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("legitimate login: expected 200, got %d (%s)", res.StatusCode, drainBody(res))
	}
	got := false
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			got = true
		}
	}
	if !got {
		t.Fatalf("legitimate login set no session cookie")
	}
	n, err := s.repo.DeleteUserSessions(context.Background(), victim.ID)
	if err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("legitimate login wrote %d session rows, want 1", n)
	}
}

// TestOAuthCallback_LegacyStateRowStillRedeems covers the rolling deploy: a
// state row written by the PREVIOUS binary carries the old three-segment
// "mode|userID|redirect" payload and no verifier, and the browser it belongs to
// is already at the IdP with no challenge attached. That callback must still
// complete — i.e. the new code must send no code_verifier when the row has
// none, rather than sending an empty one or refusing outright.
func TestOAuthCallback_LegacyStateRowStillRedeems(t *testing.T) {
	idp := newPKCEIdP(t)
	s := newStackOn(t, idp.srv, victimInfo(), nil)
	victim := seedLinkedUser(t, s, "victim@corp.example", "victim-remote")
	ctx := context.Background()

	// A row exactly as the old binary wrote it.
	legacy := "login||"
	now := time.Now().UTC()
	if err := s.repo.CreateOAuthState(ctx, domain.NewOAuthState{
		State:       "legacy-state-token",
		Provider:    "fake",
		RedirectURL: &legacy,
		ExpiresAt:   now.Add(5 * time.Minute),
		CreatedAt:   now,
	}); err != nil {
		t.Fatalf("CreateOAuthState: %v", err)
	}

	// The old binary's redirect carried no code_challenge, so ask the IdP for a
	// code the same way.
	cl := newBrowser(t)
	authzURL := idp.srv.URL + "/oauth/authorize?state=legacy-state-token&redirect_uri=" +
		url.QueryEscape(s.srv.URL+"/api/auth/oauth/fake/callback")
	cb := driveIDP(t, cl, mustParse(t, authzURL))

	res, err := cl.Get(cb.String())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("legacy state row: expected 200, got %d (%s)", res.StatusCode, drainBody(res))
	}
	n, err := s.repo.DeleteUserSessions(ctx, victim.ID)
	if err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("legacy state row produced %d session rows, want 1", n)
	}
}

// TestOAuthCallback_LegacyStateRowWithPipeInRedirectStaysOnOrigin is the trap
// the state-payload widening sets for itself, and it is a rolling-deploy
// window, not a theoretical one.
//
// auth.SafeRedirect passes ANY single-leading-slash path through byte for byte
// — that is deliberate, and redirect_e2e_test.go pins it — so "/x|//evil.com"
// is a redirect_url the OLD binary would happily store, as the three-segment
// payload "login||/x|//evil.com". The new payload is
// "mode|userID|verifier|redirect", and a naive strings.SplitN(raw, "|", 4)
// reads that legacy row as verifier="/x", redirect="//evil.com" — which
// completeLogin writes into the Location header with no re-filtering, because
// the filtering already happened at /authorize. A protocol-relative Location is
// an open redirect to another origin, and "//evil.com/path" is already on the
// hostile list of TestOAuthCallback_RefusesBrowserNormalisedOpenRedirect.
//
// So the decode must recognise that "/x" is not a code verifier and fall back
// to the legacy reading: the redirect is everything after the second "|",
// intact, and the browser stays on this origin.
func TestOAuthCallback_LegacyStateRowWithPipeInRedirectStaysOnOrigin(t *testing.T) {
	idp := newPKCEIdP(t)
	s := newStackOn(t, idp.srv, victimInfo(), nil)
	seedLinkedUser(t, s, "victim@corp.example", "victim-remote")
	ctx := context.Background()

	// Exactly the bytes the previous binary wrote for
	// ?redirect_url=/x|//evil.com.
	legacy := "login||/x|//evil.com"
	now := time.Now().UTC()
	if err := s.repo.CreateOAuthState(ctx, domain.NewOAuthState{
		State:       "legacy-pipe-state",
		Provider:    "fake",
		RedirectURL: &legacy,
		ExpiresAt:   now.Add(5 * time.Minute),
		CreatedAt:   now,
	}); err != nil {
		t.Fatalf("CreateOAuthState: %v", err)
	}

	cl := newBrowser(t)
	authzURL := idp.srv.URL + "/oauth/authorize?state=legacy-pipe-state&redirect_uri=" +
		url.QueryEscape(s.srv.URL+"/api/auth/oauth/fake/callback")
	cb := driveIDP(t, cl, mustParse(t, authzURL))

	res, err := cl.Get(cb.String())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("legacy state row with a pipe in its redirect: expected 302, got %d (%s)",
			res.StatusCode, drainBody(res))
	}

	raw := res.Header.Get("Location")
	if raw != "/x|//evil.com" {
		t.Fatalf("legacy redirect was mangled by the new payload decode: Location = %q, want %q",
			raw, "/x|//evil.com")
	}
	// The assertion that matters: wherever the browser actually goes, it is
	// this origin.
	loc, err := res.Location()
	if err != nil {
		t.Fatalf("resolve Location: %v", err)
	}
	self := mustParse(t, s.srv.URL)
	if loc.Host != self.Host || loc.Scheme != self.Scheme {
		t.Fatalf("legacy state row sent the browser off-origin: %s (this origin is %s)", loc, self)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
