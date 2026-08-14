// login_binding.go — ties a federated login state to the browser that started
// the flow.
//
// THE DEFECT THIS CLOSES. Both federated relying-party plugins (plugins/oauth
// and plugins/ssooidc) kept their login state entirely server-side: /authorize
// (or /sso/login) minted a random `state`, wrote a row, and 302'd to the IdP
// WITHOUT writing anything to the browser. The callback then looked the row up,
// exchanged the code and called auth.IssueSession + http.SetCookie on whatever
// browser happened to make the callback request. The row says which provider
// and which redirect; it does not say which browser.
//
// So an attacker could start a login in their OWN browser, authenticate at the
// IdP as themselves, STOP at the ".../callback?code=…&state=…" URL, and mail it
// to a victim. The victim's browser presents it, the server exchanges the
// attacker's code for the attacker's identity, and Set-Cookies a session for the
// ATTACKER's account into the VICTIM's browser. yauth is itself an IdP, so from
// that moment every downstream relying party signs the victim in as the
// attacker, and any passkey or second factor the victim goes on to enrol is
// enrolled on the attacker's account. That is login CSRF / session fixation,
// RFC 9700 §4.1.
//
// PKCE (already merged) does not help: in that attack the code, the state row
// and the verifier are ALL consistently the attacker's, so the S256 check passes
// exactly as designed.
//
// THE DESIGN. Put a secret in the browser at mint time and DERIVE the public
// state from it:
//
//	secret = 32 random bytes, base64url            (cookie value, never leaves the browser)
//	state  = "b." || base64url(sha256(secret))     (public: rides through the IdP)
//
// Nothing new is persisted — no column, no migration — because the state row
// already exists and the state string itself carries the proof obligation. The
// state is public by construction (it travels through the IdP, browser history,
// access logs, a Referer) and reveals nothing about the secret.
//
// WHY THE COOKIE LOOKS LIKE THIS, which is the whole reason this took a
// dedicated file rather than a line in each plugin:
//
//   - SameSite=None (with Secure) rather than the session cookie's Lax. An IdP
//     using response_mode=form_post returns by making the browser POST
//     cross-site to the callback, and a Lax cookie is NOT sent on a cross-site
//     POST. A Lax binding cookie would therefore refuse every form_post login in
//     a real browser while passing any Go test (net/http/cookiejar ignores
//     SameSite entirely). None is safe HERE specifically: the cookie authorises
//     nothing at all — it only proves this browser started this flow — and the
//     state it unlocks is single-use and server-side.
//   - The NAME is derived from the state. Two logins open in one browser (two
//     tabs, two providers) must both complete; a single fixed-name cookie would
//     have the second /authorize clobber the first and the older tab would then
//     be refused. The callback knows the state, so it knows which cookie to read.
//   - HttpOnly always. Script has no business reading it.
//
// ENFORCEMENT IS DECIDED AT MINT TIME, never at callback time. The "b." prefix
// on the state IS the decision, recorded by the server when it minted the state.
// A callback therefore needs no config lookup, and an attacker cannot downgrade
// by choosing the callback's method, headers or content type. It also makes a
// rolling deploy safe in both directions: a state row written by the previous
// binary has no prefix and is simply not checked, so in-flight logins are not
// signed out at deploy time.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// BoundStatePrefix marks a login state as browser-bound.
//
// It is "b." and NOT a bare "b" on purpose. Both existing state generators —
// plugins/oauth's generateState and plugins/ssooidc's generateRandom — return
// base64.RawURLEncoding, whose alphabet (A-Za-z0-9-_) CONTAINS 'b'. With a
// one-character sentinel, roughly 1 in 64 of every unbound state (legacy rows
// mid-deploy, and every state minted while binding is off) would begin with 'b'
// and be misclassified as bound — then refused for a cookie that was never
// written. Roughly 1.5% of all logins failing at random is not an acceptable
// price for a shorter constant. '.' is URL-unreserved (RFC 3986 §2.3), so it
// travels through any IdP untouched, and it cannot occur in base64url output.
const BoundStatePrefix = "b."

// boundStateDigestLen is the length of base64url(sha256(...)) without padding:
// ceil(256/6) = 43 characters. A bound state is therefore always exactly
// len(BoundStatePrefix)+43 characters, which IsBoundLoginState insists on.
const boundStateDigestLen = 43

// loginBindingCookiePrefix namespaces the per-state cookie. The suffix is a
// slice of the state's own digest, so concurrent flows in one browser get
// distinct cookies (see the package comment).
const loginBindingCookiePrefix = "yauth_lb_"

// loginBindingNameDigestLen is how much of the digest goes into the cookie
// name. 12 base64url characters is 72 bits — two concurrent flows in one
// browser will not collide, and the name stays short enough to be unremarkable
// in a Cookie header.
const loginBindingNameDigestLen = 12

// Login-state binding modes, as spelled in
// plugins.oauth.login_state_binding / plugins.sso_oidc.login_state_binding.
const (
	// LoginStateBindingAuto binds iff the deployment issues Secure cookies.
	// This is the zero value: every TLS deployment gets the fix without
	// touching yaml, and a plain-HTTP deployment — which cannot use
	// SameSite=None at all, so the cookie could not survive a form_post
	// callback — keeps working exactly as before. Plain HTTP is therefore NOT
	// protected under "auto"; that is a deliberate, documented fallback, not
	// an oversight.
	LoginStateBindingAuto = "auto"
	// LoginStateBindingRequired binds regardless of cookie posture. Correct
	// for a deployment terminating TLS at a proxy that nonetheless wants the
	// binding, and for tests.
	LoginStateBindingRequired = "required"
	// LoginStateBindingOff never binds. The escape hatch for deployments whose
	// login genuinely cannot carry the cookie — see docs/federation.md.
	LoginStateBindingOff = "off"
)

// NormalizeLoginStateBinding validates a configured mode and returns its
// canonical form. The empty string means "auto". An unknown value is an
// operator typo and must be loud: silently falling back to "auto" would turn a
// deliberate "off" typed as "of" into an enforced binding that refuses every
// login in production.
func NormalizeLoginStateBinding(mode string) (string, error) {
	switch mode {
	case "", LoginStateBindingAuto:
		return LoginStateBindingAuto, nil
	case LoginStateBindingRequired:
		return LoginStateBindingRequired, nil
	case LoginStateBindingOff:
		return LoginStateBindingOff, nil
	}
	return "", fmt.Errorf("login_state_binding: unknown value %q (want %q, %q, or %q)",
		mode, LoginStateBindingAuto, LoginStateBindingRequired, LoginStateBindingOff)
}

// BindLoginState reports whether a flow starting now should mint a BOUND state,
// given the normalized mode and the deployment's cookie posture
// (host.CookieSecure()). Callers ask this ONCE, at mint time.
func BindLoginState(mode string, cookieSecure bool) bool {
	switch mode {
	case LoginStateBindingOff:
		return false
	case LoginStateBindingRequired:
		return true
	default: // auto, and any value that survived normalization
		return cookieSecure
	}
}

// NewBoundLoginState mints a fresh (secret, state) pair. The secret goes in the
// cookie via LoginBindingCookie; the state goes to the IdP and into the state
// row. Only the state is ever persisted, and it is a one-way function of the
// secret, so a database reader cannot forge the cookie.
func NewBoundLoginState() (secret, state string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("auth: read random login binding secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(buf)
	return secret, deriveBoundLoginState(secret), nil
}

func deriveBoundLoginState(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return BoundStatePrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// IsBoundLoginState reports whether this state was minted by NewBoundLoginState
// and therefore carries a browser-side companion that the callback must check.
//
// It is deliberately strict — prefix AND exact length AND alphabet — for two
// independent reasons. (1) A state that merely starts with the prefix but is
// otherwise malformed must not be treated as bound, or an unbound legacy state
// could be refused for a cookie nobody ever wrote. (2) `state` is fully
// attacker-controlled on a public unauthenticated route (anyone can GET
// /oauth/{provider}/callback?state=whatever), so every downstream helper that
// slices the state — LoginBindingCookieName — must be able to rely on the
// shape rather than on a slice expression that could run off the end.
func IsBoundLoginState(state string) bool {
	if len(state) != len(BoundStatePrefix)+boundStateDigestLen {
		return false
	}
	if state[:len(BoundStatePrefix)] != BoundStatePrefix {
		return false
	}
	for i := len(BoundStatePrefix); i < len(state); i++ {
		c := state[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// LoginBindingCookieName is the per-state cookie name. It is TOTAL: any state
// that is not a well-formed bound state yields "", never a panic. The callback
// reaches this with a value an anonymous caller chose, so "state=b." must
// answer "" rather than index out of range.
func LoginBindingCookieName(state string) string {
	if !IsBoundLoginState(state) {
		return ""
	}
	start := len(BoundStatePrefix)
	return loginBindingCookiePrefix + state[start:start+loginBindingNameDigestLen]
}

// VerifyLoginBinding reports whether secret is the one this state was derived
// from. Constant-time, because the comparison runs on an unauthenticated route
// against a value the caller supplies.
func VerifyLoginBinding(state, secret string) bool {
	if !IsBoundLoginState(state) || secret == "" {
		return false
	}
	want := deriveBoundLoginState(secret)
	return subtle.ConstantTimeCompare([]byte(state), []byte(want)) == 1
}

// LoginBindingCookie builds the browser-side half of the binding. opts is the
// deployment's ordinary cookie options — built by each plugin's
// cookieOptionsFromHost, so Path, Domain and Secure are IDENTICAL to the
// session cookie's and inherit host.CookiePath() / auth.ResolveCookieDomain.
// That matters: yauth is normally mounted under http.StripPrefix("/api/auth"),
// so a path derived from the handler's own r.URL.Path would be wrong and the
// cookie would never come back.
//
// Only three fields are overridden: the per-state Name, the MaxAge (the state
// TTL, not the session TTL — the cookie is worthless the moment the state row
// expires), and SameSite. Returns nil for a malformed state; callers must
// nil-check rather than pass it to http.SetCookie.
func LoginBindingCookie(opts CookieOptions, state, secret string, ttl time.Duration) *http.Cookie {
	name := LoginBindingCookieName(state)
	if name == "" || secret == "" {
		return nil
	}
	maxAge := int(ttl.Seconds())
	if maxAge <= 0 {
		maxAge = 600
	}
	return &http.Cookie{
		Name:     name,
		Value:    secret,
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   maxAge,
		Secure:   opts.Secure,
		HttpOnly: true,
		SameSite: loginBindingSameSite(opts.Secure),
	}
}

// ClearLoginBindingCookie expires the binding cookie. Name, Path, Domain,
// Secure and SameSite must match LoginBindingCookie's or the browser will not
// consider it the same cookie and the stale one will linger for the whole TTL.
// Returns nil for a malformed state.
func ClearLoginBindingCookie(opts CookieOptions, state string) *http.Cookie {
	name := LoginBindingCookieName(state)
	if name == "" {
		return nil
	}
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   -1,
		Secure:   opts.Secure,
		HttpOnly: true,
		SameSite: loginBindingSameSite(opts.Secure),
	}
}

// loginBindingSameSite picks None on a Secure deployment and Lax otherwise.
// None is what makes the cookie arrive on an IdP's cross-site form_post POST;
// browsers reject SameSite=None without Secure outright, so on a plain-HTTP
// deployment the only honest choice is Lax — and that is precisely why "auto"
// does not enforce binding there.
func loginBindingSameSite(secure bool) http.SameSite {
	if secure {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}
