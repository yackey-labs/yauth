package auth

// login_binding_test.go — unit cover for the primitive that ties a federated
// login state to the browser that started the flow.
//
// The defect it exists for lives in plugins/oauth/handlers.go and
// plugins/ssooidc/handlers_login.go: /authorize and /sso/login minted a random
// state, wrote a server-side row and redirected to the IdP without writing
// anything to the browser, so the callback — which calls auth.IssueSession and
// http.SetCookie on whoever shows up — had no way to tell the browser that
// started the flow from any other. A finished-but-undelivered callback URL was
// therefore a portable credential for the attacker's own account, and yauth is
// itself an IdP, so a victim who opened it was signed in as the attacker
// everywhere downstream.
//
// The cases below pin the three properties the plugin-level guard leans on, all
// of which are reachable from a public unauthenticated route with an
// attacker-chosen `state`:
//
//   - a bound state round-trips only with the exact secret it came from;
//   - IsBoundLoginState is strict enough that a legacy/unbound state is never
//     mistaken for a bound one (the regression guard for a one-character
//     sentinel: base64url's alphabet contains 'b', so ~1 in 64 unbound states
//     would have been refused for a cookie nobody wrote);
//   - every helper that slices the state is TOTAL, because "state=b." is one
//     GET away from any anonymous caller.
//
// The cookie cases pin SameSite=None+Secure, which is not decoration: an IdP
// using response_mode=form_post returns via a cross-site POST, and a Lax cookie
// would simply not be sent — the binding would refuse every form_post login in
// a real browser while passing any Go test, since net/http/cookiejar ignores
// SameSite entirely. That is exactly why it is asserted HERE, at the header
// level, rather than left to the integration positive controls.

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func secureOpts() CookieOptions {
	return CookieOptions{
		Name:     "yauth_session",
		Path:     "/",
		Domain:   "auth.example.com",
		Secure:   true,
		SameSite: "Lax",
		MaxAge:   3600,
	}
}

// --- state derivation -----------------------------------------------------

func TestNewBoundLoginState_RoundTrips(t *testing.T) {
	secret, state, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}
	if !IsBoundLoginState(state) {
		t.Fatalf("freshly minted state %q is not recognised as bound", state)
	}
	if !VerifyLoginBinding(state, secret) {
		t.Fatalf("the secret that minted %q does not verify against it", state)
	}
	// The state is public — it rides through the IdP, browser history and
	// access logs — so it must not be the secret in disguise.
	if strings.Contains(state, secret) {
		t.Fatalf("the public state embeds the secret")
	}
	sum := sha256.Sum256([]byte(secret))
	if want := BoundStatePrefix + base64.RawURLEncoding.EncodeToString(sum[:]); state != want {
		t.Fatalf("state is not prefix+base64url(sha256(secret)): got %q want %q", state, want)
	}
}

func TestNewBoundLoginState_IsFresh(t *testing.T) {
	_, a, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}
	_, b, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}
	if a == b {
		t.Fatalf("two mints produced the same state %q — concurrent flows would collide", a)
	}
}

// TestVerifyLoginBinding_WrongSecretRefused is the attack in miniature: the
// victim's browser holds no cookie for the attacker's state, or holds one for
// a different flow. Either way it must not verify.
func TestVerifyLoginBinding_WrongSecretRefused(t *testing.T) {
	_, state, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}
	other, _, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}

	for name, secret := range map[string]string{
		"another flow's secret": other,
		"empty":                 "",
		"truncated":             "",
	} {
		if name == "truncated" {
			// Rebuild the real secret minus its last character: a prefix of
			// the right value must not verify.
			s, st, err := NewBoundLoginState()
			if err != nil {
				t.Fatalf("NewBoundLoginState: %v", err)
			}
			if VerifyLoginBinding(st, s[:len(s)-1]) {
				t.Fatalf("a truncated secret verified")
			}
			continue
		}
		if VerifyLoginBinding(state, secret) {
			t.Fatalf("%s verified against a state it did not mint", name)
		}
	}
}

// TestIsBoundLoginState_LegacyStatesNotBound is the rolling-deploy guard and
// the reason the sentinel is "b." rather than "b". Both existing generators
// (plugins/oauth generateState, plugins/ssooidc generateRandom) emit
// base64.RawURLEncoding, whose alphabet contains 'b'. With a one-character
// prefix, roughly 1 in 64 unbound states — legacy rows mid-deploy, and every
// state minted while binding is off — would be classified as bound and refused
// for a cookie that was never written.
func TestIsBoundLoginState_LegacyStatesNotBound(t *testing.T) {
	// A real 32-byte base64url state that happens to start with 'b', which is
	// exactly the ~1.5% of legacy states a bare "b" sentinel would have eaten.
	legacyStartingWithB := "b" + strings.Repeat("A", 42)
	if len(legacyStartingWithB) != 43 {
		t.Fatalf("fixture is not a 43-char base64url state")
	}
	cases := map[string]string{
		"legacy 43-char base64url state starting with 'b'": legacyStartingWithB,
		"legacy 43-char base64url state":                   strings.Repeat("A", 43),
		"hand-written legacy row":                          "legacy-unbound-state",
		"empty":                                            "",
		"prefix only":                                      BoundStatePrefix,
		"prefix + one char":                                BoundStatePrefix + "A",
		"bare b":                                           "b",
		"right length, wrong alphabet":                     BoundStatePrefix + strings.Repeat("A", 42) + "!",
		"too long":                                         BoundStatePrefix + strings.Repeat("A", 44),
	}
	for name, state := range cases {
		if IsBoundLoginState(state) {
			t.Fatalf("%s (%q) was classified as a bound state — its callback would be refused for a cookie nobody wrote", name, state)
		}
		// And every helper stays total on it. This is the remote-panic guard:
		// `state` is attacker-controlled on a public route, so a slice
		// expression that assumed a length would be a crash primitive.
		if got := LoginBindingCookieName(state); got != "" {
			t.Fatalf("LoginBindingCookieName(%q) = %q, want \"\"", state, got)
		}
		if VerifyLoginBinding(state, "anything") {
			t.Fatalf("VerifyLoginBinding accepted the non-bound state %q", state)
		}
		if c := LoginBindingCookie(secureOpts(), state, "secret", time.Minute); c != nil {
			t.Fatalf("LoginBindingCookie(%q) returned a cookie, want nil", state)
		}
		if c := ClearLoginBindingCookie(secureOpts(), state); c != nil {
			t.Fatalf("ClearLoginBindingCookie(%q) returned a cookie, want nil", state)
		}
	}
}

// --- cookie naming --------------------------------------------------------

// TestLoginBindingCookieName_StableAndPerState pins the property the multi-tab
// case depends on: two logins open in one browser must not clobber each other's
// cookie, and the callback (which knows only the state) must be able to name
// the right one.
func TestLoginBindingCookieName_StableAndPerState(t *testing.T) {
	_, a, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}
	_, b, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}

	if LoginBindingCookieName(a) != LoginBindingCookieName(a) {
		t.Fatalf("cookie name is not stable for one state")
	}
	if LoginBindingCookieName(a) == LoginBindingCookieName(b) {
		t.Fatalf("two flows share a cookie name — the second /authorize would clobber the first")
	}
	name := LoginBindingCookieName(a)
	if !strings.HasPrefix(name, "yauth_lb_") {
		t.Fatalf("cookie name %q is not namespaced", name)
	}
	// It has to survive a Set-Cookie round trip as a name.
	if strings.ContainsAny(name, " ;=,\t") {
		t.Fatalf("cookie name %q contains a character illegal in a cookie name", name)
	}
}

// --- cookie shape ---------------------------------------------------------

// TestLoginBindingCookie_SecureIsSameSiteNone is the mandatory header-level
// assertion. Go's cookiejar ignores SameSite entirely, so an integration test
// cannot tell a None cookie from a Lax one — but a real browser can, and a Lax
// binding cookie is not sent on an IdP's cross-site form_post POST, which would
// refuse every form_post login in production.
func TestLoginBindingCookie_SecureIsSameSiteNone(t *testing.T) {
	secret, state, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}
	c := LoginBindingCookie(secureOpts(), state, secret, 10*time.Minute)
	if c == nil {
		t.Fatalf("LoginBindingCookie returned nil for a well-formed state")
	}
	if c.SameSite != http.SameSiteNoneMode {
		t.Fatalf("SameSite = %v, want None — a Lax cookie never arrives on an IdP form_post", c.SameSite)
	}
	if !c.Secure {
		t.Fatalf("Secure = false; browsers reject SameSite=None without Secure outright")
	}
	if !c.HttpOnly {
		t.Fatalf("HttpOnly = false; script has no business reading the binding secret")
	}
	if c.Value != secret {
		t.Fatalf("cookie carries %q, want the minted secret", c.Value)
	}
	if c.MaxAge != 600 {
		t.Fatalf("MaxAge = %d, want the state TTL in seconds (600)", c.MaxAge)
	}
	// Path/Domain are inherited verbatim from the deployment's cookie options,
	// NOT derived from the handler's r.URL.Path: yauth is normally mounted under
	// StripPrefix("/api/auth"), so a handler-derived path would scope the cookie
	// to a path the browser never visits and every login would refuse.
	if c.Path != "/" || c.Domain != "auth.example.com" {
		t.Fatalf("cookie scope = %q/%q, want the host's own path/domain", c.Path, c.Domain)
	}
	raw := c.String()
	if !strings.Contains(raw, "SameSite=None") || !strings.Contains(raw, "Secure") {
		t.Fatalf("Set-Cookie header %q does not carry SameSite=None and Secure", raw)
	}
}

// TestLoginBindingCookie_InsecureFallsBackToLax states the honest limit: a
// plain-HTTP deployment cannot use SameSite=None at all (browsers reject it
// without Secure), which is precisely why "auto" does not enforce binding there.
func TestLoginBindingCookie_InsecureFallsBackToLax(t *testing.T) {
	secret, state, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}
	opts := secureOpts()
	opts.Secure = false
	c := LoginBindingCookie(opts, state, secret, time.Minute)
	if c == nil {
		t.Fatalf("LoginBindingCookie returned nil")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v on a non-Secure deployment, want Lax", c.SameSite)
	}
	if c.Secure {
		t.Fatalf("Secure = true on a plain-HTTP deployment")
	}
}

// TestClearLoginBindingCookie_MatchesTheSetCookie pins the delete: name, path,
// domain, secure and samesite must match or the browser treats it as a
// different cookie and the stale binding lingers for the whole TTL.
func TestClearLoginBindingCookie_MatchesTheSetCookie(t *testing.T) {
	secret, state, err := NewBoundLoginState()
	if err != nil {
		t.Fatalf("NewBoundLoginState: %v", err)
	}
	set := LoginBindingCookie(secureOpts(), state, secret, time.Minute)
	clr := ClearLoginBindingCookie(secureOpts(), state)
	if set == nil || clr == nil {
		t.Fatalf("nil cookie for a well-formed state")
	}
	if clr.MaxAge >= 0 {
		t.Fatalf("clear cookie MaxAge = %d, want < 0", clr.MaxAge)
	}
	if clr.Value != "" {
		t.Fatalf("clear cookie still carries a value")
	}
	if clr.Name != set.Name || clr.Path != set.Path || clr.Domain != set.Domain ||
		clr.Secure != set.Secure || clr.SameSite != set.SameSite {
		t.Fatalf("clear cookie does not match the set cookie: %+v vs %+v", clr, set)
	}
}

// --- mode resolution ------------------------------------------------------

// TestNormalizeLoginStateBinding pins that a typo is LOUD. Falling back to the
// default on an unknown value would turn "off" mistyped as "of" into an
// enforced binding on a deployment that cannot carry the cookie — i.e. every
// login refused, in production, silently.
func TestNormalizeLoginStateBinding(t *testing.T) {
	for in, want := range map[string]string{
		"":                        LoginStateBindingAuto,
		LoginStateBindingAuto:     LoginStateBindingAuto,
		LoginStateBindingRequired: LoginStateBindingRequired,
		LoginStateBindingOff:      LoginStateBindingOff,
	} {
		got, err := NormalizeLoginStateBinding(in)
		if err != nil {
			t.Fatalf("NormalizeLoginStateBinding(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("NormalizeLoginStateBinding(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"of", "on", "true", "AUTO", "Off"} {
		if _, err := NormalizeLoginStateBinding(bad); err == nil {
			t.Fatalf("NormalizeLoginStateBinding(%q) accepted an unknown mode", bad)
		}
	}
}

// TestBindLoginState_AutoKeysOnCookieSecure documents the fallback in one
// place: "auto" protects every TLS deployment and deliberately does NOT protect
// plain HTTP, where the cookie could not survive a form_post callback anyway.
func TestBindLoginState_AutoKeysOnCookieSecure(t *testing.T) {
	if !BindLoginState(LoginStateBindingAuto, true) {
		t.Fatalf("auto + cookie_secure=true must bind")
	}
	if BindLoginState(LoginStateBindingAuto, false) {
		t.Fatalf("auto + cookie_secure=false must NOT bind (SameSite=None needs Secure)")
	}
	if !BindLoginState(LoginStateBindingRequired, false) {
		t.Fatalf("required must bind regardless of cookie posture")
	}
	if BindLoginState(LoginStateBindingOff, true) {
		t.Fatalf("off must never bind")
	}
}
