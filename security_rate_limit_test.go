package yauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/plugins/magiclink"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// The rate-limit surface (yauth.YAuthConfig.RateLimit, rate_limit.* in
// yauth.yaml) was read by nothing: every plugin wrapped its routes with
// literal numbers, so tightening rate_limit.login to 3 still gave 10, and
// magic_link_send / unlock_request / mfa_verify — all advertised in the
// schema and in the defaults — had no limiter on their route at all.
//
// Each test below sets a rule and asserts the route honours it.

// ratedServer builds a server whose rate-limit config is cfgFn's, with every
// plugin that owns a configurable operation registered.
func ratedServer(t *testing.T, rl yauth.RateLimitConfig) (*httptest.Server, func()) {
	t.Helper()

	cfg := yauth.NewDefaultConfig()
	cfg.RateLimit = rl

	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: key})
	if err != nil {
		t.Fatalf("mfa: %v", err)
	}

	ya, err := yauth.New(memrepo.New(), cfg).
		WithJWTSecret([]byte("0123456789abcdef0123456789abcdef")).
		WithPlugin(emailpassword.New(emailpassword.Config{HIBPCheck: false, HIBPCheckSet: true})).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(magiclink.New(magiclink.Config{})).
		WithPlugin(lockout.New(lockout.Config{LinkBaseURL: "https://example.test/unlock"})).
		WithPlugin(mfaPlugin).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, srv.Close
}

// postN fires n POSTs at path and returns the status of each.
func postN(t *testing.T, srv *httptest.Server, path string, body any, n int) []int {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	codes := make([]int, 0, n)
	for range n {
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		res.Body.Close()
		codes = append(codes, res.StatusCode)
	}
	return codes
}

// assertLimitedAfter checks that the first max calls were allowed (anything
// that is not 429) and that everything after was refused.
func assertLimitedAfter(t *testing.T, path string, codes []int, max int) {
	t.Helper()
	for i, code := range codes {
		blocked := code == http.StatusTooManyRequests
		if i < max && blocked {
			t.Fatalf("%s: request %d/%d was 429 but the configured max is %d (codes=%v)", path, i+1, len(codes), max, codes)
		}
		if i >= max && !blocked {
			t.Fatalf("%s: request %d/%d returned %d, expected 429 — the configured max of %d was not applied (codes=%v)", path, i+1, len(codes), code, max, codes)
		}
	}
}

func rule(max int, window time.Duration) yauth.RateLimitRule {
	return yauth.RateLimitRule{Max: yauth.RateLimitMax(max), Window: window}
}

// A tightened rate_limit.login must actually bind. Before the fix the
// email-password plugin passed a hardcoded 10 and this saw 401s all the way.
func TestRateLimit_LoginHonoursConfiguredMax(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{Login: rule(3, time.Minute)})
	defer done()

	codes := postN(t, srv, "/api/auth/login", map[string]string{
		"email": "nobody@example.com", "password": "wrong-password-here",
	}, 5)
	assertLimitedAfter(t, "/login", codes, 3)
}

// `max: 0` is documented as "no limit". It could not previously be expressed
// at all — a zero int was indistinguishable from an omitted key — so this
// used to hit the built-in 10 and 429 on the eleventh call.
func TestRateLimit_LoginMaxZeroMeansNoLimit(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{Login: rule(0, time.Minute)})
	defer done()

	codes := postN(t, srv, "/api/auth/login", map[string]string{
		"email": "nobody@example.com", "password": "wrong-password-here",
	}, 15)
	for i, code := range codes {
		if code == http.StatusTooManyRequests {
			t.Fatalf("request %d was 429 under max=0, which the schema documents as no limit (codes=%v)", i+1, codes)
		}
	}
}

// An unset rule keeps the plugin's built-in default — the guarantee that a
// deployment configuring none of this sees no change.
func TestRateLimit_UnsetRuleKeepsPluginDefault(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{})
	defer done()

	codes := postN(t, srv, "/api/auth/login", map[string]string{
		"email": "nobody@example.com", "password": "wrong-password-here",
	}, 12)
	assertLimitedAfter(t, "/login", codes, 10)
}

// POST /token verifies email+password exactly as /login does, and ran with
// no per-IP throttle whatsoever. Before the fix every one of these was a 401.
func TestRateLimit_BearerTokenIsThrottled(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{Login: rule(3, time.Minute)})
	defer done()

	codes := postN(t, srv, "/api/auth/token", map[string]string{
		"email": "nobody@example.com", "password": "wrong-password-here",
	}, 5)
	assertLimitedAfter(t, "/token", codes, 3)
}

// /login and /token are one credential check, so they share one budget:
// alternating between them must not double an attacker's guesses.
func TestRateLimit_LoginAndTokenShareOneBucket(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{Login: rule(4, time.Minute)})
	defer done()

	body := map[string]string{"email": "nobody@example.com", "password": "wrong-password-here"}
	loginCodes := postN(t, srv, "/api/auth/login", body, 4)
	for i, c := range loginCodes {
		if c == http.StatusTooManyRequests {
			t.Fatalf("/login request %d exhausted the bucket early (codes=%v)", i+1, loginCodes)
		}
	}
	tokenCodes := postN(t, srv, "/api/auth/token", body, 1)
	if tokenCodes[0] != http.StatusTooManyRequests {
		t.Fatalf("/token returned %d after /login spent the whole login budget; want 429", tokenCodes[0])
	}
}

// rate_limit.magic_link_send was advertised and enforced nowhere. The route
// sends mail to any address the caller names, so it is an unmetered
// amplifier. Before the fix all five of these returned 200.
func TestRateLimit_MagicLinkSendIsThrottled(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{MagicLinkSend: rule(2, time.Minute)})
	defer done()

	codes := postN(t, srv, "/api/auth/magic-link/send", map[string]string{
		"email": "victim@example.com",
	}, 4)
	assertLimitedAfter(t, "/magic-link/send", codes, 2)
}

// Same shape for rate_limit.unlock_request: an unauthenticated mail-send with
// no limiter on it before the fix.
func TestRateLimit_UnlockRequestIsThrottled(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{UnlockRequest: rule(2, time.Minute)})
	defer done()

	codes := postN(t, srv, "/api/auth/account/request-unlock", map[string]string{
		"email": "victim@example.com",
	}, 4)
	assertLimitedAfter(t, "/account/request-unlock", codes, 2)
}

// rate_limit.mfa_verify likewise. A six-digit code is guessable at volume if
// nothing meters how many challenges an attacker may open.
func TestRateLimit_MFAVerifyIsThrottled(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{MFAVerify: rule(2, time.Minute)})
	defer done()

	codes := postN(t, srv, "/api/auth/mfa/verify", map[string]string{
		"pending_session_id": "00000000-0000-0000-0000-000000000000",
		"code":               "123456",
	}, 4)
	assertLimitedAfter(t, "/mfa/verify", codes, 2)
}

// The bearer /token/mfa route completes the same challenge as /mfa/verify and
// shares its bucket.
func TestRateLimit_TokenMFASharesVerifyBucket(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{MFAVerify: rule(2, time.Minute)})
	defer done()

	codes := postN(t, srv, "/api/auth/token/mfa", map[string]string{
		"pending_session_id": "00000000-0000-0000-0000-000000000000",
		"code":               "123456",
	}, 3)
	assertLimitedAfter(t, "/token/mfa", codes, 2)
}

// A limiter must bucket per CLIENT, and behind a proxy the client is the
// X-Forwarded-For address, not the proxy's. Keying on RemoteAddr made one
// shared bucket for the whole internet: one noisy client could lock everyone
// else out of /login, and an attacker's own budget was whatever was left.
func TestRateLimit_BucketsPerClientBehindAProxy(t *testing.T) {
	srv, done := ratedServer(t, yauth.RateLimitConfig{Login: rule(2, time.Minute)})
	defer done()

	post := func(clientIP string) int {
		buf, _ := json.Marshal(map[string]string{
			"email": "nobody@example.com", "password": "wrong-password-here",
		})
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/login", bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		// httptest's peer is 127.0.0.1, which the default policy trusts,
		// so this stands in for a proxied client.
		req.Header.Set("X-Forwarded-For", clientIP)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		res.Body.Close()
		return res.StatusCode
	}

	// Client A spends its whole budget.
	for i := range 2 {
		if code := post("203.0.113.10"); code == http.StatusTooManyRequests {
			t.Fatalf("client A request %d was 429 within its budget", i+1)
		}
	}
	if code := post("203.0.113.10"); code != http.StatusTooManyRequests {
		t.Fatalf("client A over budget returned %d; want 429", code)
	}
	// Client B is a different client and still has its own.
	if code := post("203.0.113.11"); code == http.StatusTooManyRequests {
		t.Fatalf("client B was blocked by client A's traffic — the limiter is not per-client")
	}
}

// The config plumbing itself: a host that resolves the operator's rule, and
// the fallback for a host that cannot.
func TestRateLimitFor_ResolvesConfigOverPluginDefaults(t *testing.T) {
	cases := []struct {
		name   string
		rule   yauth.RateLimitRule
		defMax int
		want   int
	}{
		{"unset keeps the plugin default", yauth.RateLimitRule{}, 10, 10},
		{"configured wins", rule(3, time.Minute), 10, 3},
		{"zero disables", rule(0, time.Minute), 10, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := tc.rule.Resolve(tc.defMax, time.Minute)
			if got != tc.want {
				t.Fatalf("Resolve max = %d; want %d", got, tc.want)
			}
		})
	}

	// The op → rule lookup must cover every advertised operation; a missing
	// arm would silently fall back to the plugin default forever.
	cfg := yauth.RateLimitConfig{
		Login:          rule(1, time.Minute),
		Register:       rule(2, time.Minute),
		ForgotPassword: rule(3, time.Minute),
		MagicLinkSend:  rule(4, time.Minute),
		UnlockRequest:  rule(5, time.Minute),
		MFAVerify:      rule(6, time.Minute),
	}
	for op, want := range map[plugin.RateLimitOp]int{
		plugin.RateLimitLogin:          1,
		plugin.RateLimitRegister:       2,
		plugin.RateLimitForgotPassword: 3,
		plugin.RateLimitMagicLinkSend:  4,
		plugin.RateLimitUnlockRequest:  5,
		plugin.RateLimitMFAVerify:      6,
	} {
		r, ok := cfg.Rule(op)
		if !ok {
			t.Fatalf("RateLimitConfig.Rule(%q) is not covered", op)
		}
		if r.Max == nil || *r.Max != want {
			t.Fatalf("Rule(%q).Max = %v; want %d", op, r.Max, want)
		}
	}
}

// POST /login can answer 429 for TWO unrelated reasons: the per-IP fixed-window
// limiter ("you are going too fast") and the lockout plugin's
// events.Block(429, "Account locked") ("this account is locked"). The lockout
// one has always rendered through huma.NewError as RFC 9457 problem+json; the
// limiter's used to be text/plain "Too Many Requests". One route, one status
// code, two incompatible bodies — a client could not even special-case 429,
// because the body shape depended on which of the two tripped.
//
// Both are problem+json now. This drives the real, fully wired stack (not the
// middleware in isolation) and asserts every 429 it can produce parses as the
// same {title,status,detail} envelope with the documented content type.
func TestRateLimit_BothLoginRefusalsAreProblemJSON(t *testing.T) {
	type problem struct {
		Title      string `json:"title"`
		Status     int    `json:"status"`
		Detail     string `json:"detail"`
		RetryAfter int    `json:"retry_after"`
	}

	// Decode a 429 body as problem+json, failing loudly on the text/plain
	// this test exists to prevent. json.Unmarshal on "Too Many Requests\n"
	// is precisely the error real clients surfaced to their users.
	decode := func(t *testing.T, what string, res *http.Response) problem {
		t.Helper()
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatalf("%s: read body: %v", what, err)
		}
		if res.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("%s: want 429, got %d (%s)", what, res.StatusCode, body)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("%s: Content-Type: want application/problem+json, got %q (body=%s)", what, ct, body)
		}
		var p problem
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatalf("%s: 429 body is not JSON (%v): %s", what, err, body)
		}
		if p.Status != http.StatusTooManyRequests {
			t.Errorf("%s: problem.status = %d, want 429", what, p.Status)
		}
		if p.Title == "" || p.Detail == "" {
			t.Errorf("%s: problem must carry title and detail, got %+v", what, p)
		}
		return p
	}

	// (a) the per-IP limiter: spend a max=2 login budget, read the refusal.
	t.Run("rate limiter", func(t *testing.T) {
		srv, done := ratedServer(t, yauth.RateLimitConfig{Login: rule(2, time.Minute)})
		defer done()

		var res *http.Response
		for range 3 {
			res = postLogin(t, srv, "nobody@example.com", "wrong-password-here")
			if res.StatusCode == http.StatusTooManyRequests {
				break
			}
			res.Body.Close()
			res = nil
		}
		if res == nil {
			t.Fatal("the login limiter never refused within max+1 requests")
		}
		p := decode(t, "limiter", res)
		if p.Detail != "rate limit exceeded" {
			t.Errorf("limiter detail = %q, want %q", p.Detail, "rate limit exceeded")
		}
		if p.RetryAfter < 1 {
			t.Errorf("limiter retry_after = %d, want >= 1 (browsers on another origin cannot read the header)", p.RetryAfter)
		}
		if h := res.Header.Get("Retry-After"); h != strconv.Itoa(p.RetryAfter) {
			t.Errorf("Retry-After header %q disagrees with body retry_after %d", h, p.RetryAfter)
		}
		if h := res.Header.Get("X-RateLimit-Remaining"); h != "0" {
			t.Errorf("X-RateLimit-Remaining: want 0, got %q", h)
		}
	})

	// (b) lockout, on the same route, with the limiter disabled so only the
	// lockout path can produce the 429. It already rendered as problem+json;
	// this pins that the limiter now MATCHES it rather than the reverse.
	t.Run("account lockout", func(t *testing.T) {
		srv, done := ratedServer(t, yauth.RateLimitConfig{Login: rule(0, time.Minute)})
		defer done()

		const email = "locked-out-probe@example.com"
		const pw = "correct horse battery staple 9!Z"
		reg := postJSON2(t, srv, "/api/auth/register", map[string]string{"email": email, "password": pw})
		if reg.StatusCode >= 300 {
			body, _ := io.ReadAll(reg.Body)
			reg.Body.Close()
			t.Fatalf("register: got %d (%s)", reg.StatusCode, body)
		}
		reg.Body.Close()

		// lockout.Config.MaxAttempts defaults to 5.
		var res *http.Response
		for i := range 8 {
			res = postLogin(t, srv, email, "WRONG-bad-password-1!Z")
			if res.StatusCode == http.StatusTooManyRequests {
				break
			}
			res.Body.Close()
			res = nil
			if i == 7 {
				t.Fatal("lockout never tripped in 8 failed logins")
			}
		}
		if res == nil {
			t.Fatal("lockout never tripped")
		}
		decode(t, "lockout", res)
	})
}

// postLogin fires one login and returns the live response for the caller to
// inspect (postN discards bodies).
func postLogin(t *testing.T, srv *httptest.Server, email, password string) *http.Response {
	t.Helper()
	return postJSON2(t, srv, "/api/auth/login", map[string]string{"email": email, "password": password})
}

func postJSON2(t *testing.T, srv *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}
