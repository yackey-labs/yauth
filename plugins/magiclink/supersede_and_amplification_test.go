package magiclink_test

// Two defects on POST /magic-link/send, both of which end with mail nobody
// asked for or a credential nobody retired.
//
// (1) A new magic link retires none of its predecessors. registerSend
// (plugins/magiclink/handlers.go:165-180) goes straight from generateToken to
// repo.CreateMagicLink. repo.DeleteUnusedMagicLinksForEmail exists
// (repo/repo.go:136) and magiclink never calls it — emailpassword calls it from
// invalidateRecoveryTokens and calls the reset-side equivalent from
// registerForgotPassword (handlers.go:1323) for exactly this reason. So every
// /send adds a live sign-in credential for the address and invalidates nothing:
// a link captured once (shoulder-surfed, forwarded, sitting in a shared inbox,
// leaked in a mail-scanner log) keeps working no matter how many fresh ones the
// real user requests. A magic link IS the session, so this is strictly worse
// than the reset case emailpassword already handles.
//
// (2) The route is metered per CLIENT IP only. middleware.RateLimit keys the
// bucket name+":"+clientIP (middleware/ratelimit.go:41); the request body's
// email — the thing that decides who receives the mail — is nowhere in the key.
// One address per source IP, 5/min each, and the recipient's inbox takes the
// sum. With SignupEnabled the address does not even have to exist locally, so
// the target can be an arbitrary third party and every message is DKIM-signed
// by the operator's domain.
//
// Both refusals are paired with positive controls: the newest link must still
// sign in, and one ordinary user requesting one link must still get it.

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/magiclink"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// at returns the i-th recorded send. captureMailer is declared in
// magiclink_test.go; this is the same test package.
func (m *captureMailer) at(i int) (string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i >= len(m.calls) {
		return "", ""
	}
	return m.calls[i].Email, m.calls[i].Link
}

// TestSend_RetiresPriorUnusedLinks: asking for a fresh link must leave exactly
// one live link for that address — the one the user is looking at.
func TestSend_RetiresPriorUnusedLinks(t *testing.T) {
	srv, mailer, stop := newServer(t, magiclink.Config{SignupEnabled: true})
	defer stop()

	const email = "victim@example.com"
	c := &http.Client{}

	// The link that leaks.
	res := postJSON(t, c, srv.URL+"/api/auth/magic-link/send", map[string]string{"email": email})
	res.Body.Close() //nolint:errcheck
	mailer.waitForMails(t, 1)
	_, firstLink := mailer.at(0)
	first := tokenFromLink(firstLink)
	if first == "" {
		t.Fatalf("no token in first link %q", firstLink)
	}

	// The user asks for another one.
	res = postJSON(t, c, srv.URL+"/api/auth/magic-link/send", map[string]string{"email": email})
	res.Body.Close() //nolint:errcheck
	mailer.waitForMails(t, 2)
	_, secondLink := mailer.at(1)
	second := tokenFromLink(secondLink)
	if second == "" || second == first {
		t.Fatalf("second send did not mint a distinct token (first=%q second=%q)", first, second)
	}

	// The stale one must be dead.
	jar, _ := cookiejar.New(nil)
	attacker := &http.Client{Jar: jar}
	res = postJSON(t, attacker, srv.URL+"/api/auth/magic-link/verify", map[string]string{"token": first})
	body := drain(res)
	if res.StatusCode == http.StatusOK {
		t.Errorf("a superseded magic link still signed in (200: %s) — a link captured once stays a live credential "+
			"however many fresh ones the user requests", body)
	}
	u, _ := url.Parse(srv.URL)
	if cs := jar.Cookies(u); len(cs) > 0 {
		t.Errorf("the superseded link set a session cookie: %v", cs)
	}

	// POSITIVE CONTROL: the link the user actually has must still work.
	jar2, _ := cookiejar.New(nil)
	owner := &http.Client{Jar: jar2}
	res = postJSON(t, owner, srv.URL+"/api/auth/magic-link/verify", map[string]string{"token": second})
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("the NEWEST magic link stopped working: %d (%s)", res.StatusCode, body)
	}
	if cs := jar2.Cookies(u); len(cs) == 0 {
		t.Fatalf("the newest link did not establish a session")
	}
}

// newProxiedServer wires magic-link behind a trusted-proxy policy, so an
// X-Forwarded-For header decides the client IP the rate limiter keys on —
// the deployment shape every hosted install has.
func newProxiedServer(t *testing.T) (*httptest.Server, *captureMailer) {
	t.Helper()
	mailer := &captureMailer{}
	cfg := yauth.NewDefaultConfig()
	cfg.TrustedProxies = []string{"private"} // httptest dials from loopback

	ya, err := yauth.New(memrepo.New(), cfg).
		WithPlugin(magiclink.New(magiclink.Config{
			SignupEnabled: true,
			Mailer:        mailer,
			LinkBaseURL:   "https://example.test/magic",
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, mailer
}

// sendFrom posts /magic-link/send as if it arrived from clientIP.
func sendFrom(t *testing.T, srv *httptest.Server, clientIP, email string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/magic-link/send",
		strings.NewReader(`{"email":"`+email+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", clientIP)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send from %s: %v", clientIP, err)
	}
	return res
}

// TestSend_ThrottledPerRecipientAcrossClientIPs: the budget that matters is the
// recipient's, not the sender's. A distributed caller — trivially, one host per
// address in a /24 — currently multiplies the per-IP allowance straight into
// one mailbox.
func TestSend_ThrottledPerRecipientAcrossClientIPs(t *testing.T) {
	srv, mailer := newProxiedServer(t)
	const victim = "target@third-party.example"

	// Twelve distinct source IPs, each well within its own 5/min per-IP
	// bucket, all aimed at one inbox.
	ips := []string{
		"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4",
		"198.51.100.5", "198.51.100.6", "198.51.100.7", "198.51.100.8",
		"198.51.100.9", "198.51.100.10", "198.51.100.11", "198.51.100.12",
	}
	bodies := make([]string, 0, len(ips))
	for _, ip := range ips {
		res := sendFrom(t, srv, ip, victim)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("send from %s: got %d (%s) — a throttled caller must still get the neutral 200, "+
				"never a 429, which would hand back the enumeration answer the neutral body exists to hide",
				ip, res.StatusCode, drain(res))
		}
		bodies = append(bodies, drain(res))
	}
	for i, b := range bodies {
		if b != bodies[0] {
			t.Errorf("response body from %s differs from the first (%q vs %q) — the throttle is observable",
				ips[i], b, bodies[0])
		}
	}

	// The recipient bucket: a handful an hour, not one per source address.
	// Sends are dispatched off the request goroutine, so let them land before
	// counting — otherwise this passes by under-counting rather than by
	// throttling. The lower bound is there for the same reason: a "fix" that
	// mails nothing at all must not satisfy the ceiling.
	const maxPerRecipient = 5
	mailer.settle()
	if mailer.count() == 0 {
		t.Fatalf("no magic-link mail was delivered at all — the throttle cannot be satisfied by sending nothing")
	}
	if got := mailer.count(); got > maxPerRecipient {
		t.Fatalf("%d magic-link emails were delivered to %s from %d distinct client IPs — "+
			"the rate-limit key is name+client_ip only (middleware/ratelimit.go:41), so the recipient's inbox "+
			"absorbs the sum of every attacker's per-IP budget", got, victim, len(ips))
	}
}

// POSITIVE CONTROL for the recipient bucket: one person asking for one link
// must get it. A per-recipient throttle is itself a denial-of-recovery lever,
// so the ordinary case has to stay untouched.
func TestSend_SingleRequestStillDelivers(t *testing.T) {
	srv, mailer := newProxiedServer(t)
	res := sendFrom(t, srv, "198.51.100.99", "ordinary@example.com")
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("send: %d (%s)", res.StatusCode, body)
	}
	mailer.waitForMails(t, 1)
	mailer.settle()
	if mailer.count() != 1 {
		t.Fatalf("a single legitimate /magic-link/send delivered %d mails, want 1", mailer.count())
	}
}
