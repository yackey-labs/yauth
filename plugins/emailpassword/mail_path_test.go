package emailpassword_test

// The two public routes that put mail in somebody's inbox — /forgot-password
// and /resend-verification — are metered per CLIENT IP and send the message
// ON the request goroutine.
//
// Per-IP metering. middleware.RateLimit keys its bucket name+":"+clientIP
// (middleware/ratelimit.go:41). The email in the request body — the thing that
// decides who receives the mail — never enters the key. So the budget belongs
// to the sender, and the recipient's inbox absorbs the sum of every sender's:
// 5/min from each of 256 hosts in a /24 is over a thousand DKIM-signed
// messages a minute into one mailbox, from the operator's own domain. There is
// a second-order effect specific to /forgot-password: it calls
// DeleteUnusedPasswordResetsForUser on every request (handlers.go:1323), so the
// flood also retires the link the victim is trying to click, over and over.
//
// Blocking send. registerForgotPassword calls Mailer.SendPasswordReset inline
// (handlers.go:1342) and only then returns the neutral 200. An unknown address
// returns at :1313 without touching the mailer. The bodies are byte-identical,
// but one comes back in a millisecond and the other after a full SMTP
// conversation, which is the account-existence answer the neutral body exists
// to withhold. /register's duplicate-address branch already backgrounds its
// send for precisely this reason (handlers.go:275-279); the other call sites
// did not follow. The test below does not measure a ratio — it holds the
// mailer open and asks whether the response can arrive while a send is still
// in flight, which is the same property stated without a stopwatch.
//
// Both refusals are paired with positive controls: one ordinary request must
// still produce exactly one mail, and the link it carries must still reset the
// password.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// recordingMailer counts what actually left the building, and can be told to
// block inside a send so a test can look at the request while it is happening.
type recordingMailer struct {
	mu       sync.Mutex
	resets   []string
	verifies []string

	// gate, when non-nil, blocks every SendPasswordReset until it is closed.
	gate    chan struct{}
	entered chan struct{} // closed by the first blocked send
	once    sync.Once
}

func (m *recordingMailer) SendPasswordReset(_ context.Context, email, link string) error {
	m.mu.Lock()
	m.resets = append(m.resets, link)
	m.mu.Unlock()
	if m.gate != nil {
		m.once.Do(func() { close(m.entered) })
		select {
		case <-m.gate:
		case <-time.After(10 * time.Second): // never wedge the suite
		}
	}
	return nil
}

func (m *recordingMailer) SendVerification(_ context.Context, email, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifies = append(m.verifies, email)
	return nil
}

func (m *recordingMailer) SendAccountExists(context.Context, string) error { return nil }

func (m *recordingMailer) resetCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.resets)
}

func (m *recordingMailer) verifyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.verifies)
}

func (m *recordingMailer) lastResetLink(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.resets) == 0 {
		t.Fatalf("no reset mail was sent")
	}
	return m.resets[len(m.resets)-1]
}

// newProxiedMailServer wires email-password behind a trusted-proxy policy, so
// X-Forwarded-For decides the client IP the limiter keys on — the shape of
// every deployment that sits behind a load balancer.
func newProxiedMailServer(t *testing.T, m *recordingMailer) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.TrustedProxies = []string{"private"} // httptest dials from loopback

	ya, err := yauth.New(r, cfg).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength:        8,
			HIBPCheck:                false,
			HIBPCheckSet:             true,
			Mailer:                   m,
			PasswordResetLinkBaseURL: "https://example.test/reset",
			VerificationLinkBaseURL:  "https://example.test/verify",
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// postFrom issues a JSON POST that appears to originate from clientIP.
func postFrom(t *testing.T, cl *http.Client, srv *httptest.Server, path, clientIP, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", clientIP)
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("POST %s from %s: %v", path, clientIP, err)
	}
	return res
}

var floodIPs = []string{
	"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4",
	"198.51.100.5", "198.51.100.6", "198.51.100.7", "198.51.100.8",
	"198.51.100.9", "198.51.100.10", "198.51.100.11", "198.51.100.12",
}

// maxPerRecipient is the ceiling a per-recipient bucket has to impose. The
// exact number is a policy choice; anything that lets twelve source IPs
// deliver twelve mails is not a bucket at all.
const maxPerRecipient = 5

// TestForgotPassword_ThrottledPerRecipientAcrossClientIPs is the mail bomb.
func TestForgotPassword_ThrottledPerRecipientAcrossClientIPs(t *testing.T) {
	m := &recordingMailer{}
	srv, _ := newProxiedMailServer(t, m)
	const victim = "victim@example.com"
	registerUser(t, srv, victim, "old-password-123")

	cl := &http.Client{Timeout: 5 * time.Second}
	bodies := make([]string, 0, len(floodIPs))
	for _, ip := range floodIPs {
		res := postFrom(t, cl, srv, "/api/auth/forgot-password", ip, `{"email":"`+victim+`"}`)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("forgot-password from %s: got %d (%s) — a throttled caller must still get the neutral 200, "+
				"never a 429, which hands back the enumeration answer the neutral body hides",
				ip, res.StatusCode, drain(res))
		}
		bodies = append(bodies, drain(res))
	}
	for i, b := range bodies {
		if b != bodies[0] {
			t.Errorf("body from %s differs from the first (%q vs %q) — the throttle is observable", floodIPs[i], b, bodies[0])
		}
	}

	// Sends are dispatched off the request goroutine now, so let them land
	// before counting — otherwise this could pass by under-counting rather
	// than by throttling. The lower bound is there for the same reason: a
	// "fix" that mails nothing at all must not satisfy the ceiling.
	settle(m.resetCount)
	if m.resetCount() < 1 {
		t.Fatalf("no password-reset mail was delivered at all — the throttle cannot be satisfied by sending nothing")
	}
	if got := m.resetCount(); got > maxPerRecipient {
		t.Fatalf("%d password-reset emails were delivered to %s from %d distinct client IPs — "+
			"the rate-limit key is name+client_ip only, so one inbox absorbs every sender's budget "+
			"(and each request also retires the link the victim is trying to click)",
			got, victim, len(floodIPs))
	}
}

// TestResendVerification_ThrottledPerRecipientAcrossClientIPs is the same
// amplifier on the other mail route.
func TestResendVerification_ThrottledPerRecipientAcrossClientIPs(t *testing.T) {
	m := &recordingMailer{}
	srv, _ := newProxiedMailServer(t, m)
	const victim = "unverified@example.com"
	registerUser(t, srv, victim, "old-password-123")
	before := m.verifyCount() // registration itself sends one

	cl := &http.Client{Timeout: 5 * time.Second}
	for _, ip := range floodIPs {
		res := postFrom(t, cl, srv, "/api/auth/resend-verification", ip, `{"email":"`+victim+`"}`)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("resend-verification from %s: got %d (%s)", ip, res.StatusCode, drain(res))
		}
		drain(res)
	}

	settle(m.verifyCount)
	if m.verifyCount()-before < 1 {
		t.Fatalf("no verification mail was delivered at all — the throttle cannot be satisfied by sending nothing")
	}
	if got := m.verifyCount() - before; got > maxPerRecipient {
		t.Fatalf("%d verification emails were delivered to %s from %d distinct client IPs", got, victim, len(floodIPs))
	}
}

// POSITIVE CONTROL for both buckets: one user asking once must get exactly one
// mail, and that mail must still reset the password. A per-recipient throttle
// is itself a denial-of-recovery lever, so the ordinary path has to be intact.
func TestForgotPassword_SingleRequestStillMailsAWorkingLink(t *testing.T) {
	m := &recordingMailer{}
	srv, r := newProxiedMailServer(t, m)
	const email, pw = "ordinary@example.com", "old-password-123"
	registerUser(t, srv, email, pw)

	cl := &http.Client{Timeout: 5 * time.Second}
	res := postFrom(t, cl, srv, "/api/auth/forgot-password", "198.51.100.99", `{"email":"`+email+`"}`)
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password: %d (%s)", res.StatusCode, body)
	}
	waitFor(t, func() bool { return m.resetCount() == 1 }, "exactly one reset mail")

	link := m.lastResetLink(t)
	tok := link[strings.Index(link, "token=")+len("token="):]
	res = postJSON(t, srv.URL+"/api/auth/reset-password", map[string]any{
		"token": tok, "password": "chosen-by-the-owner-1",
	})
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("the mailed reset link stopped working: %d (%s)", res.StatusCode, body)
	}
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("lookup user: %v", err)
	}
}

// TestForgotPassword_DoesNotBlockOnTheMailer is the existence oracle, stated
// without a stopwatch: the mailer is held open inside SendPasswordReset, and
// the HTTP response for a KNOWN address must still come back. Today it cannot
// — the send is on the request goroutine, so the response waits for the SMTP
// conversation while an unknown address returns immediately.
func TestForgotPassword_DoesNotBlockOnTheMailer(t *testing.T) {
	m := &recordingMailer{gate: make(chan struct{}), entered: make(chan struct{})}
	srv, _ := newProxiedMailServer(t, m)
	const email = "slow-relay@example.com"
	registerUser(t, srv, email, "old-password-123")

	defer close(m.gate)

	cl := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/forgot-password",
		strings.NewReader(`{"email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "198.51.100.50")

	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("/forgot-password for a KNOWN address did not answer while the mailer was still sending: %v — "+
			"the response time IS the account-existence answer the neutral body is meant to withhold", err)
	}
	if body := drain(res); res.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password: %d (%s)", res.StatusCode, body)
	}

	// And the mail must genuinely be in flight, not skipped: the send has to
	// have STARTED before the response came back.
	select {
	case <-m.entered:
	case <-time.After(2 * time.Second):
		t.Fatalf("no send was ever attempted — the handler returned 200 without mailing anything")
	}
}

// settle waits until count stops moving, which is what an UPPER-bound
// assertion needs: there is no condition to poll for, only quiescence.
func settle(count func() int) {
	deadline := time.Now().Add(2 * time.Second)
	prev := -1
	for time.Now().Before(deadline) {
		n := count()
		if n == prev {
			return
		}
		prev = n
		time.Sleep(50 * time.Millisecond)
	}
}

// waitFor polls cond for up to a second. Sends move off the request goroutine
// under the fix, so the assertion has to tolerate a send that completes just
// after the response.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
