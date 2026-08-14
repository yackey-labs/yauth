package webhooks_test

// Why this file exists.
//
// The webhooks plugin registers an events.Handler with the host
// (plugin.go Routes → host.RegisterEventHandler(newEventHandler(...))).
// YAuth.Emit → YAuth.dispatchEvent runs every registered handler INLINE,
// on the goroutine serving the HTTP request — there is no queue, no
// goroutine hand-off, and no context deadline between the login handler
// and the webhook code. plugins/emailpassword/handlers.go calls
// host.Emit twice per login (login.attempt before the password compare,
// login.succeeded after it), so a webhook subscribed to "*" turns each
// login into two calls to eventHandler.Handle → Dispatcher.Enqueue.
//
// Dispatcher.Enqueue's own doc comment says "Callers should treat
// enqueue failures as best-effort", but the body does a BARE channel
// send:
//
//	d.mu.RLock()
//	defer d.mu.RUnlock()
//	if d.closed { ... }
//	d.jobs <- job
//
// with no default case. d.jobs is buffered at workers*8 and each worker
// holds a job for the whole DeliveryTimeout. So once a registered
// receiver stops answering, the workers park in http.Client.Do, the
// buffer fills, and the NEXT Enqueue blocks forever — inside Emit,
// inside the login handler, on the request goroutine. Authentication
// stops for the entire deployment because one operator-registered
// webhook endpoint got slow. No attacker is required; an attacker who
// can register (or merely DoS) one receiver gets a full auth outage.
//
// The same bare send is what starves Shutdown: blocked senders hold
// d.mu.RLock() while Shutdown wants d.mu.Lock().
//
// Bundled here because it is the same two files: paginationFromQuery
// (handlers.go) accepts any positive int for ?page=, and both list
// handlers compute `start := (page - 1) * perPage` with only an
// `if start > len(...)` guard. A large ?page= overflows int to a
// negative start and the slice expression panics, killing the
// connection on an admin route.
//
// Every refusal assertion below is paired with a positive control so a
// future "fix" cannot pass by simply breaking webhook delivery or the
// pagination feature outright.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/webhooks"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- helpers -------------------------------------------------------------

// blockingSink is an httptest server whose handler parks until release
// is closed. It models the real-world failure the spec describes: a
// registered receiver that accepted the TCP connection and then stopped
// answering.
type blockingSink struct {
	srv     *httptest.Server
	release chan struct{}

	mu   sync.Mutex
	hits int
}

func newBlockingSink() *blockingSink {
	s := &blockingSink{release: make(chan struct{})}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		s.mu.Lock()
		s.hits++
		s.mu.Unlock()
		<-s.release
		w.WriteHeader(http.StatusOK)
	}))
	return s
}

func (s *blockingSink) Hits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// newWebhookServerWithYAuthConfig mirrors newWebhooksTestServerWithConfig
// from integration_test.go but also lets the test override the host
// YAuthConfig — needed so the pagination test can get an admin caller via
// AutoAdminFirstUser rather than reaching past the HTTP surface.
func newWebhookServerWithYAuthConfig(t *testing.T, whCfg webhooks.Config, customize func(*yauth.YAuthConfig)) (*httptest.Server, *yauth.YAuth) {
	t.Helper()
	r := memrepo.New()

	cfg := yauth.NewDefaultConfig()
	if customize != nil {
		customize(&cfg)
	}

	ya, err := yauth.New(r, cfg).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		WithPlugin(webhooks.New(whCfg)).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ya.Shutdown(ctx)
	})
	return srv, ya
}

func postJSON(t *testing.T, cl *http.Client, url string, body any) (*http.Response, error) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return cl.Do(req)
}

// --- 1. Enqueue must never park the caller -------------------------------

// TestEnqueue_DoesNotBlockWhenQueueIsFull drives Dispatcher.Enqueue
// directly with nothing draining the channel (Start is deliberately not
// called). The channel capacity is workers*8, so with workers=1 the ninth
// job has nowhere to go. Enqueue's contract — stated in its own doc
// comment — is that the caller treats it as best-effort; today the ninth
// call parks forever instead of returning.
func TestEnqueue_DoesNotBlockWhenQueueIsFull(t *testing.T) {
	const workers = 1
	const capacity = workers * 8

	d := webhooks.NewDispatcher(
		memrepo.New(),
		&http.Client{Timeout: time.Second},
		workers,
		webhooks.RetryConfig{MaxAttempts: 1, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
		nil,
	)
	// NOTE: no d.Start(), and no d.Shutdown() in cleanup. Nothing drains
	// d.jobs, and Shutdown would itself deadlock against a parked Enqueue
	// holding d.mu.RLock() — which is the second half of the same defect.

	hook := domain.Webhook{
		ID:     "wh-full-queue",
		URL:    "http://127.0.0.1:1/never-listening",
		Secret: "secret",
		Active: true,
		Events: json.RawMessage(`["*"]`),
	}

	returned := make(chan int, 1)
	go func() {
		accepted := 0
		for i := 0; i < capacity+1; i++ {
			job := webhooks.NewDeliveryJobForTest(hook, "login.succeeded", map[string]any{"n": i})
			if err := d.Enqueue(job); err == nil {
				accepted++
			}
		}
		returned <- accepted
	}()

	select {
	case accepted := <-returned:
		if accepted < capacity {
			t.Fatalf("positive control: expected at least %d jobs to be accepted into the buffer, got %d",
				capacity, accepted)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Dispatcher.Enqueue BLOCKED on job %d of %d with a full (capacity %d) queue: "+
			"the bare `d.jobs <- job` send parks the caller, which on the real path is the "+
			"HTTP request goroutine serving a login", capacity+1, capacity+1, capacity)
	}
}

// TestEnqueue_StillDeliversWhenDrained is the POSITIVE CONTROL for the
// test above: a started dispatcher with a receiver that answers must
// still deliver every enqueued job. A "fix" that drops everything on the
// floor fails here.
func TestEnqueue_StillDeliversWhenDrained(t *testing.T) {
	rcv := newReceiver(t)
	defer rcv.Close()

	r := memrepo.New()
	const secret = "drained-secret"
	whID := "wh-drained"
	now := time.Now().UTC()
	rawEvents, _ := json.Marshal([]string{"*"})
	if err := r.CreateWebhook(context.Background(), domain.NewWebhook{
		ID:        whID,
		URL:       rcv.srv.URL,
		Secret:    secret,
		Events:    rawEvents,
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	d := webhooks.NewDispatcher(r, &http.Client{Timeout: 2 * time.Second}, 2,
		webhooks.RetryConfig{MaxAttempts: 1, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond}, nil)
	d.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.Shutdown(ctx)
	})

	hook, err := r.GetWebhookByID(context.Background(), whID)
	if err != nil || hook == nil {
		t.Fatalf("get webhook: %v", err)
	}

	const n = 9
	for i := 0; i < n; i++ {
		if err := d.Enqueue(webhooks.NewDeliveryJobForTest(*hook, "login.succeeded", map[string]any{"n": i})); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	if !waitFor(t, 5*time.Second, func() bool { return len(rcv.Hits()) >= n }) {
		t.Fatalf("positive control: expected %d deliveries to reach the receiver, got %d", n, len(rcv.Hits()))
	}
}

// --- 2. A slow receiver must not stop authentication ---------------------

// TestLogin_NotBlockedBySlowWebhookReceiver is the end-to-end statement of
// the defect. One webhook subscribed to "*" points at a receiver that
// never answers. Each login emits two events (login.attempt +
// login.succeeded), so with WorkerCount=1 the 8-slot buffer plus the one
// in-flight job absorbs 9 deliveries; from the fifth login onwards the
// request goroutine parks inside Emit and POST /login never returns.
func TestLogin_NotBlockedBySlowWebhookReceiver(t *testing.T) {
	srv, ya := newWebhookServerWithYAuthConfig(t, webhooks.Config{
		// These receivers are httptest servers on 127.0.0.1. The delivery
		// client refuses private destinations by default now (see
		// auth/safehttp) — that guard is CORRECT and stays on; the test
		// harness is simply the in-cluster deployment shape, so it opts in
		// the same way such a deployment does.
		AllowPrivateDestinations: true,
		WorkerCount:              1,
		DeliveryTimeout:          30 * time.Second,
		MaxAttempts:              1,
		BackoffJitter:            -1,
	}, func(c *yauth.YAuthConfig) {
		// The default login limiter is 10/60s from one IP; the queue fills
		// well before that, but disable it so a 429 can never be mistaken
		// for the stall we are measuring.
		c.RateLimit.Login = yauth.RateLimitRule{Max: yauth.RateLimitMax(0)}
	})

	sink := newBlockingSink()
	defer sink.srv.Close()
	// Registered AFTER the sink so it runs BEFORE sink.srv.Close() and
	// before the harness's ya.Shutdown cleanup — otherwise the parked
	// senders holding d.mu.RLock() deadlock Shutdown's d.mu.Lock().
	defer close(sink.release)

	const email = "stalled@example.com"
	const password = "correct horse battery staple"

	// Register BEFORE the webhook exists so registration itself is not
	// competing for queue slots.
	plain := &http.Client{Timeout: 10 * time.Second}
	res, err := postJSON(t, plain, srv.URL+"/api/auth/register", map[string]string{
		"email": email, "password": password,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register: want 200, got %d", res.StatusCode)
	}

	seedWebhook(t, ya, sink.srv.URL, "slow-secret", []string{"*"})

	const logins = 8
	cl := &http.Client{Timeout: 3 * time.Second}
	for i := 0; i < logins; i++ {
		start := time.Now()
		res, err := postJSON(t, cl, srv.URL+"/api/auth/login", map[string]string{
			"email": email, "password": password,
		})
		if err != nil {
			t.Fatalf("login %d/%d STALLED after %v: %v\n"+
				"a single unresponsive webhook receiver filled the dispatcher's 8-slot queue and "+
				"Dispatcher.Enqueue's bare channel send parked the login request goroutine inside "+
				"YAuth.Emit — authentication is down for the whole deployment",
				i+1, logins, time.Since(start), err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("login %d/%d: want 200, got %d (%s)", i+1, logins, res.StatusCode, body)
		}
	}
}

// TestLogin_StillDeliversWebhooksWhenReceiverIsHealthy is the POSITIVE
// CONTROL for the test above: with a receiver that answers, the same
// number of logins must both succeed AND actually produce webhook
// deliveries. A "fix" that silences the webhook plugin fails here.
func TestLogin_StillDeliversWebhooksWhenReceiverIsHealthy(t *testing.T) {
	rcv := newReceiver(t)
	defer rcv.Close()

	srv, ya := newWebhookServerWithYAuthConfig(t, webhooks.Config{
		AllowPrivateDestinations: true, // 127.0.0.1 receiver — see the note above.
		WorkerCount:              1,
		DeliveryTimeout:          5 * time.Second,
		MaxAttempts:              1,
		BackoffJitter:            -1,
	}, func(c *yauth.YAuthConfig) {
		c.RateLimit.Login = yauth.RateLimitRule{Max: yauth.RateLimitMax(0)}
	})

	const email = "healthy@example.com"
	const password = "correct horse battery staple"

	plain := &http.Client{Timeout: 10 * time.Second}
	res, err := postJSON(t, plain, srv.URL+"/api/auth/register", map[string]string{
		"email": email, "password": password,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()

	whID := seedWebhook(t, ya, rcv.srv.URL, "healthy-secret", []string{"*"})

	const logins = 8
	cl := &http.Client{Timeout: 3 * time.Second}
	for i := 0; i < logins; i++ {
		res, err := postJSON(t, cl, srv.URL+"/api/auth/login", map[string]string{
			"email": email, "password": password,
		})
		if err != nil {
			t.Fatalf("positive control: login %d/%d failed: %v", i+1, logins, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("positive control: login %d/%d: want 200, got %d", i+1, logins, res.StatusCode)
		}
	}

	// Each login emits login.attempt + login.succeeded; the wildcard hook
	// subscribes to both. Assert real deliveries landed, not merely that
	// the logins returned.
	if !waitFor(t, 10*time.Second, func() bool { return len(rcv.Hits()) >= logins*2 }) {
		t.Fatalf("positive control: expected >=%d webhook deliveries for %d logins, got %d",
			logins*2, logins, len(rcv.Hits()))
	}
	if !waitFor(t, 5*time.Second, func() bool {
		rows, _ := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 100)
		return len(rows) >= logins*2
	}) {
		rows, _ := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 100)
		t.Fatalf("positive control: expected >=%d persisted delivery rows, got %d", logins*2, len(rows))
	}
}

// --- 3. Pagination overflow ---------------------------------------------

// adminClient registers the first user (AutoAdminFirstUser promotes it)
// and returns a cookie-jar client carrying its admin session.
func adminClient(t *testing.T, srvURL string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	cl := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	const email = "admin@example.com"
	const password = "correct horse battery staple"

	res, err := postJSON(t, cl, srvURL+"/api/auth/register", map[string]string{
		"email": email, "password": password,
	})
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	res.Body.Close()

	res, err = postJSON(t, cl, srvURL+"/api/auth/login", map[string]string{
		"email": email, "password": password,
	})
	if err != nil {
		t.Fatalf("login admin: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login admin: want 200, got %d (%s)", res.StatusCode, body)
	}
	return cl
}

// TestWebhookList_OverflowPageDoesNotPanic drives GET /webhooks with a
// ?page= large enough that (page-1)*per_page overflows int. Both list
// handlers guard only the upper bound (`if start > len(...)`), so the
// negative start reaches the slice expression and panics inside the
// handler — net/http tears the connection down and the admin sees a
// transport error rather than a response.
func TestWebhookList_OverflowPageDoesNotPanic(t *testing.T) {
	srv, ya := newWebhookServerWithYAuthConfig(t, webhooks.Config{
		AllowPrivateDestinations: true, // 127.0.0.1 receiver — see the note above.
		WorkerCount:              1,
		DeliveryTimeout:          time.Second,
	}, func(c *yauth.YAuthConfig) {
		c.AutoAdminFirstUser = true
		c.RateLimit.Login = yauth.RateLimitRule{Max: yauth.RateLimitMax(0)}
	})

	rcv := newReceiver(t)
	defer rcv.Close()
	seedWebhook(t, ya, rcv.srv.URL, "page-secret", []string{"user.registered"})

	cl := adminClient(t, srv.URL)

	// POSITIVE CONTROL first: ordinary pagination must work, otherwise a
	// blanket 400 on every ?page= would "pass" the assertion below.
	res, err := cl.Get(srv.URL + "/api/auth/webhooks?page=1&per_page=200")
	if err != nil {
		t.Fatalf("positive control: GET /webhooks?page=1: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("positive control: GET /webhooks?page=1 want 200, got %d (%s)", res.StatusCode, body)
	}
	var okBody struct {
		Items []map[string]any `json:"items"`
		Total int64            `json:"total"`
	}
	if err := json.Unmarshal(body, &okBody); err != nil {
		t.Fatalf("positive control: decode: %v (%s)", err, body)
	}
	if len(okBody.Items) != 1 || okBody.Total != 1 {
		t.Fatalf("positive control: want the one seeded webhook on page 1, got items=%d total=%d",
			len(okBody.Items), okBody.Total)
	}

	// Now the overflow page. (page-1)*200 wraps past MaxInt64 to a large
	// negative number.
	const overflowPage = 46116860184273881
	url := fmt.Sprintf("%s/api/auth/webhooks?page=%d&per_page=200", srv.URL, overflowPage)
	res, err = cl.Get(url)
	if err != nil {
		t.Fatalf("GET /webhooks?page=%d KILLED THE CONNECTION: %v\n"+
			"paginationFromQuery accepts any positive ?page=, start=(page-1)*per_page overflows "+
			"to a negative int, and the handler's `hooks[start:end]` panics on an admin route",
			overflowPage, err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode >= 500 {
		t.Fatalf("GET /webhooks?page=%d: want a clamped/refused page, got %d (%s)",
			overflowPage, res.StatusCode, body)
	}
}
