package webhooks_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/webhooks"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// receiver is an httptest server that records every webhook delivery
// it sees so the test can assert on counts, signatures, and headers.
type receiver struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []receivedHit
}

type receivedHit struct {
	Body      []byte
	Event     string
	Delivery  string
	Signature string
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.hits = append(r.hits, receivedHit{
			Body:      body,
			Event:     req.Header.Get("X-YAuth-Event"),
			Delivery:  req.Header.Get("X-YAuth-Delivery"),
			Signature: req.Header.Get("X-YAuth-Signature"),
		})
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	return r
}

func (r *receiver) Close() { r.srv.Close() }

func (r *receiver) Hits() []receivedHit {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]receivedHit, len(r.hits))
	copy(out, r.hits)
	return out
}

// waitFor polls fn until it returns true or timeout elapses. Avoids
// time.Sleep races in async webhook tests.
func waitFor(t *testing.T, timeout time.Duration, fn func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}

func newWebhooksTestServer(t *testing.T) (*httptest.Server, *yauth.YAuth) {
	return newWebhooksTestServerWithConfig(t, webhooks.Config{
		WorkerCount:     2,
		DeliveryTimeout: 5 * time.Second,
	})
}

func newWebhooksTestServerWithConfig(t *testing.T, cfg webhooks.Config) (*httptest.Server, *yauth.YAuth) {
	t.Helper()
	repo := memrepo.New()

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		WithPlugin(webhooks.New(cfg)).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ya.Shutdown(shutdownCtx)
	})
	return srv, ya
}

// seedWebhook writes a webhook row directly via the repository, since
// the admin endpoints require an admin caller and provisioning one is
// out of scope for this test. The caller-supplied secret is what the
// receiver will verify against.
func seedWebhook(t *testing.T, ya *yauth.YAuth, url, secret string, eventTypes []string) string {
	t.Helper()
	id := "wh-" + randHex(t, 8)
	rawEvents, err := json.Marshal(eventTypes)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	now := time.Now().UTC()
	if err := ya.Repo().CreateWebhook(context.Background(), domain.NewWebhook{
		ID:        id,
		URL:       url,
		Secret:    secret,
		Events:    rawEvents,
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	return id
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(buf)
}

// TestWebhookDelivery_OnUserRegistered exercises the full pipeline:
// register a user via the email-password plugin, watch the webhook
// dispatcher fan the user.registered event to a real httptest receiver,
// and verify the HMAC signature + persisted delivery row.
func TestWebhookDelivery_OnUserRegistered(t *testing.T) {
	rcv := newReceiver(t)
	defer rcv.Close()

	srv, ya := newWebhooksTestServer(t)
	const secret = "test-secret-correct-horse-battery-staple"
	whID := seedWebhook(t, ya, rcv.srv.URL, secret, []string{"user.registered"})

	body := map[string]string{
		"email":    "alice@example.com",
		"password": "correct horse battery staple",
	}
	buf, _ := json.Marshal(body)
	res, err := http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", res.StatusCode)
	}

	if !waitFor(t, 2*time.Second, func() bool { return len(rcv.Hits()) >= 1 }) {
		t.Fatalf("expected receiver to record at least one hit, got %d", len(rcv.Hits()))
	}
	hit := rcv.Hits()[0]
	if hit.Event != "user.registered" {
		t.Fatalf("X-YAuth-Event: got %q want user.registered", hit.Event)
	}
	if hit.Delivery == "" {
		t.Fatalf("X-YAuth-Delivery missing")
	}
	if !strings.HasPrefix(hit.Signature, "sha256=") {
		t.Fatalf("X-YAuth-Signature prefix: got %q", hit.Signature)
	}

	wantSig := computeHMAC(secret, hit.Body)
	if hit.Signature != "sha256="+wantSig {
		t.Fatalf("signature mismatch:\n got  %s\n want sha256=%s\n body %s", hit.Signature, wantSig, hit.Body)
	}

	var env map[string]any
	if err := json.Unmarshal(hit.Body, &env); err != nil {
		t.Fatalf("body not JSON: %v\n%s", err, hit.Body)
	}
	if env["event"] != "user.registered" {
		t.Fatalf("body.event: got %v", env["event"])
	}

	// Verify delivery was persisted.
	if !waitFor(t, 2*time.Second, func() bool {
		rows, _ := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
		return len(rows) >= 1
	}) {
		t.Fatalf("expected at least one delivery row in DB")
	}
	rows, err := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if rows[0].EventType != "user.registered" {
		t.Fatalf("delivery row event_type: got %q", rows[0].EventType)
	}
	if !rows[0].Success {
		t.Fatalf("delivery row success: expected true, got false (status=%v)", rows[0].StatusCode)
	}
	if rows[0].StatusCode == nil || *rows[0].StatusCode != 200 {
		t.Fatalf("delivery row status_code: got %v want 200", rows[0].StatusCode)
	}
}

// TestWebhookDelivery_FiltersByEvent verifies that a webhook subscribed
// only to login.succeeded does NOT receive a user.registered event.
func TestWebhookDelivery_FiltersByEvent(t *testing.T) {
	rcv := newReceiver(t)
	defer rcv.Close()

	srv, ya := newWebhooksTestServer(t)
	seedWebhook(t, ya, rcv.srv.URL, "secret", []string{"login.succeeded"})

	body := map[string]string{
		"email":    "bob@example.com",
		"password": "correct horse battery staple",
	}
	buf, _ := json.Marshal(body)
	res, err := http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()

	// Wait a beat to give a misbehaving dispatcher time to deliver.
	time.Sleep(200 * time.Millisecond)
	if got := len(rcv.Hits()); got != 0 {
		t.Fatalf("expected zero hits for unsubscribed event, got %d", got)
	}
}

// TestWebhookShutdown_DrainsWorkers verifies that YAuth.Shutdown waits
// for in-flight deliveries to complete.
func TestWebhookShutdown_DrainsWorkers(t *testing.T) {
	rcv := newReceiver(t)
	defer rcv.Close()

	srv, ya := newWebhooksTestServer(t)
	seedWebhook(t, ya, rcv.srv.URL, "secret", []string{"user.registered"})

	body := map[string]string{
		"email":    "carol@example.com",
		"password": "correct horse battery staple",
	}
	buf, _ := json.Marshal(body)
	res, err := http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ya.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if got := len(rcv.Hits()); got < 1 {
		t.Fatalf("expected at least 1 hit after shutdown, got %d", got)
	}
}

func computeHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// programmedReceiver returns a configured sequence of HTTP status codes
// across consecutive deliveries. After the sequence is exhausted the
// receiver returns the last code in the slice (or 200 if empty).
type programmedReceiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	hits   int
	codes  []int
	bodies [][]byte
}

func newProgrammedReceiver(t *testing.T, codes []int) *programmedReceiver {
	t.Helper()
	r := &programmedReceiver{codes: codes}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		idx := r.hits
		r.hits++
		r.bodies = append(r.bodies, body)
		var code int
		switch {
		case len(r.codes) == 0:
			code = http.StatusOK
		case idx >= len(r.codes):
			code = r.codes[len(r.codes)-1]
		default:
			code = r.codes[idx]
		}
		r.mu.Unlock()
		w.WriteHeader(code)
	}))
	return r
}

func (r *programmedReceiver) Close() { r.srv.Close() }

func (r *programmedReceiver) Hits() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

// TestWebhookRetry_RecoversAfterTransientFailure: receiver returns 500
// twice then 200; the third attempt should succeed and three delivery
// rows should be persisted with attempts 1, 2, 3.
func TestWebhookRetry_RecoversAfterTransientFailure(t *testing.T) {
	rcv := newProgrammedReceiver(t, []int{500, 500, 200})
	defer rcv.Close()

	srv, ya := newWebhooksTestServerWithConfig(t, webhooks.Config{
		WorkerCount:     2,
		DeliveryTimeout: 2 * time.Second,
		MaxAttempts:     5,
		InitialBackoff:  20 * time.Millisecond,
		MaxBackoff:      200 * time.Millisecond,
		BackoffJitter:   -1, // disable jitter for deterministic timing
	})
	const secret = "retry-secret"
	whID := seedWebhook(t, ya, rcv.srv.URL, secret, []string{"user.registered"})

	body := map[string]string{
		"email":    "retry@example.com",
		"password": "correct horse battery staple",
	}
	buf, _ := json.Marshal(body)
	res, err := http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", res.StatusCode)
	}

	if !waitFor(t, 5*time.Second, func() bool { return rcv.Hits() >= 3 }) {
		t.Fatalf("expected receiver to record 3 hits, got %d", rcv.Hits())
	}

	// Wait for the success row to be persisted.
	if !waitFor(t, 5*time.Second, func() bool {
		rows, _ := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
		for _, row := range rows {
			if row.Success {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("expected at least one successful delivery row")
	}

	rows, err := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(rows) < 3 {
		t.Fatalf("expected >=3 delivery rows, got %d", len(rows))
	}

	// Walk attempts to ensure 1,2,3 are present and the third succeeded.
	seen := map[int]*domain.WebhookDelivery{}
	for _, r := range rows {
		seen[r.Attempt] = r
	}
	for n := 1; n <= 3; n++ {
		if _, ok := seen[n]; !ok {
			t.Fatalf("missing delivery row for attempt %d (rows=%v)", n, rows)
		}
	}
	if !seen[3].Success {
		t.Fatalf("attempt 3 should be success=true, got %+v", seen[3])
	}
	if seen[1].Success || seen[2].Success {
		t.Fatalf("attempts 1 and 2 should be success=false")
	}
}

// TestWebhookRetry_DeadLetter: receiver always returns 500. After
// MaxAttempts is reached, a dead-letter delivery row is persisted with
// success=false and a DEAD_LETTER marker in the response_body.
func TestWebhookRetry_DeadLetter(t *testing.T) {
	rcv := newProgrammedReceiver(t, []int{500})
	defer rcv.Close()

	srv, ya := newWebhooksTestServerWithConfig(t, webhooks.Config{
		WorkerCount:     2,
		DeliveryTimeout: 2 * time.Second,
		MaxAttempts:     3,
		InitialBackoff:  10 * time.Millisecond,
		MaxBackoff:      50 * time.Millisecond,
		BackoffJitter:   -1,
	})
	const secret = "dead-letter-secret"
	whID := seedWebhook(t, ya, rcv.srv.URL, secret, []string{"user.registered"})

	body := map[string]string{
		"email":    "deadletter@example.com",
		"password": "correct horse battery staple",
	}
	buf, _ := json.Marshal(body)
	res, err := http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()

	if !waitFor(t, 15*time.Second, func() bool { return rcv.Hits() >= 3 }) {
		t.Fatalf("expected 3 attempts, got %d", rcv.Hits())
	}

	// Wait for dead-letter row to land. Give CI hardware extra slack —
	// the row creation runs on a worker goroutine after the 3rd attempt
	// returns, and slow CI runners with argon2 hashing in-flight can
	// push the recordDeadLetter call to the tail of the budget.
	if !waitFor(t, 15*time.Second, func() bool {
		rows, _ := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
		for _, row := range rows {
			if row.ResponseBody != nil && strings.Contains(*row.ResponseBody, "DEAD_LETTER") {
				return true
			}
		}
		return false
	}) {
		rows, _ := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
		t.Fatalf("expected dead-letter row to be persisted (have %d rows)", len(rows))
	}

	rows, err := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	// 3 attempts + 1 dead-letter row.
	if len(rows) < 4 {
		t.Fatalf("expected >=4 rows (3 attempts + dead-letter), got %d", len(rows))
	}
	var dl *domain.WebhookDelivery
	for _, r := range rows {
		if r.ResponseBody != nil && strings.Contains(*r.ResponseBody, "DEAD_LETTER") {
			dl = r
			break
		}
	}
	if dl == nil {
		t.Fatalf("dead-letter row not found")
	}
	if dl.Success {
		t.Fatalf("dead-letter row should be success=false")
	}
	if dl.StatusCode != nil {
		t.Fatalf("dead-letter row should have nil status_code, got %v", *dl.StatusCode)
	}
}

// TestWebhookRetry_4xxNoRetry: receiver returns 400. The dispatcher
// should record exactly one attempt and not retry. No dead-letter row
// either — 4xx (excl 408/429) is a terminal failure on the first try.
func TestWebhookRetry_4xxNoRetry(t *testing.T) {
	rcv := newProgrammedReceiver(t, []int{400})
	defer rcv.Close()

	srv, ya := newWebhooksTestServerWithConfig(t, webhooks.Config{
		WorkerCount:     2,
		DeliveryTimeout: 2 * time.Second,
		MaxAttempts:     5,
		InitialBackoff:  10 * time.Millisecond,
		MaxBackoff:      50 * time.Millisecond,
		BackoffJitter:   -1,
	})
	whID := seedWebhook(t, ya, rcv.srv.URL, "secret", []string{"user.registered"})

	body := map[string]string{
		"email":    "noretry@example.com",
		"password": "correct horse battery staple",
	}
	buf, _ := json.Marshal(body)
	res, err := http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()

	// Wait for one delivery row to land.
	if !waitFor(t, 3*time.Second, func() bool {
		rows, _ := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
		return len(rows) >= 1
	}) {
		t.Fatalf("expected at least one delivery row")
	}

	// Give the dispatcher generous time to (incorrectly) retry — if the
	// retry policy is broken we want this assertion to fail.
	time.Sleep(300 * time.Millisecond)

	if got := rcv.Hits(); got != 1 {
		t.Fatalf("expected exactly 1 receiver hit on 4xx, got %d", got)
	}
	rows, err := ya.Repo().ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 delivery row, got %d", len(rows))
	}
	if rows[0].Attempt != 1 {
		t.Fatalf("expected attempt=1, got %d", rows[0].Attempt)
	}
	if rows[0].Success {
		t.Fatalf("expected success=false on 4xx")
	}
	if rows[0].StatusCode == nil || *rows[0].StatusCode != 400 {
		t.Fatalf("expected status_code=400, got %v", rows[0].StatusCode)
	}
}

// TestWebhookRetry_PersistsAcrossRestart exercises the crash-safe queue:
// the first dispatcher writes a ScheduledWebhookRetry row after attempt
// 1 fails, then the test shuts it down, constructs a second dispatcher
// against the same repo, and verifies the second dispatcher claims the
// row and fires attempt 2.
func TestWebhookRetry_PersistsAcrossRestart(t *testing.T) {
	rcv := newProgrammedReceiver(t, []int{500, 200})
	defer rcv.Close()

	// Per-test in-memory repo shared across the two dispatchers — both
	// dispatchers are constructed against this same r, so the persisted
	// retry row written by the first is visible to the second.
	r := memrepo.New()

	const secret = "restart-secret"
	whID := "wh-restart-" + randHex(t, 4)
	rawEvents, _ := json.Marshal([]string{"user.registered"})
	now := time.Now().UTC()
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

	retryCfg := webhooks.RetryConfig{
		MaxAttempts:       5,
		InitialBackoff:    50 * time.Millisecond,
		MaxBackoff:        100 * time.Millisecond,
		BackoffJitter:     0,
		DeadLetterEnabled: true,
		// Disable the periodic claimer so the first dispatcher never
		// picks the row back up; we want to assert it survives shutdown.
		ClaimerInterval:  1 * time.Hour,
		ClaimerBatchSize: 100,
	}
	httpClient := &http.Client{Timeout: 2 * time.Second}

	// --- First dispatcher: fire attempt 1, watch it fail, observe the
	// scheduled retry row land in the DB, then shut down.
	d1 := webhooks.NewDispatcher(r, httpClient, 2, retryCfg, nil)
	d1.Start()

	hook, err := r.GetWebhookByID(context.Background(), whID)
	if err != nil || hook == nil {
		t.Fatalf("get webhook: %v", err)
	}
	job := webhooks.NewDeliveryJobForTest(*hook, "user.registered", map[string]any{
		"email": "restart@example.com",
	})
	if err := d1.Enqueue(job); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Wait for attempt 1 to land + scheduled retry row to be persisted.
	if !waitFor(t, 5*time.Second, func() bool {
		rows, _ := r.ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
		return len(rows) >= 1
	}) {
		t.Fatalf("expected attempt-1 delivery row after first dispatcher run")
	}
	if !waitFor(t, 5*time.Second, func() bool {
		// Claim with a very-far-in-future "now" to peek at all rows
		// would also delete them; use a probe by attempting to claim
		// rows with not_before at most 1h from now (which is past the
		// 50ms backoff). Then re-persist them so the second dispatcher
		// can still see them.
		rows, _ := r.ClaimDueRetries(context.Background(), time.Now().Add(time.Hour), 10)
		if len(rows) == 0 {
			return false
		}
		// Re-persist exactly what we just claimed so the second
		// dispatcher's claim cycle still has work to do.
		for _, row := range rows {
			_ = r.CreateScheduledRetry(context.Background(), domain.NewScheduledWebhookRetry{
				ID:        row.ID,
				WebhookID: row.WebhookID,
				EventType: row.EventType,
				Payload:   row.Payload,
				Attempt:   row.Attempt,
				NotBefore: row.NotBefore,
				CreatedAt: row.CreatedAt,
			})
		}
		return true
	}) {
		t.Fatalf("expected scheduled retry row to be persisted after attempt 1")
	}

	hitsAfterFirstShutdown := rcv.Hits()
	if hitsAfterFirstShutdown < 1 {
		t.Fatalf("expected at least 1 receiver hit before first shutdown, got %d", hitsAfterFirstShutdown)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d1.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown d1: %v", err)
	}

	// Confirm the retry row still exists after shutdown — un-claimed
	// rows must remain in the DB for the next process to pick up.
	rowsBeforeRestart, err := r.ClaimDueRetries(context.Background(), time.Now().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("claim probe: %v", err)
	}
	if len(rowsBeforeRestart) == 0 {
		t.Fatalf("expected retry row to survive shutdown")
	}
	// Re-persist (claim deletes them) so the new dispatcher can claim them.
	for _, row := range rowsBeforeRestart {
		if err := r.CreateScheduledRetry(context.Background(), domain.NewScheduledWebhookRetry{
			ID:        row.ID,
			WebhookID: row.WebhookID,
			EventType: row.EventType,
			Payload:   row.Payload,
			Attempt:   row.Attempt,
			NotBefore: row.NotBefore,
			CreatedAt: row.CreatedAt,
		}); err != nil {
			t.Fatalf("re-persist retry: %v", err)
		}
	}

	// --- Second dispatcher: same repo, fast claimer interval. It should
	// claim the persisted retry row and fire attempt 2, which the
	// programmed receiver answers with 200.
	retryCfg2 := retryCfg
	retryCfg2.ClaimerInterval = 50 * time.Millisecond
	d2 := webhooks.NewDispatcher(r, httpClient, 2, retryCfg2, nil)
	d2.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d2.Shutdown(ctx)
	})

	if !waitFor(t, 5*time.Second, func() bool { return rcv.Hits() >= 2 }) {
		t.Fatalf("expected second dispatcher to fire attempt 2 (got %d total hits)", rcv.Hits())
	}

	if !waitFor(t, 5*time.Second, func() bool {
		rows, _ := r.ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
		for _, row := range rows {
			if row.Success && row.Attempt >= 2 {
				return true
			}
		}
		return false
	}) {
		rows, _ := r.ListWebhookDeliveriesByWebhookID(context.Background(), whID, 10)
		t.Fatalf("expected attempt >=2 success row from second dispatcher, got rows=%+v", rows)
	}
}
