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

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/plugins/webhooks"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
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
	t.Helper()
	// Per-test in-memory DB. cache=shared scopes by name, so naming
	// the DB after the test isolates it from sibling tests.
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := gormrepo.New(db)

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(webhooks.New(webhooks.Config{WorkerCount: 2, DeliveryTimeout: 5 * time.Second})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
