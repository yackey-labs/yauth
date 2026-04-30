package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
)

// maxResponseBody is the hard cap (4 KiB) on stored response bodies.
// Larger responses are truncated; the database column is intentionally
// bounded so a misbehaving receiver cannot fill the deliveries table.
const maxResponseBody = 4 * 1024

// signaturePrefix is the literal prefix carried in the X-YAuth-Signature
// header. Only sha256 is supported in the MVP; the prefix lets receivers
// negotiate algorithms in a future revision without changing the header.
const signaturePrefix = "sha256="

// payloadEnvelope is the JSON body POSTed to the receiver. It matches
// the shape documented in the README and consumed by the example
// receiver: {event, timestamp, data}.
type payloadEnvelope struct {
	Event     string         `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// deliveryJob is the unit of work pushed onto the dispatcher channel.
// It captures everything a worker needs without holding a reference to
// the request that produced it — workers run after the request returns.
type deliveryJob struct {
	webhook   domain.Webhook
	eventType string
	payload   payloadEnvelope
}

// Dispatcher fans deliveryJobs out to a fixed-size worker pool. Workers
// sign each payload with the webhook's HMAC secret, POST it, and persist
// a WebhookDelivery row recording the outcome.
type Dispatcher struct {
	repo       repo.Repository
	httpClient *http.Client
	workers    int

	jobs chan *deliveryJob
	wg   sync.WaitGroup

	// closeOnce guards the close(jobs) so multiple Shutdown calls are a
	// no-op rather than a panic on a closed channel.
	closeOnce sync.Once

	// mu protects the closed flag — set under the lock once the channel
	// has been closed so Enqueue can short-circuit instead of writing to
	// a closed channel.
	mu     sync.RWMutex
	closed bool
}

// NewDispatcher constructs a dispatcher with a buffered job channel
// sized to 8x the worker count, a small headroom that lets bursty
// emit() callers return without blocking on slow receivers.
func NewDispatcher(r repo.Repository, client *http.Client, workers int) *Dispatcher {
	if workers <= 0 {
		workers = defaultWorkerCount
	}
	return &Dispatcher{
		repo:       r,
		httpClient: client,
		workers:    workers,
		jobs:       make(chan *deliveryJob, workers*8),
	}
}

// Start spawns the worker goroutines. Safe to call exactly once before
// any Enqueue calls.
func (d *Dispatcher) Start() {
	for i := 0; i < d.workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
}

// Enqueue pushes a job into the channel. Returns an error if the
// dispatcher is shutting down so the caller can drop the event rather
// than panic on a closed channel. Callers should treat enqueue failures
// as best-effort — the event has already happened.
func (d *Dispatcher) Enqueue(job *deliveryJob) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return errors.New("webhooks: dispatcher is shut down")
	}
	d.jobs <- job
	return nil
}

// Shutdown closes the job channel and waits for workers to drain. If
// ctx expires before draining completes Shutdown returns ctx.Err()
// while leaving the workers running — they will exit on their own once
// they finish their current HTTP call, and the buffered jobs that were
// never picked up are dropped at process exit.
func (d *Dispatcher) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()

	d.closeOnce.Do(func() { close(d.jobs) })

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// worker pulls jobs off the channel until it is closed. Each delivery
// is a single HTTP attempt; failures are persisted but not retried.
//
// TODO(yauth-go): retry policy with exponential backoff and dead-letter
// table once the MVP ships. The Rust implementation persists attempt
// numbers >1 — the column is wired here, but the value is hard-coded
// to 1 until retry lands.
func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for job := range d.jobs {
		// Use Background — the originating request's context is gone
		// by the time the worker picks up the job.
		ctx, cancel := context.WithTimeout(context.Background(), d.httpClient.Timeout+5*time.Second)
		d.deliver(ctx, job)
		cancel()
	}
}

// deliver performs the signed HTTP POST and records a delivery row.
func (d *Dispatcher) deliver(ctx context.Context, job *deliveryJob) {
	body, err := json.Marshal(job.payload)
	if err != nil {
		// Encoding failure is a programmer bug — record an attempt with
		// success=false so operators see the failure surface in the
		// deliveries table.
		d.recordDelivery(ctx, job, body, nil, fmt.Sprintf("marshal payload: %v", err), false)
		return
	}

	deliveryID := uuid.NewString()
	signature := signPayload(job.webhook.Secret, body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, job.webhook.URL, bytes.NewReader(body))
	if err != nil {
		d.recordDelivery(ctx, job, body, nil, fmt.Sprintf("build request: %v", err), false)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-YAuth-Event", job.eventType)
	req.Header.Set("X-YAuth-Delivery", deliveryID)
	req.Header.Set("X-YAuth-Signature", signaturePrefix+signature)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		d.recordDelivery(ctx, job, body, nil, fmt.Sprintf("http: %v", err), false)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if len(respBody) > maxResponseBody {
		respBody = respBody[:maxResponseBody]
	}

	status := int16(resp.StatusCode)
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	d.recordDelivery(ctx, job, body, &status, string(respBody), success)
}

// recordDelivery persists a WebhookDelivery row. Errors writing the
// row are intentionally swallowed — failure to record observability
// data should not break the production path. The original delivery
// outcome is unaffected.
func (d *Dispatcher) recordDelivery(ctx context.Context, job *deliveryJob, payload []byte, status *int16, responseBody string, success bool) {
	bodyPtr := &responseBody
	if responseBody == "" {
		bodyPtr = nil
	}
	_ = d.repo.CreateWebhookDelivery(ctx, domain.NewWebhookDelivery{
		ID:           uuid.NewString(),
		WebhookID:    job.webhook.ID,
		EventType:    job.eventType,
		Payload:      payload,
		StatusCode:   status,
		ResponseBody: bodyPtr,
		Success:      success,
		Attempt:      1,
		CreatedAt:    time.Now().UTC(),
	})
}

// signPayload returns the lower-case hex HMAC-SHA256 of body using
// secret as the key. Exported indirectly via the X-YAuth-Signature
// header; receivers reproduce the calculation to verify authenticity.
func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
