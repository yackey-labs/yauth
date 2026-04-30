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
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
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

// deadLetterMarker is the substring written to the response_body of the
// terminal dead-letter row. Operators can grep for it to find webhooks
// that were given up on after MaxAttempts.
const deadLetterMarker = "DEAD_LETTER"

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
//
// attempt is the 1-indexed attempt counter; it is incremented before
// each delivery so the persisted row records the correct attempt number.
type deliveryJob struct {
	webhook   domain.Webhook
	eventType string
	payload   payloadEnvelope
	attempt   int
}

// RetryConfig groups the retry/backoff knobs the dispatcher honours.
// Constructed by the plugin from its public Config; not exported on its
// own because callers should configure via Config.
type RetryConfig struct {
	MaxAttempts       int
	InitialBackoff    time.Duration
	MaxBackoff        time.Duration
	BackoffJitter     float64
	DeadLetterEnabled bool
}

// Dispatcher fans deliveryJobs out to a fixed-size worker pool. Workers
// sign each payload with the webhook's HMAC secret, POST it, and persist
// a WebhookDelivery row recording the outcome. On retryable failures the
// dispatcher schedules a delayed requeue via time.AfterFunc rather than
// blocking the worker — the worker stays free to drain other jobs.
type Dispatcher struct {
	repo       repo.Repository
	httpClient *http.Client
	workers    int
	retry      RetryConfig

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

	// timers tracks pending retry timers so Shutdown can stop them
	// before draining workers. Key is a unique handle (atomic counter),
	// value is *time.Timer.
	timers   sync.Map
	timerSeq atomic.Uint64
	logf     func(format string, args ...any)
}

// NewDispatcher constructs a dispatcher with a buffered job channel
// sized to 8x the worker count, a small headroom that lets bursty
// emit() callers return without blocking on slow receivers.
func NewDispatcher(r repo.Repository, client *http.Client, workers int, retry RetryConfig) *Dispatcher {
	if workers <= 0 {
		workers = defaultWorkerCount
	}
	if retry.MaxAttempts <= 0 {
		retry.MaxAttempts = defaultMaxAttempts
	}
	if retry.InitialBackoff <= 0 {
		retry.InitialBackoff = defaultInitialBackoff
	}
	if retry.MaxBackoff <= 0 {
		retry.MaxBackoff = defaultMaxBackoff
	}
	if retry.BackoffJitter < 0 {
		retry.BackoffJitter = 0
	}
	return &Dispatcher{
		repo:       r,
		httpClient: client,
		workers:    workers,
		retry:      retry,
		jobs:       make(chan *deliveryJob, workers*8),
		logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
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

// Shutdown closes the job channel, stops any pending retry timers, and
// waits for workers to drain. If ctx expires before draining completes
// Shutdown returns ctx.Err() while leaving the workers running — they
// will exit on their own once they finish their current HTTP call, and
// the buffered jobs that were never picked up are dropped at process
// exit.
func (d *Dispatcher) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()

	// Stop any pending retry timers so they don't try to push onto a
	// closed channel. The closure registered with AfterFunc races with
	// us: it calls LoadAndDelete on the same map entry, so whichever
	// side wins removes the key. If we win, we Stop the timer; if the
	// closure wins, it'll attempt Enqueue and fail cleanly because
	// d.closed is already true.
	d.timers.Range(func(k, v any) bool {
		if _, loaded := d.timers.LoadAndDelete(k); loaded {
			if t, ok := v.(*time.Timer); ok {
				t.Stop()
			}
		}
		return true
	})

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
// is a single HTTP attempt; the worker classifies the outcome and
// either schedules a delayed retry via time.AfterFunc or lets the job
// drop. The worker itself never blocks on backoff — that keeps the
// pool responsive under heavy retry load.
func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for job := range d.jobs {
		// Use Background — the originating request's context is gone
		// by the time the worker picks up the job.
		ctx, cancel := context.WithTimeout(context.Background(), d.httpClient.Timeout+5*time.Second)
		outcome := d.deliver(ctx, job)
		cancel()

		if outcome.success || !outcome.retryable {
			continue
		}
		if job.attempt >= d.retry.MaxAttempts {
			d.recordDeadLetter(context.Background(), job, outcome)
			continue
		}
		d.scheduleRetry(job)
	}
}

// deliveryOutcome is the worker's decision after a single attempt.
type deliveryOutcome struct {
	success    bool
	retryable  bool
	statusCode int
}

// deliver performs the signed HTTP POST, records a delivery row for
// the attempt, and returns an outcome describing what to do next.
func (d *Dispatcher) deliver(ctx context.Context, job *deliveryJob) deliveryOutcome {
	job.attempt++

	body, err := json.Marshal(job.payload)
	if err != nil {
		// Encoding failure is a programmer bug — record an attempt with
		// success=false so operators see the failure surface in the
		// deliveries table. Not retryable — the payload won't change.
		d.recordDelivery(ctx, job, body, nil, fmt.Sprintf("marshal payload: %v", err), false)
		return deliveryOutcome{success: false, retryable: false}
	}

	deliveryID := uuid.NewString()
	signature := signPayload(job.webhook.Secret, body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, job.webhook.URL, bytes.NewReader(body))
	if err != nil {
		d.recordDelivery(ctx, job, body, nil, fmt.Sprintf("build request: %v", err), false)
		return deliveryOutcome{success: false, retryable: false}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-YAuth-Event", job.eventType)
	req.Header.Set("X-YAuth-Delivery", deliveryID)
	req.Header.Set("X-YAuth-Signature", signaturePrefix+signature)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Network error — retryable.
		d.recordDelivery(ctx, job, body, nil, fmt.Sprintf("http: %v", err), false)
		return deliveryOutcome{success: false, retryable: true}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if len(respBody) > maxResponseBody {
		respBody = respBody[:maxResponseBody]
	}

	status := int16(resp.StatusCode)
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	d.recordDelivery(ctx, job, body, &status, string(respBody), success)

	return deliveryOutcome{
		success:    success,
		retryable:  shouldRetry(resp.StatusCode),
		statusCode: resp.StatusCode,
	}
}

// shouldRetry reports whether a status code should trigger a retry.
// 5xx is always retryable; 408 (Request Timeout) and 429 (Too Many
// Requests) are explicitly retryable. Other 4xx are terminal because
// the receiver is rejecting the request shape — retrying won't help.
func shouldRetry(statusCode int) bool {
	if statusCode >= 500 {
		return true
	}
	if statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests {
		return true
	}
	return false
}

// scheduleRetry computes the delay for the next attempt and arms a
// time.AfterFunc that requeues the job when it fires. The timer is
// tracked in d.timers so Shutdown can stop pending retries cleanly.
func (d *Dispatcher) scheduleRetry(job *deliveryJob) {
	delay := d.backoffFor(job.attempt)

	handle := d.timerSeq.Add(1)

	timer := time.AfterFunc(delay, func() {
		// On fire: remove from the tracking map and try to requeue. If
		// Shutdown won the race for this entry it has stopped (or is
		// stopping) the timer, but the closure still runs once if
		// Stop() loses the race; in that case the LoadAndDelete here
		// returns !loaded and we exit.
		if _, loaded := d.timers.LoadAndDelete(handle); !loaded {
			return
		}
		if err := d.Enqueue(job); err != nil {
			// Dispatcher closed before requeue landed — drop the job.
			d.logf("yauth-go webhooks: dropping retry for webhook %s after shutdown\n", job.webhook.ID)
		}
	})
	d.timers.Store(handle, timer)
}

// backoffFor returns the backoff duration for the *next* attempt given
// that the current attempt number is `current`. Formula:
//
//	delay = InitialBackoff * 2^(current-1), capped at MaxBackoff,
//	        then perturbed by ±BackoffJitter.
//
// The first retry (after attempt 1 fails) uses InitialBackoff itself.
func (d *Dispatcher) backoffFor(current int) time.Duration {
	if current < 1 {
		current = 1
	}
	// Cap exponent to avoid overflow on pathological MaxAttempts.
	exp := current - 1
	if exp > 30 {
		exp = 30
	}
	base := float64(d.retry.InitialBackoff) * math.Pow(2, float64(exp))
	if base > float64(d.retry.MaxBackoff) {
		base = float64(d.retry.MaxBackoff)
	}
	if d.retry.BackoffJitter > 0 {
		// Jitter range: [-BackoffJitter, +BackoffJitter] of base.
		// math/rand/v2 is safe for concurrent use; no mutex needed.
		factor := 1 + d.retry.BackoffJitter*(2*rand.Float64()-1)
		base *= factor
	}
	if base < 0 {
		base = 0
	}
	return time.Duration(base)
}

// recordDeadLetter persists a final WebhookDelivery row marking the job
// as terminally failed. The status_code is left nil and the response
// body carries deadLetterMarker so operators can surface these via a
// simple LIKE query. A stderr log makes the event visible without a
// downstream telemetry pipeline.
func (d *Dispatcher) recordDeadLetter(ctx context.Context, job *deliveryJob, last deliveryOutcome) {
	d.logf("yauth-go webhooks: dead-letter webhook=%s event=%s attempts=%d last_status=%d\n",
		job.webhook.ID, job.eventType, job.attempt, last.statusCode)
	if !d.retry.DeadLetterEnabled {
		return
	}
	body, _ := json.Marshal(job.payload)
	msg := fmt.Sprintf("%s: gave up after %d attempts (last_status=%d)", deadLetterMarker, job.attempt, last.statusCode)
	// Bump attempt one past the last real attempt so the dead-letter
	// row sorts after the final delivery row.
	deadLetterAttempt := job.attempt + 1
	_ = d.repo.CreateWebhookDelivery(ctx, domain.NewWebhookDelivery{
		ID:           uuid.NewString(),
		WebhookID:    job.webhook.ID,
		EventType:    job.eventType,
		Payload:      body,
		StatusCode:   nil,
		ResponseBody: &msg,
		Success:      false,
		Attempt:      deadLetterAttempt,
		CreatedAt:    time.Now().UTC(),
	})
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
		Attempt:      job.attempt,
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
