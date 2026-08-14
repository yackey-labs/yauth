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
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
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

	// ClaimerInterval is how often the claimer goroutine scans the
	// retry queue for due rows. Defaults to 1s.
	ClaimerInterval time.Duration
	// ClaimerBatchSize caps the number of retries claimed per scan.
	// Defaults to 100.
	ClaimerBatchSize int
}

// Dispatcher fans deliveryJobs out to a fixed-size worker pool. Workers
// sign each payload with the webhook's HMAC secret, POST it, and persist
// a WebhookDelivery row recording the outcome. On retryable failures the
// dispatcher writes a ScheduledWebhookRetry row to the repo and a
// separate claimer goroutine periodically pulls due rows back into the
// in-process worker channel — so retries survive a process restart.
type Dispatcher struct {
	repo       repo.Repository
	httpClient *http.Client
	workers    int
	retry      RetryConfig
	secretKey  []byte // AES-256 key for decrypting at-rest webhook secrets; nil → plaintext pass-through

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

	// claimerStop signals the claimer goroutine to exit; closed once
	// during Shutdown. claimerDone is closed by the claimer when it
	// returns so Shutdown can wait for it.
	claimerStop chan struct{}
	claimerDone chan struct{}

	// lastDropLog is the unix-nano timestamp of the last "queue full"
	// warning, used to throttle it — see noteDroppedEnqueue.
	lastDropLog atomic.Int64

	logf func(format string, args ...any)
}

// NewDispatcher constructs a dispatcher with a buffered job channel
// sized to 8x the worker count, a small headroom that lets bursty
// emit() callers return without blocking on slow receivers.
func NewDispatcher(r repo.Repository, client *http.Client, workers int, retry RetryConfig, secretKey []byte) *Dispatcher {
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
	if retry.ClaimerInterval <= 0 {
		retry.ClaimerInterval = defaultClaimerInterval
	}
	if retry.ClaimerBatchSize <= 0 {
		retry.ClaimerBatchSize = defaultClaimerBatchSize
	}
	return &Dispatcher{
		repo:        r,
		httpClient:  client,
		workers:     workers,
		retry:       retry,
		secretKey:   secretKey,
		jobs:        make(chan *deliveryJob, workers*8),
		claimerStop: make(chan struct{}),
		claimerDone: make(chan struct{}),
		logf:        slogLogf(slog.Default()),
	}
}

// slogLogf adapts the dispatcher's printf-style logf onto a structured
// logger: the formatted message is emitted at WARN (trailing newline
// trimmed) through the supplied logger, so webhook delivery diagnostics
// route through the host's configured handler instead of raw stderr.
func slogLogf(l *slog.Logger) func(string, ...any) {
	return func(format string, args ...any) {
		l.Warn(strings.TrimRight(fmt.Sprintf(format, args...), "\n"))
	}
}

// useLogger redirects the dispatcher's diagnostics to l. Called by the
// plugin at Routes time with PluginHost.Logger() so all webhook output
// shares the application's logger. No-op when l is nil.
func (d *Dispatcher) useLogger(l *slog.Logger) {
	if l == nil {
		return
	}
	d.logf = slogLogf(l)
}

// Start spawns the worker goroutines and the claimer goroutine. Safe to
// call exactly once before any Enqueue calls. The claimer immediately
// runs one scan to pick up any retries persisted by a prior process so
// a crash mid-backoff doesn't drop them on the floor.
func (d *Dispatcher) Start() {
	for i := 0; i < d.workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	go d.claimerLoop()
}

// ErrQueueFull is returned by Enqueue when the buffered job channel has
// no free slot. It is a routine outcome, not a bug: it is how Enqueue
// keeps its promise never to park the caller. Callers distinguish it
// from the shutdown error — runClaim re-persists the retry row with a
// deferred not_before, and the admin /test route reports it honestly.
var ErrQueueFull = errors.New("webhooks: delivery queue is full")

// Enqueue pushes a job into the channel. It NEVER blocks the caller:
// the invariant is that YAuth.Emit — which runs every registered event
// handler INLINE on the HTTP request goroutine — returns promptly no
// matter what a webhook receiver is doing.
//
// It used to do a bare `d.jobs <- job`. The channel holds workers*8
// jobs and every worker parks inside http.Client.Do for the whole
// DeliveryTimeout, so a single registered receiver that stopped
// answering filled the buffer and then parked the next login request
// goroutine inside Emit — forever. Authentication went down for the
// entire deployment because one operator-registered endpoint got slow,
// and the parked senders held d.mu.RLock() so Shutdown's d.mu.Lock()
// starved too. No attacker was required; DoSing one receiver was enough.
//
// The non-blocking send trades at-least-once webhook delivery for the
// availability of authentication, which is the trade this function's
// contract already claimed to make ("best-effort"). Delivery FAILURES
// are still durable via the retry table; enqueue DROPS are not, so the
// caller must make them observable rather than swallow them. The guard
// is deliberately here and not a goroutine-per-event hand-off in Emit:
// unbounded goroutines would move the outage from latency to memory.
//
// Returns the shutdown error when the dispatcher is closed (so we never
// write to a closed channel) and ErrQueueFull when the buffer is full.
func (d *Dispatcher) Enqueue(job *deliveryJob) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return errors.New("webhooks: dispatcher is shut down")
	}
	select {
	case d.jobs <- job:
		return nil
	default:
		return ErrQueueFull
	}
}

// dropLogInterval throttles the saturation warning. The drop is logged
// from the login request goroutine, so an unthrottled per-drop WARN
// would itself add latency to the auth path under exactly the load that
// triggers it — one line per interval is enough to tell an operator the
// queue is saturated.
const dropLogInterval = time.Second

// noteDroppedEnqueue records that a delivery was dropped at the enqueue
// boundary. Silent drops are the thing that makes the availability
// trade above unacceptable; a throttled line makes a saturated queue
// visible without turning observability into the next latency source.
func (d *Dispatcher) noteDroppedEnqueue(webhookID, eventType string, cause error) {
	now := time.Now().UnixNano()
	prev := d.lastDropLog.Load()
	if now-prev < int64(dropLogInterval) {
		return
	}
	// CAS so concurrent request goroutines emit one line between them,
	// not one line each.
	if !d.lastDropLog.CompareAndSwap(prev, now) {
		return
	}
	d.logf("yauth-go webhooks: DROPPED delivery webhook=%s event=%s: %v "+
		"(further drops suppressed for %s)", webhookID, eventType, cause, dropLogInterval)
}

// Shutdown closes the job channel, stops the claimer, and waits for
// workers to drain. Un-claimed retry rows are intentionally left in the
// DB so the next process picks them up. If ctx expires before draining
// completes Shutdown returns ctx.Err() while leaving the workers
// running — they will exit on their own once they finish their current
// HTTP call, and the buffered jobs that were never picked up are
// dropped at process exit.
func (d *Dispatcher) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	alreadyClosed := d.closed
	d.closed = true
	d.mu.Unlock()

	if !alreadyClosed {
		close(d.claimerStop)
	}

	// Wait for the claimer to stop pushing new jobs before we close the
	// jobs channel, otherwise the claimer could race with closeOnce and
	// write to a closed channel.
	select {
	case <-d.claimerDone:
	case <-ctx.Done():
		return ctx.Err()
	}

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

// claimerLoop runs claim cycles until claimerStop is closed. Each cycle
// reads up to ClaimerBatchSize due rows and pushes them onto the worker
// channel. A scan immediately at startup catches retries persisted by a
// prior process; the periodic ticker covers retries scheduled by the
// current process.
func (d *Dispatcher) claimerLoop() {
	defer close(d.claimerDone)
	d.runClaim()
	t := time.NewTicker(d.retry.ClaimerInterval)
	defer t.Stop()
	for {
		select {
		case <-d.claimerStop:
			return
		case <-t.C:
			d.runClaim()
		}
	}
}

// runClaim performs a single claim cycle. Errors are logged and
// swallowed — the next tick will retry. Each claimed row is mapped
// back to the originating webhook (so we can sign with the current
// secret) and pushed onto the job channel. If the webhook has been
// deleted since the retry was scheduled the row is dropped.
func (d *Dispatcher) runClaim() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := d.repo.ClaimDueRetries(ctx, time.Now().UTC(), d.retry.ClaimerBatchSize)
	if err != nil {
		d.logf("yauth-go webhooks: claim due retries: %v\n", err)
		return
	}
	for _, row := range rows {
		hook, err := d.repo.GetWebhookByID(ctx, row.WebhookID)
		if err != nil || hook == nil {
			// Webhook deleted while a retry was queued; drop it silently.
			continue
		}
		var env payloadEnvelope
		if err := json.Unmarshal(row.Payload, &env); err != nil {
			d.logf("yauth-go webhooks: decode retry payload: %v\n", err)
			continue
		}
		job := &deliveryJob{
			webhook:   *hook,
			eventType: row.EventType,
			payload:   env,
			attempt:   row.Attempt,
		}
		if err := d.Enqueue(job); err != nil {
			// ClaimDueRetries DELETES the rows it returns, so a claimed
			// row exists only in this loop. Re-persist it — losing a
			// claimed-but-not-enqueued row would silently drop a
			// delivery — and `continue` rather than `return`: bailing
			// out abandoned every REMAINING row in the batch (up to
			// ClaimerBatchSize-1, default 100). That only bit at
			// shutdown before; now that ErrQueueFull is a routine
			// return value, every saturated claim cycle would have
			// destroyed already-persisted retries. The availability fix
			// must not buy itself a durability bug.
			notBefore := row.NotBefore
			if errors.Is(err, ErrQueueFull) {
				// Saturation is transient but not instantaneous. Keep
				// the original (already-due) not_before and the very
				// next tick re-claims and re-writes the same rows in a
				// hot loop; push it out one interval instead.
				notBefore = time.Now().UTC().Add(d.retry.ClaimerInterval)
			}
			d.repersist(ctx, job, notBefore)
			continue
		}
	}
}

// repersist writes a retry row back to the repo at the supplied
// not_before. Used when a claim succeeds but Enqueue fails — because
// the dispatcher is shutting down (not_before unchanged, the next
// process picks it up when it was already due) or because the delivery
// queue is saturated (not_before deferred one claimer interval).
func (d *Dispatcher) repersist(ctx context.Context, job *deliveryJob, notBefore time.Time) {
	body, err := json.Marshal(job.payload)
	if err != nil {
		return
	}
	_ = d.repo.CreateScheduledRetry(ctx, domain.NewScheduledWebhookRetry{
		ID:        uuid.NewString(),
		WebhookID: job.webhook.ID,
		EventType: job.eventType,
		Payload:   body,
		Attempt:   job.attempt,
		NotBefore: notBefore.UTC(),
		CreatedAt: time.Now().UTC(),
	})
}

// worker pulls jobs off the channel until it is closed. Each delivery
// is a single HTTP attempt; the worker classifies the outcome and
// either persists a ScheduledWebhookRetry row for later pickup or
// records a dead-letter delivery. The worker itself never blocks on
// backoff — that's the claimer's job — keeping the pool responsive
// under heavy retry load.
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
		d.scheduleRetry(context.Background(), job)
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
	rawSecret, legacy, err := decryptSecret(d.secretKey, job.webhook.Secret)
	if err != nil {
		d.recordDelivery(ctx, job, body, nil, fmt.Sprintf("decrypt secret: %v", err), false)
		return deliveryOutcome{success: false, retryable: false}
	}
	// A cleartext row reaching dispatch after the startup sweep means one was
	// written by another process (an older build, or a direct DB insert). Say
	// so — the whole point of this change is that plaintext is never silent.
	if legacy && len(d.secretKey) > 0 {
		d.logf("webhooks: webhook %s has a signing secret stored in CLEARTEXT; it will be "+
			"re-encrypted on the next restart, but treat it as disclosed and rotate it",
			job.webhook.ID)
	}
	signature := signPayload(rawSecret, body)

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

	// Drain (bounded) so the connection can be reused — but do NOT keep the
	// bytes. Persisting the receiver's response body is what turned a blind
	// SSRF into a read primitive: whatever an internal endpoint answered was
	// written to yauth_webhook_deliveries.response_body and served straight
	// back on GET /webhooks/{id}/deliveries. The status code is the whole of
	// what an operator needs to diagnose a delivery, and recordDelivery maps
	// "" to NULL, so the column simply goes empty.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody+1))

	status := int16(resp.StatusCode)
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	note := ""
	if !success {
		note = fmt.Sprintf("receiver returned %d", resp.StatusCode)
	}
	d.recordDelivery(ctx, job, body, &status, note, success)

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

// scheduleRetry computes the delay for the next attempt and persists a
// ScheduledWebhookRetry row with not_before = now + delay. The claimer
// will pick it up once due. Persistence is what makes this crash-safe:
// killing the process between deliver() and the next attempt no longer
// loses the retry — the row sits in the DB until any dispatcher claims it.
func (d *Dispatcher) scheduleRetry(ctx context.Context, job *deliveryJob) {
	delay := d.backoffFor(job.attempt)
	body, err := json.Marshal(job.payload)
	if err != nil {
		d.logf("yauth-go webhooks: marshal retry payload: %v\n", err)
		return
	}
	now := time.Now().UTC()
	if err := d.repo.CreateScheduledRetry(ctx, domain.NewScheduledWebhookRetry{
		ID:        uuid.NewString(),
		WebhookID: job.webhook.ID,
		EventType: job.eventType,
		Payload:   body,
		Attempt:   job.attempt,
		NotBefore: now.Add(delay),
		CreatedAt: now,
	}); err != nil {
		d.logf("yauth-go webhooks: persist retry: %v\n", err)
	}
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
