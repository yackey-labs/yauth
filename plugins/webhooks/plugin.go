// Package webhooks implements the outbound-webhook plugin for yauth-go.
//
// Operators register webhooks via admin endpoints; the plugin signs every
// AuthEvent with the per-webhook HMAC secret and POSTs it to the
// configured URL asynchronously through a worker pool.
//
// Routes registered by Plugin.Routes (relative to the prefix, all admin):
//
//	GET    {prefix}/webhooks                — list webhooks
//	POST   {prefix}/webhooks                — create webhook (one-time secret in response)
//	GET    {prefix}/webhooks/{id}           — fetch one webhook
//	PATCH  {prefix}/webhooks/{id}           — update url/events/active, optionally rotate secret
//	PUT    {prefix}/webhooks/{id}           — alias for PATCH (Rust parity)
//	DELETE {prefix}/webhooks/{id}           — delete webhook
//	GET    {prefix}/webhooks/{id}/deliveries — recent delivery attempts
//	POST   {prefix}/webhooks/{id}/test      — fire a synthetic webhook.test event
//
// Lifecycle: Routes() starts the dispatcher; YAuth.Shutdown(ctx) drains
// pending jobs by closing the channel and waiting for workers to finish
// in-flight HTTP calls. Once Shutdown returns, no further events will be
// dispatched even if more arrive at the registered events.Handler.
package webhooks

import (
	"github.com/danielgtaylor/huma/v2"

	"context"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/plugin"
)

const (
	defaultWorkerCount       = 4
	defaultDeliveryTimeout   = 10 * time.Second
	defaultMaxAttempts       = 5
	defaultInitialBackoff    = 1 * time.Second
	defaultMaxBackoff        = 5 * time.Minute
	defaultBackoffJitter     = 0.2
	defaultDeadLetterEnabled = true
	defaultClaimerInterval   = 1 * time.Second
	defaultClaimerBatchSize  = 100
)

// Config tunes plugin behaviour. Zero value yields safe defaults.
type Config struct {
	// WorkerCount is the number of goroutines draining the delivery
	// channel. Defaults to 4.
	WorkerCount int

	// DeliveryTimeout is the per-attempt HTTP timeout. Defaults to 10s.
	DeliveryTimeout time.Duration

	// HTTPClient overrides the default *http.Client used for delivery.
	// When nil, a client with Timeout=DeliveryTimeout is constructed.
	// Tests can inject a client whose Transport routes to httptest.
	HTTPClient *http.Client

	// MaxAttempts is the maximum number of delivery attempts per job
	// before the dispatcher gives up. Defaults to 5.
	MaxAttempts int

	// InitialBackoff is the delay before the second attempt; subsequent
	// attempts double up to MaxBackoff. Defaults to 1s.
	InitialBackoff time.Duration

	// MaxBackoff caps the per-attempt backoff. Defaults to 5m.
	MaxBackoff time.Duration

	// BackoffJitter is the +/- proportion applied to each backoff
	// (0.2 → ±20%). Defaults to 0.2. Set <0 to disable jitter.
	BackoffJitter float64

	// DeadLetterEnabled controls whether a final dead-letter delivery
	// row is persisted when MaxAttempts is exhausted without success.
	// Pointer so the zero value can default to true. Set to a pointer
	// to false to disable.
	DeadLetterEnabled *bool

	// ClaimerInterval is how often the claimer goroutine scans the
	// retry queue for due rows. Defaults to 1s. Lower values reduce
	// retry latency; higher values reduce DB load.
	ClaimerInterval time.Duration

	// ClaimerBatchSize caps the number of retries a single claim cycle
	// pulls from the queue. Defaults to 100. Larger batches amortise
	// the round-trip but bound the worst-case stall on shutdown.
	ClaimerBatchSize int
}

// webhooksPlugin is an unexported implementation of plugin.Plugin and
// plugin.ShutdownAware.
type webhooksPlugin struct {
	cfg        Config
	dispatcher *Dispatcher
}

// New constructs the webhooks plugin.
func New(cfg Config) plugin.Plugin {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = defaultWorkerCount
	}
	if cfg.DeliveryTimeout <= 0 {
		cfg.DeliveryTimeout = defaultDeliveryTimeout
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = defaultInitialBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.BackoffJitter == 0 {
		cfg.BackoffJitter = defaultBackoffJitter
	} else if cfg.BackoffJitter < 0 {
		cfg.BackoffJitter = 0
	}
	if cfg.DeadLetterEnabled == nil {
		v := defaultDeadLetterEnabled
		cfg.DeadLetterEnabled = &v
	}
	if cfg.ClaimerInterval <= 0 {
		cfg.ClaimerInterval = defaultClaimerInterval
	}
	if cfg.ClaimerBatchSize <= 0 {
		cfg.ClaimerBatchSize = defaultClaimerBatchSize
	}
	return &webhooksPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *webhooksPlugin) Name() string { return "webhooks" }

// Routes implements plugin.Plugin. It starts the dispatcher's worker
// goroutines, registers the events.Handler that fans events out to it,
// and mounts admin endpoints under prefix guarded by RequireAdmin.
func (p *webhooksPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	httpClient := p.cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: p.cfg.DeliveryTimeout}
	}

	p.dispatcher = NewDispatcher(host.Repo(), httpClient, p.cfg.WorkerCount, RetryConfig{
		MaxAttempts:       p.cfg.MaxAttempts,
		InitialBackoff:    p.cfg.InitialBackoff,
		MaxBackoff:        p.cfg.MaxBackoff,
		BackoffJitter:     p.cfg.BackoffJitter,
		DeadLetterEnabled: *p.cfg.DeadLetterEnabled,
		ClaimerInterval:   p.cfg.ClaimerInterval,
		ClaimerBatchSize:  p.cfg.ClaimerBatchSize,
	}, deriveWebhookKey(host.JWTSecret()))
	p.dispatcher.Start()

	host.RegisterEventHandler(newEventHandler(host.Repo(), p.dispatcher))

	// Every management route is huma-native: a typed operation guarded by
	// RequireAdminHuma (the same admin identity logic as the legacy
	// mw.RequireAdmin wrapper). The list/create/update/deliveries routes
	// additionally pair with StashHTTPHuma so the ported handlers keep
	// byte-identical request parsing — the lenient ?page=/?per_page= query
	// precedence on the GET lists and the strict DisallowUnknownFields body
	// decode on create/update. The mux is retained in the signature for plugins
	// that still register raw net/http routes; webhooks no longer uses it.
	p.registerList(host, api, mw, prefix)
	p.registerCreate(host, api, mw, prefix)
	p.registerGet(host, api, mw, prefix)
	// PATCH and its PUT alias (Rust parity) share one handler but need
	// distinct OperationIDs — huma requires operation-id uniqueness.
	p.registerUpdate(host, api, mw, prefix, http.MethodPatch, "webhook-update")
	p.registerUpdate(host, api, mw, prefix, http.MethodPut, "webhook-put")
	p.registerDelete(host, api, mw, prefix)
	p.registerDeliveries(host, api, mw, prefix)
	p.registerTest(host, api, mw, prefix)
}

// Shutdown implements plugin.ShutdownAware. It signals the dispatcher to
// stop accepting new jobs, waits for in-flight workers to drain, and
// returns ctx.Err() if the context expires first.
func (p *webhooksPlugin) Shutdown(ctx context.Context) error {
	if p.dispatcher == nil {
		return nil
	}
	return p.dispatcher.Shutdown(ctx)
}

// Compile-time interface conformance.
var (
	_ plugin.Plugin        = (*webhooksPlugin)(nil)
	_ plugin.ShutdownAware = (*webhooksPlugin)(nil)
)
