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

	"github.com/yackey-labs/yauth/auth/safehttp"
	"github.com/yackey-labs/yauth/plugin"
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
	// EncryptionKey is the key material webhook signing secrets are
	// encrypted at rest with (AES-256-GCM; the AES key is derived from it
	// via HKDF-SHA256, so any length is accepted — 32+ bytes recommended).
	//
	// When empty the plugin falls back to PluginHost.JWTSecret(), which is
	// what it has always used. That fallback is only populated when the
	// bearer plugin is configured (or yauth.Builder.WithJWTSecret is called
	// by hand), so a deployment running webhooks WITHOUT bearer had no key
	// at all — and every HMAC signing secret was written to
	// yauth_webhooks.secret in cleartext, silently, with a read-side
	// pass-through that made the rows indistinguishable from encrypted ones.
	//
	// With NEITHER source available the plugin now refuses to persist a
	// secret: POST /webhooks and a secret-rotating PATCH/PUT fail with 500,
	// and Routes() logs an ERROR at startup. Set this (or a JWT secret) to
	// run webhooks at all.
	EncryptionKey []byte

	// WorkerCount is the number of goroutines draining the delivery
	// channel. Defaults to 4.
	WorkerCount int

	// DeliveryTimeout is the per-attempt HTTP timeout. Defaults to 10s.
	DeliveryTimeout time.Duration

	// HTTPClient overrides the default *http.Client used for delivery.
	// When nil, a client with Timeout=DeliveryTimeout is constructed.
	// Tests can inject a client whose Transport routes to httptest.
	HTTPClient *http.Client

	// AllowPrivateDestinations opts INTO registering and delivering to
	// webhook receivers on loopback / RFC 1918 addresses.
	//
	// A webhook URL is chosen by a deployment admin over the admin API and is
	// then dialled by the server on every matching auth event, with the
	// response recorded. That makes an unfiltered destination an SSRF
	// primitive aimed at anything the process can reach — the cloud metadata
	// service, a database port bound to loopback, an internal admin UI. So the
	// default (false) refuses private destinations both at create time and,
	// for rows that predate the guard, at dial time.
	//
	// Deployments that ship webhooks to an in-cluster collector or a sidecar
	// need private egress and should set this. It is not a full bypass: the
	// link-local range (169.254.0.0/16 — the instance metadata service) stays
	// refused, because that is never the destination an operator meant. See
	// auth/safehttp.
	AllowPrivateDestinations bool

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

// encryptionKey resolves the AES key used for webhook secrets at rest:
// Config.EncryptionKey when set, otherwise the host's JWT secret (the
// historical source). Returns nil when neither is available — callers must
// treat nil as "cannot store a secret", never as plaintext mode.
func (p *webhooksPlugin) encryptionKey(host plugin.PluginHost) []byte {
	if len(p.cfg.EncryptionKey) > 0 {
		return deriveWebhookKey(p.cfg.EncryptionKey)
	}
	return deriveWebhookKey(host.JWTSecret())
}

// Routes implements plugin.Plugin. It starts the dispatcher's worker
// goroutines, registers the events.Handler that fans events out to it,
// and mounts admin endpoints under prefix guarded by RequireAdmin.
func (p *webhooksPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()
	key := p.encryptionKey(host)

	// Say it once, loudly, at startup rather than never. Without a key the
	// plugin still runs — existing webhooks keep delivering — but no new
	// secret can be stored, so the operator needs to know before the first
	// POST /webhooks fails.
	if len(key) == 0 {
		host.Logger().Error("webhooks: no encryption key configured — webhook signing secrets " +
			"cannot be stored and creating or rotating a webhook secret will fail. Set " +
			"webhooks.Config.EncryptionKey, or configure the bearer plugin / " +
			"yauth.Builder.WithJWTSecret. Any secrets already stored in cleartext stay that way " +
			"until a key is available.")
	} else {
		// A key exists: bring any rows still holding cleartext (written
		// before encryption, or by the plaintext fallback that used to sit
		// in encryptSecret) up to the current format.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		migrated, err := migrateLegacySecrets(ctx, host.Repo(), key)
		cancel()
		if err != nil {
			host.Logger().Error("webhooks: could not re-encrypt legacy plaintext webhook secrets; "+
				"they remain in cleartext in yauth_webhooks.secret", "error", err, "migrated", migrated)
		} else if migrated > 0 {
			host.Logger().Warn("webhooks: re-encrypted webhook signing secrets that were stored "+
				"in cleartext. Treat them as disclosed and rotate them.", "count", migrated)
		}
	}

	httpClient := p.cfg.HTTPClient
	if httpClient == nil {
		// safehttp.Client still wraps the transport in otelhttp (so each
		// delivery emits a CLIENT span and propagates the W3C traceparent),
		// but adds the two things this client used to be missing:
		//
		//   - a dial-time private-address filter, which is what refuses a
		//     destination row written before this guard existed, or a
		//     hostname that only resolves privately at delivery time; and
		//   - a redirect policy. CheckRedirect used to be nil, so Go followed
		//     up to 10 hops: a receiver answering 302 turned the signed POST
		//     into a GET (exactly what IMDSv1 requires) and Go carried every
		//     header except Authorization and Cookie across the hop — so
		//     X-YAuth-Signature, computed with the deployment's secret,
		//     travelled to whatever host the receiver named. maxRedirects=0
		//     means the 3xx is recorded as the delivery outcome instead.
		//
		// A caller-supplied HTTPClient is still used verbatim: operators who
		// bring their own transport (proxy, mTLS) own its policy.
		httpClient = safehttp.Client(p.cfg.AllowPrivateDestinations, p.cfg.DeliveryTimeout, 0)
	}

	p.dispatcher = NewDispatcher(host.Repo(), httpClient, p.cfg.WorkerCount, RetryConfig{
		MaxAttempts:       p.cfg.MaxAttempts,
		InitialBackoff:    p.cfg.InitialBackoff,
		MaxBackoff:        p.cfg.MaxBackoff,
		BackoffJitter:     p.cfg.BackoffJitter,
		DeadLetterEnabled: *p.cfg.DeadLetterEnabled,
		ClaimerInterval:   p.cfg.ClaimerInterval,
		ClaimerBatchSize:  p.cfg.ClaimerBatchSize,
	}, key)
	p.dispatcher.useLogger(host.Logger())
	p.dispatcher.Start()

	host.RegisterEventHandler(newEventHandler(host.Repo(), p.dispatcher))

	// Every management route is huma-native: a typed operation guarded by
	// RequireAdminHuma (the same admin identity logic as the legacy
	// mw.RequireAdmin wrapper). Create/update carry a native typed Body, so
	// huma parses + validates the request and the OpenAPI request schema
	// auto-derives; additionalProperties:false rejects unknown fields (422).
	// Only the list/deliveries routes still pair with StashHTTPHuma, and solely
	// to keep the lenient ?page=/?per_page= query precedence (bad values degrade
	// to defaults rather than 422). The mux is retained in the signature for
	// plugins that still register raw net/http routes; webhooks no longer uses it.
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
