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
	"context"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/plugin"
)

const (
	defaultWorkerCount     = 4
	defaultDeliveryTimeout = 10 * time.Second
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
	return &webhooksPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *webhooksPlugin) Name() string { return "webhooks" }

// Routes implements plugin.Plugin. It starts the dispatcher's worker
// goroutines, registers the events.Handler that fans events out to it,
// and mounts admin endpoints under prefix guarded by RequireAdmin.
func (p *webhooksPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	mw := host.Middleware()

	httpClient := p.cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: p.cfg.DeliveryTimeout}
	}

	p.dispatcher = NewDispatcher(host.Repo(), httpClient, p.cfg.WorkerCount)
	p.dispatcher.Start()

	host.RegisterEventHandler(newEventHandler(host.Repo(), p.dispatcher))

	mux.Handle("GET "+prefix+"/webhooks", mw.RequireAdmin(http.HandlerFunc(p.handleList(host))))
	mux.Handle("POST "+prefix+"/webhooks", mw.RequireAdmin(http.HandlerFunc(p.handleCreate(host))))
	mux.Handle("GET "+prefix+"/webhooks/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleGet(host))))
	mux.Handle("PATCH "+prefix+"/webhooks/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleUpdate(host))))
	mux.Handle("DELETE "+prefix+"/webhooks/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleDelete(host))))
	mux.Handle("GET "+prefix+"/webhooks/{id}/deliveries", mw.RequireAdmin(http.HandlerFunc(p.handleDeliveries(host))))
	mux.Handle("POST "+prefix+"/webhooks/{id}/test", mw.RequireAdmin(http.HandlerFunc(p.handleTest(host))))
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
