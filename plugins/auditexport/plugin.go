package auditexport

import (
	"github.com/danielgtaylor/huma/v2"

	"context"
	"net/http"
	"sync"
	"time"

	"github.com/yackey-labs/yauth/domain"
	pluginpkg "github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
)

// Config tunes plugin behaviour. Zero value yields safe defaults that
// mirror the Rust PR #106 AuditExportConfig.
type Config struct {
	// BatchSize is the maximum number of outbox rows a single drain pass
	// claims per destination. Defaults to 100.
	BatchSize int
	// BatchInterval is the worker poll cadence. Defaults to 5s.
	BatchInterval time.Duration
	// MaxInflight caps the number of concurrent dispatch goroutines per
	// destination. Defaults to 4.
	MaxInflight int
	// RetryMaxAttempts is the failure count at which a row transitions
	// to dead_letter. Defaults to 5 (1s, 5s, 30s, 5m, 1h backoff).
	RetryMaxAttempts int32
	// HTTPTimeout is the per-attempt HTTP request timeout used by the
	// webhook dispatcher. Defaults to 10s.
	HTTPTimeout time.Duration
	// SignatureWindow is the max accepted timestamp drift on the
	// receiver side. The dispatcher signs every webhook with the current
	// time; this value is propagated to VerifyHMACSignature in tests and
	// docs. Defaults to 5 minutes (Stripe-style).
	SignatureWindow time.Duration

	// HTTPClient overrides the dispatcher's HTTP client. Tests inject a
	// client whose Transport routes to httptest.NewServer; production
	// callers should leave this nil.
	HTTPClient *http.Client

	// TestHooks attaches dispatch observability hooks. Production code
	// MUST leave this nil — TestHooks is not part of the public API
	// stability guarantee.
	TestHooks *TestHooks
}

func (c *Config) applyDefaults() {
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	if c.BatchInterval <= 0 {
		c.BatchInterval = 5 * time.Second
	}
	if c.MaxInflight <= 0 {
		c.MaxInflight = 4
	}
	if c.RetryMaxAttempts <= 0 {
		c.RetryMaxAttempts = 5
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 10 * time.Second
	}
	if c.SignatureWindow <= 0 {
		c.SignatureWindow = 5 * time.Minute
	}
}

// plugin is the unexported implementation of pluginpkg.Plugin.
type plugin struct {
	cfg        Config
	store      *store
	dispatcher *Dispatcher
	metrics    *Metrics
	auditRepo  repo.AuditLogRepository

	host pluginpkg.PluginHost

	mu      sync.Mutex
	workers map[string]*WorkerHandle
}

// New constructs the audit-export plugin.
func New(cfg Config) pluginpkg.Plugin {
	cfg.applyDefaults()
	p := &plugin{
		cfg:     cfg,
		store:   newStore(),
		metrics: NewMetrics(),
		workers: make(map[string]*WorkerHandle),
	}
	disp := NewDispatcher(cfg.HTTPTimeout, cfg.SignatureWindow)
	if cfg.HTTPClient != nil {
		disp = disp.WithHTTPClient(cfg.HTTPClient)
	}
	if cfg.TestHooks != nil {
		disp = disp.WithTestHooks(cfg.TestHooks)
	}
	p.dispatcher = disp
	return p
}

// Name implements plugin.Plugin.
func (p *plugin) Name() string { return "audit-export" }

// Routes implements plugin.Plugin. Registers admin CRUD endpoints,
// spawns one worker per active destination, and registers the audit
// recorder that fans every audit row the host writes for an emitted
// AuthEvent through EnqueueForAudit, so the outbox stays in sync with
// audit-log writes.
func (p *plugin) Routes(host pluginpkg.PluginHost, mux pluginpkg.Router, api huma.API, prefix string) {
	p.host = host
	p.auditRepo = host.Repo()
	mw := host.Middleware()

	// Every route is huma-native: a typed operation guarded by
	// RequireAdminHuma, with StashHTTPHuma threading the underlying
	// *http.Request onto the operation ctx so the ported handlers keep
	// byte-identical request parsing (strict body decode via decodeJSON,
	// custom scope/limit query precedence). The resolved admin identity is
	// recovered from the operation ctx (NOT the stashed request), so actor
	// attribution in auditEvent stays correct.
	_ = mux // routes are huma-native; the raw mux is no longer used here.

	// Deployment-wide admin endpoints.
	p.registerCreate(api, mw, prefix, prefix+"/audit/destinations", "auditExport-create-destination", false)
	p.registerList(api, mw, prefix, prefix+"/audit/destinations", "auditExport-list-destinations", false)
	p.registerGet(api, mw, prefix)
	p.registerUpdate(api, mw, prefix, prefix+"/audit/destinations/{id}", http.MethodPatch, "auditExport-patch-destination", false)
	p.registerUpdate(api, mw, prefix, prefix+"/audit/destinations/{id}", http.MethodPut, "auditExport-put-destination", false)
	p.registerDelete(api, mw, prefix, prefix+"/audit/destinations/{id}", "auditExport-delete-destination", false)
	p.registerOutbox(api, mw, prefix)
	p.registerReplay(api, mw, prefix)

	// Per-organization admin endpoints. The {org_id} path parameter scopes
	// the CRUD to that org.
	p.registerCreate(api, mw, prefix, prefix+"/organizations/{org_id}/audit/destinations", "auditExport-org-create-destination", true)
	p.registerList(api, mw, prefix, prefix+"/organizations/{org_id}/audit/destinations", "auditExport-org-list-destinations", true)
	p.registerUpdate(api, mw, prefix, prefix+"/organizations/{org_id}/audit/destinations/{id}", http.MethodPatch, "auditExport-org-patch-destination", true)
	p.registerUpdate(api, mw, prefix, prefix+"/organizations/{org_id}/audit/destinations/{id}", http.MethodPut, "auditExport-org-put-destination", true)
	p.registerDelete(api, mw, prefix, prefix+"/organizations/{org_id}/audit/destinations/{id}", "auditExport-org-delete-destination", true)

	// Audit recorder — yauth writes the audit row for every emitted
	// AuthEvent inside Emit (see the host's audit_events.go) and hands us
	// the row id, which is exactly what the outbox needs and exactly what
	// an events.Handler could never learn. Registering here rather than at
	// New() because the host handle only exists from Routes onward.
	//
	// The capability is optional so a host that predates it still builds;
	// on such a host the outbox simply carries only the rows this plugin's
	// own routes enqueue, which is the pre-existing behaviour.
	if reg, ok := host.(pluginpkg.AuditRecorderRegistrar); ok {
		reg.RegisterAuditRecorder(p.recordAudit)
	}

	// Spawn workers for already-registered destinations. New destinations
	// created via the admin API can be wired up by calling Refresh, or
	// the operator may run a SIGHUP cycle.
	p.spawnWorkersForActive()
}

// Shutdown implements plugin.ShutdownAware. Drains every running worker
// with a per-worker timeout slice of ctx's deadline (or 10s if none).
func (p *plugin) Shutdown(ctx context.Context) error {
	timeout := 10 * time.Second
	if d, ok := ctx.Deadline(); ok {
		if remaining := time.Until(d); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	p.mu.Lock()
	handles := make([]*WorkerHandle, 0, len(p.workers))
	for _, h := range p.workers {
		handles = append(handles, h)
	}
	p.workers = map[string]*WorkerHandle{}
	p.mu.Unlock()
	for _, h := range handles {
		_ = h.Shutdown(timeout)
	}
	return nil
}

// Refresh spawns workers for newly-active destinations and tears down
// those whose destination has been deleted or disabled. Callers may
// invoke this after creating a destination at runtime to start its
// drain loop without restarting the process.
func (p *plugin) Refresh() ShutdownReport {
	report := p.spawnWorkersForActive()
	return report
}

// ShutdownReport reports clean vs forced worker shutdowns.
type ShutdownReport struct {
	Clean  int
	Forced int
}

func (p *plugin) spawnWorkersForActive() ShutdownReport {
	active := domain.DestinationStatus("active")
	rows := p.store.ListDestinations(ListDestinationFilter{Status: &active})
	p.mu.Lock()
	defer p.mu.Unlock()
	want := make(map[string]struct{}, len(rows))
	for _, d := range rows {
		want[d.ID] = struct{}{}
		if _, running := p.workers[d.ID]; running {
			continue
		}
		h := SpawnWorker(WorkerConfig{
			DestinationID:    d.ID,
			BatchSize:        p.cfg.BatchSize,
			BatchInterval:    p.cfg.BatchInterval,
			MaxInflight:      p.cfg.MaxInflight,
			RetryMaxAttempts: p.cfg.RetryMaxAttempts,
		}, p.store, p.auditRepo, p.dispatcher, p.metrics)
		p.workers[d.ID] = h
	}
	// Tear down workers for destinations that no longer exist or aren't active.
	report := ShutdownReport{}
	for id, h := range p.workers {
		if _, ok := want[id]; ok {
			continue
		}
		delete(p.workers, id)
		if h.Shutdown(2 * time.Second) {
			report.Clean++
		} else {
			report.Forced++
		}
	}
	return report
}

// WorkerCount returns the number of running drain workers.
func (p *plugin) WorkerCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.workers)
}

// Store returns the in-memory store backing the plugin. Tests use this
// to seed destinations and inspect outbox rows directly; production
// callers should drive everything via the admin endpoints.
func (p *plugin) Store() *store { return p.store }

// Dispatcher returns the dispatcher instance. Tests use this to invoke
// SendOne directly.
func (p *plugin) Dispatcher() *Dispatcher { return p.dispatcher }

// Metrics returns the metrics handle for in-process assertion.
func (p *plugin) Metrics() *Metrics { return p.metrics }

// Compile-time interface conformance.
var (
	_ pluginpkg.Plugin        = (*plugin)(nil)
	_ pluginpkg.ShutdownAware = (*plugin)(nil)
)

// recordAudit is the plugin.AuditRecorder the host calls immediately after
// committing the audit row for an emitted AuthEvent. It enqueues one outbox
// entry per destination whose scope matches (deployment-wide, or the event's
// organization), which is what makes a login success, a login failure, a
// logout or a password change reach a webhook / syslog / S3 destination.
//
// It never blocks the auth flow and returns nothing: enqueue failures are
// the store's problem, and a login must not fail because an exporter is
// unhappy.
func (p *plugin) recordAudit(ctx context.Context, auditLogID string, organizationID *string) {
	_ = ctx
	if auditLogID == "" {
		return
	}
	p.store.EnqueueForAudit(auditLogID, organizationID)
}

// EnqueueForAudit is the public outbox-enqueue hook. Callers writing
// audit-log rows directly (via host.Repo().LogAuditEvent) should call
// this immediately after a successful insert with the same audit-log
// ID + organization scope. The plugin's store mutex spans the matching
// scan and the row inserts, so the "outbox transactional" invariant
// holds for memory-backend semantics: a destination active at the
// moment of enqueue receives an outbox row, and destinations added
// afterward do not retroactively pick up the event.
//
// Returns the IDs of the newly-created outbox rows; an empty slice
// means no destination matched (deployment-wide + matching-org).
func (p *plugin) EnqueueForAudit(auditLogID string, organizationID *string) []string {
	return p.store.EnqueueForAudit(auditLogID, organizationID)
}
