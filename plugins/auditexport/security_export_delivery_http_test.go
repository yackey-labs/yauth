// security_export_delivery_http_test.go — the two halves of the audit-export
// delivery finding that only show up through the admin HTTP surface, which is
// the only way an operator ever creates a destination.
//
// 1. NO DESTINATION CREATED THROUGH THE API EVER GETS A DRAIN WORKER.
//    plugin.Routes calls spawnWorkersForActive() exactly once, at router build
//    time, when the destination store (an in-process map, newStore()) is still
//    empty. createDo / updateDo / deleteDo (routes.go) never touch the worker
//    map, and Refresh() has no non-test caller anywhere in the module. So on a
//    real deployment WorkerCount() is 0 forever: an admin POSTs a webhook
//    destination, the API answers 201, GET reports it "active", the outbox
//    fills up — and nothing is ever exported. The store-level tests all pass
//    because they seed p.store directly and then call Refresh(); this file goes
//    through the route, which is the path an operator actually uses.
//
// 2. A READ-EDIT-PATCH SILENTLY UNSIGNS THE STREAM. toResponse returns
//    sanitizeConfig(), which strips hmac_secret / hec_token / api_key and every
//    header.* entry, while updateDo assigns changes.Config = req.Config and
//    store.UpdateDestination REPLACES row.Config wholesale. The ordinary console
//    flow — GET the destination, change one field, PATCH the object back —
//    therefore deletes the HMAC secret and every static auth header the operator
//    configured. hmac_configured flips to false, the webhooks keep flowing with
//    no X-Yauth-Signature, and the receiver's VerifyHMACSignature now has an
//    unsigned, unauthenticated audit stream it cannot distinguish from a forged
//    one. Nothing warns.
//
// Both tests are paired with POSITIVE CONTROLS: an explicitly-Refreshed
// destination must still deliver (so a "fix" cannot pass by breaking export),
// a PATCH that names no config must keep signing, a genuine re-point must still
// take effect, and a PATCH whose effective config points at the metadata
// service must still be refused 400 by the #108 egress guard.
package auditexport_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/auditexport"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// workerIntrospect is the plugin's own test surface, reached through an
// interface because New() returns plugin.Plugin over an unexported type.
type workerIntrospect interface {
	WorkerCount() int
	Refresh() auditexport.ShutdownReport
}

// newDeliveryEnv is newRouteEnv with two changes the delivery tests need: a
// caller-supplied auditexport.Config (short batch interval, and the in-cluster
// AllowPrivateDestinations opt-in that lets a 127.0.0.1 httptest receiver stand
// in for a collector), and a handle on the plugin so WorkerCount is observable.
func newDeliveryEnv(t *testing.T, cfg auditexport.Config) (*routeEnv, workerIntrospect) {
	t.Helper()
	r := memrepo.New()
	pl := auditexport.New(cfg)

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).WithPlugin(pl).Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)

	wi, ok := pl.(workerIntrospect)
	if !ok {
		t.Fatalf("plugin does not expose WorkerCount/Refresh: %T", pl)
	}
	// The drain workers these tests deliberately start must not outlive them:
	// stop them before the collector's server goes away.
	return &routeEnv{srv: srv, repo: r, stop: func() { shutdownPlugin(t, pl); srv.Close() }}, wi
}

// collector records every request an export destination delivers to it.
type collector struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []http.Header
	bodys [][]byte
}

func newCollector() *collector {
	c := &collector{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 8192)
		n, _ := r.Body.Read(buf)
		body := make([]byte, n)
		copy(body, buf[:n])
		c.mu.Lock()
		c.reqs = append(c.reqs, r.Header.Clone())
		c.bodys = append(c.bodys, body)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return c
}

func (c *collector) URL() string { return c.srv.URL + "/hook" }
func (c *collector) Close()      { c.srv.Close() }
func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reqs)
}
func (c *collector) last() (http.Header, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reqs) == 0 {
		return nil, nil
	}
	return c.reqs[len(c.reqs)-1], c.bodys[len(c.bodys)-1]
}

// waitForDelivery polls until the collector has at least n requests.
func (c *collector) waitForDelivery(n int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if c.count() >= n {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c.count() >= n
}

func createViaAPI(t *testing.T, env *routeEnv, tok string, body map[string]any) map[string]any {
	t.Helper()
	res := env.do(t, http.MethodPost, "/api/auth/audit/destinations", tok, body)
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create destination: want 201, got %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return out
}

func getDestination(t *testing.T, env *routeEnv, tok, id string) map[string]any {
	t.Helper()
	res := env.do(t, http.MethodGet, "/api/auth/audit/destinations/"+id, tok, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get destination: want 200, got %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	return out
}

func deliveryConfig() auditexport.Config {
	return auditexport.Config{
		BatchInterval: 20 * time.Millisecond,
		// The collector is an httptest server on 127.0.0.1 — the in-cluster
		// deployment shape, opted into exactly as such a deployment does. The
		// #108 dial-time guard stays on for everyone else.
		AllowPrivateDestinations: true,
	}
}

// TestAuditExport_DestinationCreatedViaAPI_GetsAWorker is the headline finding:
// the only supported way to create a destination produces a destination that
// exports nothing, forever.
func TestAuditExport_DestinationCreatedViaAPI_GetsAWorker(t *testing.T) {
	env, plug := newDeliveryEnv(t, deliveryConfig())
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	recv := newCollector()
	defer recv.Close()

	created := createViaAPI(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"format": "json",
		"config": map[string]string{"url": recv.URL(), "hmac_secret": "s3cret"},
	})
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("create returned no id")
	}

	if got := plug.WorkerCount(); got != 1 {
		t.Errorf("a destination created through the admin API got no drain worker: WorkerCount()=%d, want 1", got)
	}

	// The create wrote its own audit-log row (audit_export.destination.created)
	// and enqueued an outbox entry for this destination, so a running worker
	// delivers within a couple of batch intervals.
	if !recv.waitForDelivery(1, 2*time.Second) {
		t.Errorf("destination created through the admin API exported nothing in 2s (deliveries: %d)", recv.count())
	}

	// POSITIVE CONTROL: everything downstream of the missing spawn call works —
	// once a worker exists the very same destination delivers. This is what
	// isolates the defect to "no worker is ever started", and it is what a fix
	// must not regress.
	plug.Refresh()
	if got := plug.WorkerCount(); got != 1 {
		t.Fatalf("POSITIVE CONTROL: Refresh() did not start a worker: WorkerCount()=%d", got)
	}
	if !recv.waitForDelivery(1, 3*time.Second) {
		t.Fatalf("POSITIVE CONTROL: destination still exported nothing after Refresh() (deliveries: %d)", recv.count())
	}
}

// TestAuditExport_DeleteTearsDownWorker: a deleted destination must not keep a
// drain worker polling for it.
func TestAuditExport_DeleteTearsDownWorker(t *testing.T) {
	env, plug := newDeliveryEnv(t, deliveryConfig())
	defer env.stop()
	tok, _ := env.seedAdmin(t)
	recv := newCollector()
	defer recv.Close()

	created := createViaAPI(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"config": map[string]string{"url": recv.URL()},
	})
	id := created["id"].(string)

	// Start from the state a working deployment would be in.
	plug.Refresh()
	if got := plug.WorkerCount(); got != 1 {
		t.Fatalf("setup: want 1 worker, got %d", got)
	}

	res := env.do(t, http.MethodDelete, "/api/auth/audit/destinations/"+id, tok, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", res.StatusCode)
	}
	if got := plug.WorkerCount(); got != 0 {
		t.Errorf("DELETE left %d drain worker(s) running for a destination that no longer exists", got)
	}
}

// TestAuditExport_StatusFlipStartsAndStopsWorker: disabling a destination must
// stop its worker, and re-enabling it must start one again — both go through
// PATCH, which today never touches the worker map.
func TestAuditExport_StatusFlipStartsAndStopsWorker(t *testing.T) {
	env, plug := newDeliveryEnv(t, deliveryConfig())
	defer env.stop()
	tok, _ := env.seedAdmin(t)
	recv := newCollector()
	defer recv.Close()

	created := createViaAPI(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"config": map[string]string{"url": recv.URL()},
	})
	id := created["id"].(string)
	plug.Refresh()
	if got := plug.WorkerCount(); got != 1 {
		t.Fatalf("setup: want 1 worker, got %d", got)
	}

	res := env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+id, tok, map[string]any{"status": "disabled"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch disabled: want 200, got %d", res.StatusCode)
	}
	if got := plug.WorkerCount(); got != 0 {
		t.Errorf("PATCH status=disabled left %d drain worker(s) running", got)
	}

	res = env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+id, tok, map[string]any{"status": "active"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch active: want 200, got %d", res.StatusCode)
	}
	// POSITIVE CONTROL: re-enabling must bring the exporter back.
	if got := plug.WorkerCount(); got != 1 {
		t.Errorf("PATCH status=active did not restart the drain worker: WorkerCount()=%d", got)
	}
}

// TestAuditExport_PatchPreservesSecrets is the security half: the ordinary
// console round-trip (GET, edit a field, PATCH the object back) silently
// unsigns the audit stream and drops every static auth header.
func TestAuditExport_PatchPreservesSecrets(t *testing.T) {
	env, plug := newDeliveryEnv(t, deliveryConfig())
	defer env.stop()
	tok, _ := env.seedAdmin(t)
	recv := newCollector()
	defer recv.Close()

	const secret = "shared-secret"
	created := createViaAPI(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"format": "json",
		"config": map[string]string{
			"url":                 recv.URL(),
			"hmac_secret":         secret,
			"header.X-Siem-Token": "static-auth-token",
		},
	})
	id := created["id"].(string)
	if created["hmac_configured"] != true {
		t.Fatalf("setup: create should report hmac_configured=true, got %v", created["hmac_configured"])
	}

	// What the console sees: the secret and the static header are stripped.
	before := getDestination(t, env, tok, id)
	cfg, _ := before["config"].(map[string]any)
	if _, leaked := cfg["hmac_secret"]; leaked {
		t.Fatal("setup: GET leaked hmac_secret; this test assumes it is sanitised")
	}
	if before["hmac_configured"] != true {
		t.Fatalf("setup: GET should report hmac_configured=true, got %v", before["hmac_configured"])
	}

	// Drain whatever the create already produced, and take the delivery count
	// AFTER it lands. The destination has a live drain worker from the moment
	// it is created, so without this the wire assertion below could sample the
	// pre-PATCH (still-signed) request and pass vacuously.
	if !recv.waitForDelivery(1, 3*time.Second) {
		t.Fatalf("setup: the created destination delivered nothing (deliveries: %d)", recv.count())
	}
	deliveredBeforePatch := recv.count()

	// The console edit: rename, PATCH the object back exactly as it was read.
	res := env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+id, tok, map[string]any{
		"name":   "siem-renamed",
		"config": cfg,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	after := getDestination(t, env, tok, id)
	if after["hmac_configured"] != true {
		t.Errorf("read-edit-PATCH deleted the HMAC secret: hmac_configured is now %v — the audit stream is unsigned and nothing warned",
			after["hmac_configured"])
	}

	// STATE that matters: what actually goes out on the wire from here on. The
	// PATCH wrote its own audit row (audit_export.destination.updated), so the
	// next delivery is unambiguously a post-PATCH one.
	plug.Refresh()
	if !recv.waitForDelivery(deliveredBeforePatch+1, 3*time.Second) {
		t.Fatalf("no webhook delivered after the PATCH (deliveries: %d, was %d)", recv.count(), deliveredBeforePatch)
	}
	head, body := recv.last()
	sig := head.Get("X-Yauth-Signature")
	if sig == "" {
		t.Fatalf("the audit stream is now UNSIGNED: delivered webhook carries no X-Yauth-Signature after a read-edit-PATCH")
	}
	if err := auditexport.VerifyHMACSignature(secret, sig, body, time.Now(), 5*time.Minute); err != nil {
		t.Errorf("receiver-side verification of the post-PATCH delivery failed: %v", err)
	}
	if got := head.Get("X-Siem-Token"); got != "static-auth-token" {
		t.Errorf("read-edit-PATCH dropped the static auth header: X-Siem-Token=%q", got)
	}
}

// TestAuditExport_PatchWithoutConfigKeepsSigning is a POSITIVE CONTROL: a PATCH
// that names no config at all must leave the secret alone (it does today), and
// the delivery must still be signed. It pins the behaviour a merge fix must not
// disturb.
func TestAuditExport_PatchWithoutConfigKeepsSigning(t *testing.T) {
	env, plug := newDeliveryEnv(t, deliveryConfig())
	defer env.stop()
	tok, _ := env.seedAdmin(t)
	recv := newCollector()
	defer recv.Close()

	const secret = "shared-secret"
	created := createViaAPI(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"config": map[string]string{"url": recv.URL(), "hmac_secret": secret},
	})
	id := created["id"].(string)

	res := env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+id, tok, map[string]any{"name": "siem-renamed"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch: want 200, got %d", res.StatusCode)
	}
	after := getDestination(t, env, tok, id)
	if after["hmac_configured"] != true {
		t.Fatalf("POSITIVE CONTROL: a name-only PATCH must not touch the secret, hmac_configured=%v", after["hmac_configured"])
	}

	plug.Refresh()
	if !recv.waitForDelivery(1, 3*time.Second) {
		t.Fatalf("POSITIVE CONTROL: nothing delivered (deliveries: %d)", recv.count())
	}
	head, body := recv.last()
	sig := head.Get("X-Yauth-Signature")
	if sig == "" {
		t.Fatal("POSITIVE CONTROL: delivery after a name-only PATCH is unsigned")
	}
	if err := auditexport.VerifyHMACSignature(secret, sig, body, time.Now(), 5*time.Minute); err != nil {
		t.Fatalf("POSITIVE CONTROL: signature does not verify: %v", err)
	}
}

// TestAuditExport_PatchEmptyStringDeletesKey is the escape hatch, and the
// second POSITIVE CONTROL for the carry-forward: because a PATCH now inherits
// the secret keys the GET response cannot echo, there has to be a way to say
// "stop signing" — sending the key with an empty string. It must DELETE the
// key rather than store "": hmac_configured is computed from the stored config,
// so a stored "" would advertise a signed stream that the dispatcher does not
// sign, which is the very lie this test file exists to close.
func TestAuditExport_PatchEmptyStringDeletesKey(t *testing.T) {
	env, plug := newDeliveryEnv(t, deliveryConfig())
	defer env.stop()
	tok, _ := env.seedAdmin(t)
	recv := newCollector()
	defer recv.Close()

	created := createViaAPI(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"config": map[string]string{"url": recv.URL(), "hmac_secret": "shared-secret"},
	})
	id := created["id"].(string)
	if !recv.waitForDelivery(1, 3*time.Second) {
		t.Fatalf("setup: nothing delivered (deliveries: %d)", recv.count())
	}
	deliveredBeforePatch := recv.count()

	res := env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+id, tok, map[string]any{
		"config": map[string]string{"url": recv.URL(), "hmac_secret": ""},
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("patch: want 200, got %d", res.StatusCode)
	}

	after := getDestination(t, env, tok, id)
	if after["hmac_configured"] == true {
		t.Errorf("hmac_secret:\"\" still reports hmac_configured=true — an unsigned stream that claims to be signed")
	}

	// STATE: and the wire agrees — the delivery really is unsigned now.
	plug.Refresh()
	if !recv.waitForDelivery(deliveredBeforePatch+1, 3*time.Second) {
		t.Fatalf("nothing delivered after the PATCH (deliveries: %d, was %d)", recv.count(), deliveredBeforePatch)
	}
	if head, _ := recv.last(); head.Get("X-Yauth-Signature") != "" {
		t.Errorf("hmac_secret:\"\" did not turn signing off: X-Yauth-Signature=%q", head.Get("X-Yauth-Signature"))
	}
}

// TestAuditExport_PatchedConfigIsStillEgressChecked is the guard-rail for the
// merge fix: whatever the handler ends up storing, the EFFECTIVE url must still
// go through #108's ValidateDestinationURL. A merge that validates only the
// incoming fragment, or that skips validation because "the url did not change",
// would re-open the metadata-service hole this repo already closed.
func TestAuditExport_PatchedConfigIsStillEgressChecked(t *testing.T) {
	env, _ := newDeliveryEnv(t, auditexport.Config{BatchInterval: 20 * time.Millisecond})
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	created := createViaAPI(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"config": map[string]string{"url": "https://siem.example.com/ingest"},
	})
	id := created["id"].(string)

	res := env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+id, tok, map[string]any{
		"config": map[string]string{"url": "http://169.254.169.254/latest/meta-data/"},
	})
	body := bodyOf(res)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("PATCH re-pointing at the metadata service: want 400, got %d (%s)", res.StatusCode, body)
	}
	after := getDestination(t, env, tok, id)
	cfg, _ := after["config"].(map[string]any)
	if cfg["url"] != "https://siem.example.com/ingest" {
		t.Fatalf("refused PATCH still re-pointed the destination: url is now %v", cfg["url"])
	}
}
