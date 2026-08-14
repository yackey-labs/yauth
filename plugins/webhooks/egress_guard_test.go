// egress_guard_test.go — regression suite for "the webhooks plugin hands a
// deployment admin an internal read primitive".
//
// Four separate holes, all on the same outbound path:
//
//   - registerCreate (handlers.go) checks only `req.URL == ""`, and
//     registerUpdate checks nothing at all. Neither ever calls url.Parse. So
//     POST /webhooks {"url":"http://169.254.169.254/latest/meta-data/iam/
//     security-credentials/"} is accepted, and any later event points the
//     deployment's own HTTP client at the cloud metadata service — or at a
//     `file://` URL, or at any internal listener the process can reach.
//
//   - webhooksPlugin.Routes builds the delivery client as
//     &http.Client{Timeout, Transport: otelhttp.NewTransport(...)} with a nil
//     CheckRedirect, so Go follows up to 10 hops. A receiver answering 302
//     turns the signed POST into a GET (exactly what IMDSv1 wants) and Go
//     copies every header except Authorization and Cookie across the hop —
//     so X-YAuth-Signature, computed with the deployment's signing secret,
//     travels to whatever host the receiver names.
//     plugins/oauth2server/backchannel_logout.go already refuses redirects
//     for precisely this reason.
//
//   - Dispatcher.deliver reads up to 4 KiB of the receiver's response body
//     and passes it to recordDelivery, which persists it in
//     yauth_webhook_deliveries.response_body — and GET /webhooks/{id}/
//     deliveries serialises it straight back to the caller. That is what
//     converts the blind SSRF into a read primitive: whatever the internal
//     endpoint answered is now readable over the admin API.
//
//   - A caller-supplied signing secret is accepted at any length, so
//     {"secret":"a"} produces a webhook whose HMAC is trivially forgeable by
//     the receiver — the signature stops meaning anything at all.
//
// Every refusal below is paired with a positive control: a public
// destination, an in-cluster *hostname* destination (the shape real installs
// ship — a hostname is resolved at dial time, not refused at create time), a
// long secret, a generated secret, and an actual successful delivery whose
// signature still verifies and whose row is still recorded. A "fix" that
// simply stops webhooks working cannot pass this file.
package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// egressJWTSecret is the key material the test host reports, so webhook
// secrets can be encrypted at rest (create refuses without one).
var egressJWTSecret = []byte("jwt-secret-for-the-egress-guard-tests")

// newEgressServer mounts the webhooks admin routes exactly like
// newSecretsServer does, but also returns the plugin so a test can drive one
// delivery synchronously through the dispatcher the plugin actually built.
// That matters for the redirect case: CheckRedirect lives on the client
// constructed inside Routes, so a test that injects its own client would not
// be exercising the code under test at all.
func newEgressServer(t *testing.T, cfg Config, r repo.Repository) (*httptest.Server, *webhooksPlugin) {
	t.Helper()
	host := newSecretsHost(r, egressJWTSecret)
	host.mw.AddResolver(adminResolver{})

	mux := http.NewServeMux()
	p := New(cfg).(*webhooksPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	return srv, p
}

// seedEncryptedWebhook writes a webhook row whose secret is sealed with the
// same key the dispatcher will use to unseal it.
func seedEncryptedWebhook(t *testing.T, r repo.Repository, url, secret string) domain.Webhook {
	t.Helper()
	sealed, err := encryptSecret(deriveWebhookKey(egressJWTSecret), secret)
	if err != nil {
		t.Fatalf("seal secret: %v", err)
	}
	now := time.Now().UTC()
	in := domain.NewWebhook{
		ID: uuid.NewString(), URL: url, Secret: sealed,
		Events: json.RawMessage(`["user.registered"]`), Active: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := r.CreateWebhook(context.Background(), in); err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	return domain.Webhook{
		ID: in.ID, URL: in.URL, Secret: in.Secret, Events: in.Events,
		Active: true, CreatedAt: now, UpdatedAt: now,
	}
}

// deliverOnce drives a single synchronous delivery attempt through the
// plugin's own dispatcher — same client, same signing, same recording as a
// real event fan-out, minus the worker-pool timing.
func deliverOnce(t *testing.T, p *webhooksPlugin, hook domain.Webhook) deliveryOutcome {
	t.Helper()
	job := &deliveryJob{
		webhook:   hook,
		eventType: "user.registered",
		payload: payloadEnvelope{
			Event:     "user.registered",
			Timestamp: time.Now().UTC(),
			Data:      map[string]any{"user_id": "u1"},
		},
	}
	return p.dispatcher.deliver(context.Background(), job)
}

func getWithAdmin(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func countWebhooks(t *testing.T, r repo.Repository) int {
	t.Helper()
	hooks, err := r.ListWebhooks(context.Background())
	if err != nil {
		t.Fatalf("list webhooks: %v", err)
	}
	return len(hooks)
}

// --- W1: the destination URL is never parsed or filtered -----------------

// TestWebhookCreate_RefusesLinkLocalMetadataDestination is the finding in its
// simplest form: an install admin registers the cloud metadata service as a
// webhook receiver and the API says 201. Link-local (169.254.0.0/16) is the
// unambiguous case — no real deployment ships webhooks there — so refusing it
// costs no legitimate install anything.
func TestWebhookCreate_RefusesLinkLocalMetadataDestination(t *testing.T) {
	r := memrepo.New()
	srv, _ := newEgressServer(t, Config{WorkerCount: 1}, r)

	const imds = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	resp := postJSON(t, srv.URL+"/webhooks", map[string]any{
		"url":    imds,
		"events": []string{"user.registered"},
		"secret": "a-signing-secret-long-enough-for-the-length-rule",
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /webhooks with the metadata service as destination: got %d, want 400: %s",
			resp.StatusCode, body)
	}
	// The claim is about STATE: a refused create must leave nothing behind
	// that a later event could fire at.
	if n := countWebhooks(t, r); n != 0 {
		hooks, _ := r.ListWebhooks(context.Background())
		t.Fatalf("refused create persisted %d webhook row(s); first url = %q", n, hooks[0].URL)
	}
}

// TestWebhookCreate_RefusesNonHTTPScheme covers the other half of "never
// parsed": the URL string is handed to http.NewRequest verbatim, so anything
// url.Parse accepts is accepted here.
func TestWebhookCreate_RefusesNonHTTPScheme(t *testing.T) {
	r := memrepo.New()
	srv, _ := newEgressServer(t, Config{WorkerCount: 1}, r)

	for _, bad := range []string{
		"file:///etc/passwd",
		"gopher://127.0.0.1:11211/_stats",
		"not-a-url-at-all",
	} {
		resp := postJSON(t, srv.URL+"/webhooks", map[string]any{
			"url":    bad,
			"events": []string{"user.registered"},
			"secret": "a-signing-secret-long-enough-for-the-length-rule",
		})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST /webhooks url=%q: got %d, want 400: %s", bad, resp.StatusCode, body)
		}
	}
	if n := countWebhooks(t, r); n != 0 {
		t.Fatalf("refused creates persisted %d webhook row(s)", n)
	}
}

// TestWebhookCreate_AcceptsRealDestinations is the POSITIVE CONTROL for the
// two tests above, and it is deliberately load-bearing: an over-broad guard
// that refuses private-looking HOSTNAMES would lock out every install
// shipping to an in-cluster collector. A hostname must still be accepted at
// create time — where it resolves is a dial-time question.
func TestWebhookCreate_AcceptsRealDestinations(t *testing.T) {
	r := memrepo.New()
	srv, _ := newEgressServer(t, Config{WorkerCount: 1}, r)

	for _, good := range []string{
		"https://hooks.example.com/ingest",
		"http://otel-collector.observability.svc.cluster.local:4318/webhook",
	} {
		resp := postJSON(t, srv.URL+"/webhooks", map[string]any{
			"url":    good,
			"events": []string{"user.registered"},
			"secret": "a-signing-secret-long-enough-for-the-length-rule",
		})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("POST /webhooks url=%q: got %d, want 201: %s", good, resp.StatusCode, body)
		}
	}
	if n := countWebhooks(t, r); n != 2 {
		t.Fatalf("expected both legitimate destinations to persist, got %d row(s)", n)
	}
}

// TestWebhookUpdate_RefusesRepointingAtLinkLocalMetadata covers the write
// path the create-side check would otherwise leave wide open: registerUpdate
// assigns req.URL into the change set without looking at it, so a webhook
// created against a public receiver can simply be re-pointed afterwards.
func TestWebhookUpdate_RefusesRepointingAtLinkLocalMetadata(t *testing.T) {
	r := memrepo.New()
	srv, _ := newEgressServer(t, Config{WorkerCount: 1}, r)

	hook := seedEncryptedWebhook(t, r, "https://hooks.example.com/ingest", "a-signing-secret-long-enough")

	const imds = "http://169.254.169.254/latest/meta-data/"
	resp := patchJSON(t, srv.URL+"/webhooks/"+hook.ID, map[string]any{
		"url":    imds,
		"events": []string{"user.registered"},
		"active": true,
		// An empty secret means "keep the existing one"; the PATCH body
		// schema requires the field to be present.
		"secret": "",
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PATCH /webhooks/{id} re-pointing at the metadata service: got %d, want 400: %s",
			resp.StatusCode, body)
	}

	got, err := r.GetWebhookByID(context.Background(), hook.ID)
	if err != nil {
		t.Fatalf("get webhook: %v", err)
	}
	if got.URL != "https://hooks.example.com/ingest" {
		t.Fatalf("refused update still re-pointed the webhook: url is now %q", got.URL)
	}

	// POSITIVE CONTROL: a legitimate re-point still works.
	resp = patchJSON(t, srv.URL+"/webhooks/"+hook.ID, map[string]any{
		"url":    "https://hooks.example.com/ingest-v2",
		"events": []string{"user.registered"},
		"active": true,
		"secret": "",
	})
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH to a public destination: got %d, want 200: %s", resp.StatusCode, body)
	}
	got, err = r.GetWebhookByID(context.Background(), hook.ID)
	if err != nil {
		t.Fatalf("get webhook: %v", err)
	}
	if got.URL != "https://hooks.example.com/ingest-v2" {
		t.Fatalf("legitimate update did not take effect: url is %q", got.URL)
	}
}

// --- W10: a one-character signing secret is accepted ---------------------

// TestWebhookCreate_RefusesShortSecret pins the length floor. The generated
// secret is 32 bytes of entropy; accepting "a" from the caller means the
// receiver can forge X-YAuth-Signature for any body, which is the entire
// value of the header.
func TestWebhookCreate_RefusesShortSecret(t *testing.T) {
	r := memrepo.New()
	srv, _ := newEgressServer(t, Config{WorkerCount: 1}, r)

	resp := postJSON(t, srv.URL+"/webhooks", map[string]any{
		"url":    "https://hooks.example.com/ingest",
		"events": []string{"user.registered"},
		"secret": "a",
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /webhooks with a 1-character secret: got %d, want 400: %s",
			resp.StatusCode, body)
	}
	if n := countWebhooks(t, r); n != 0 {
		t.Fatalf("refused create persisted %d webhook row(s) with a forgeable secret", n)
	}

	// POSITIVE CONTROL 1: a 32-character caller-supplied secret is fine.
	resp = postJSON(t, srv.URL+"/webhooks", map[string]any{
		"url":    "https://hooks.example.com/ingest",
		"events": []string{"user.registered"},
		"secret": strings.Repeat("k", 32),
	})
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /webhooks with a 32-character secret: got %d, want 201: %s",
			resp.StatusCode, body)
	}

	// POSITIVE CONTROL 2: omitting the secret still generates one.
	resp = postJSON(t, srv.URL+"/webhooks", map[string]any{
		"url":    "https://hooks.example.com/ingest",
		"events": []string{"user.registered"},
	})
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /webhooks with no secret: got %d, want 201: %s", resp.StatusCode, body)
	}
	var created webhookJSON
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode create response: %v: %s", err, body)
	}
	if len(created.Secret) < 32 {
		t.Fatalf("generated secret is only %d characters: %q", len(created.Secret), created.Secret)
	}
}

// --- W3: the receiver's response body is stored and served back ----------

// TestWebhookDelivery_DoesNotStoreOrServeReceiverResponseBody is the step
// that turns a blind SSRF into a read primitive. The row is the thing that
// matters — GET /webhooks/{id}/deliveries only serialises what deliver()
// chose to persist — so this asserts on both.
func TestWebhookDelivery_DoesNotStoreOrServeReceiverResponseBody(t *testing.T) {
	const sentinel = "SENTINEL-INTERNAL-DATA-aws-access-key"

	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sentinel))
	}))
	defer receiver.Close()

	r := memrepo.New()
	// An injected client keeps this test about the RECORDING behaviour, not
	// about which addresses the default client is willing to dial.
	srv, p := newEgressServer(t, Config{
		WorkerCount: 1,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	}, r)

	hook := seedEncryptedWebhook(t, r, receiver.URL, "a-signing-secret-long-enough")
	outcome := deliverOnce(t, p, hook)

	// POSITIVE CONTROL: the delivery itself still happened and is still
	// observable. Suppressing the body must not mean suppressing the row.
	if !outcome.success {
		t.Fatalf("delivery to a healthy receiver failed: %+v", outcome)
	}
	rows, err := r.ListWebhookDeliveriesByWebhookID(context.Background(), hook.ID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one delivery row, got %d", len(rows))
	}
	if rows[0].StatusCode == nil || *rows[0].StatusCode != 200 {
		t.Fatalf("delivery row lost the status code: %+v", rows[0].StatusCode)
	}
	if !rows[0].Success {
		t.Fatalf("delivery row records failure for a 200 response")
	}

	// The finding: the receiver's bytes are in the database.
	if rows[0].ResponseBody != nil && strings.Contains(*rows[0].ResponseBody, sentinel) {
		t.Errorf("delivery row stored the receiver's response body: %q", *rows[0].ResponseBody)
	}

	// ...and served straight back over the admin API.
	status, body := getWithAdmin(t, srv.URL+"/webhooks/"+hook.ID+"/deliveries")
	if status != http.StatusOK {
		t.Fatalf("GET deliveries: got %d: %s", status, body)
	}
	if strings.Contains(body, sentinel) {
		t.Errorf("GET /webhooks/{id}/deliveries echoed the receiver's response body back to the caller:\n%s", body)
	}
}

// --- W2: redirects are followed, laundering the POST and the signature ---

// redirectTrap is the attacker-controlled second hop. It records every
// request it sees so the test can assert on both the count and the headers.
type redirectTrap struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []http.Header
}

func newRedirectTrap() *redirectTrap {
	trap := &redirectTrap{}
	trap.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		trap.mu.Lock()
		trap.hits = append(trap.hits, req.Header.Clone())
		trap.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	return trap
}

func (t *redirectTrap) Hits() []http.Header {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]http.Header, len(t.hits))
	copy(out, t.hits)
	return out
}

// TestWebhookDelivery_DoesNotFollowRedirectOffHost drives one delivery at a
// receiver that answers 302 pointing at a second host. Because the client the
// plugin builds has a nil CheckRedirect, Go follows the hop, converts the
// signed POST into a GET, and carries X-YAuth-Signature — a valid signature
// over the deployment's payload, computed with the deployment's secret —
// to the second host.
//
// This uses the plugin's OWN client (Config.HTTPClient left nil) on purpose:
// CheckRedirect is a property of that client, so an injected one would prove
// nothing.
//
// AllowPrivateDestinations is set BECAUSE the redirector and the trap are
// httptest servers on 127.0.0.1. Without it the dial-time guard refuses the
// first hop and the test passes without ever reaching CheckRedirect — it would
// measure the wrong guard and would keep passing if the redirect policy were
// later removed. The two guards are independent and are asserted separately:
// see TestWebhookDelivery_RefusesPrivateDestinationAtDial for the other one.
func TestWebhookDelivery_DoesNotFollowRedirectOffHost(t *testing.T) {
	trap := newRedirectTrap()
	defer trap.srv.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, trap.srv.URL+"/collect", http.StatusFound)
	}))
	defer redirector.Close()

	r := memrepo.New()
	_, p := newEgressServer(t, Config{
		WorkerCount:              1,
		DeliveryTimeout:          5 * time.Second,
		AllowPrivateDestinations: true,
	}, r)

	hook := seedEncryptedWebhook(t, r, redirector.URL, "a-signing-secret-long-enough")
	outcome := deliverOnce(t, p, hook)

	hits := trap.Hits()
	if len(hits) != 0 {
		t.Errorf("the delivery followed a redirect to a second host: it recorded %d request(s)", len(hits))
	}
	for i, h := range hits {
		if sig := h.Get("X-YAuth-Signature"); sig != "" {
			t.Errorf("hop %d carried the signing header off-host: X-YAuth-Signature=%q", i, sig)
		}
	}

	// A 302 must not be laundered into a recorded success either — otherwise
	// operators see a green delivery for a payload that went somewhere else.
	if outcome.success {
		t.Errorf("a redirect response was recorded as a successful delivery: %+v", outcome)
	}
	rows, err := r.ListWebhookDeliveriesByWebhookID(context.Background(), hook.ID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(rows) == 1 && rows[0].Success {
		status := "none"
		if rows[0].StatusCode != nil {
			status = strconv.Itoa(int(*rows[0].StatusCode))
		}
		t.Errorf("delivery row records success=true for a redirected delivery (status %s)", status)
	}
	// ANTI-VACUITY: the first hop must genuinely have happened and returned
	// the 302 itself. If the dial had been refused instead there would be no
	// status code at all, and this test would be silently measuring the
	// private-address guard rather than the redirect policy.
	if len(rows) != 1 || rows[0].StatusCode == nil || *rows[0].StatusCode != http.StatusFound {
		t.Fatalf("the redirector was never actually reached — this test is not exercising "+
			"CheckRedirect. rows=%d", len(rows))
	}
	if outcome.statusCode != http.StatusFound {
		t.Errorf("the 3xx was not recorded as the delivery outcome: got status %d", outcome.statusCode)
	}
}

// TestWebhookDelivery_RefusesPrivateDestinationAtDial covers the half of the
// guard the create-time check cannot reach: a row that is ALREADY in the
// table. Every deployment upgrading into this fix has some, and a hostname
// that resolves privately only at delivery time never passes through
// registerCreate at all.
//
// The requirement is "refuse at dial, do not silently drop": the attempt must
// fail, and the failure must be recorded, so an operator looking at the
// deliveries table sees why their receiver stopped working instead of nothing
// at all.
func TestWebhookDelivery_RefusesPrivateDestinationAtDial(t *testing.T) {
	var hits int
	var mu sync.Mutex
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	r := memrepo.New()
	// Knob OFF, plugin's own client: this is the default deployment.
	_, p := newEgressServer(t, Config{WorkerCount: 1, DeliveryTimeout: 5 * time.Second}, r)

	// Seeded straight into the repo — exactly like a row that predates the
	// create-time check.
	hook := seedEncryptedWebhook(t, r, receiver.URL, "a-signing-secret-long-enough")
	outcome := deliverOnce(t, p, hook)

	if outcome.success {
		t.Errorf("a loopback destination was delivered to with the default config: %+v", outcome)
	}
	mu.Lock()
	got := hits
	mu.Unlock()
	if got != 0 {
		t.Errorf("the receiver was actually contacted %d time(s) — nothing was refused", got)
	}
	rows, err := r.ListWebhookDeliveriesByWebhookID(context.Background(), hook.ID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the refusal was not recorded: got %d delivery row(s), want 1", len(rows))
	}
	if rows[0].Success {
		t.Errorf("the refused delivery was recorded as a success")
	}
}

// TestWebhookDelivery_DirectReceiverStillWorks is the POSITIVE CONTROL for
// the redirect test: with a client the operator supplied, a plain receiver
// still gets the signed POST, the signature still verifies against the
// webhook's secret, and the row is still written. Refusing redirects must not
// mean refusing deliveries.
func TestWebhookDelivery_DirectReceiverStillWorks(t *testing.T) {
	const secret = "a-signing-secret-long-enough-to-matter"

	var (
		mu   sync.Mutex
		gotB []byte
		gotS string
		hits int
	)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		hits++
		gotB = body
		gotS = req.Header.Get("X-YAuth-Signature")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	r := memrepo.New()
	_, p := newEgressServer(t, Config{
		WorkerCount: 1,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	}, r)

	hook := seedEncryptedWebhook(t, r, receiver.URL, secret)
	outcome := deliverOnce(t, p, hook)
	if !outcome.success {
		t.Fatalf("legitimate delivery failed: %+v", outcome)
	}

	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("receiver saw %d requests, want 1", hits)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotB)
	want := signaturePrefix + hex.EncodeToString(mac.Sum(nil))
	if gotS != want {
		t.Fatalf("signature mismatch:\n got  %s\n want %s\n body %s", gotS, want, gotB)
	}

	rows, err := r.ListWebhookDeliveriesByWebhookID(context.Background(), hook.ID, 10)
	if err != nil || len(rows) != 1 || !rows[0].Success {
		t.Fatalf("expected one successful delivery row, got %d rows (err=%v)", len(rows), err)
	}
}
