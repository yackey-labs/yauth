// security_hmac_secret_floor_test.go — the admin-API half of "refuse to emit a
// credential-shaped thing that proves nothing".
//
// The audit-export stream is signed with HMAC-SHA256 keyed on the destination's
// config["hmac_secret"] (dispatcher.go sendWebhook → ComputeHMACSignature), and
// the receiver is told to recompute it. The signature is therefore the ONLY
// thing distinguishing a genuine audit delivery from one an attacker POSTs at
// the same collector — audit exports are exactly the stream someone wants to
// forge into, because it is the record of what happened.
//
// createDo and updateDo (routes.go) validate name, kind, format and the egress
// destination, and then store config verbatim. Nothing looks at hmac_secret at
// all. So an operator can create a destination whose signing key is "hunter2",
// the API answers 201 and GET reports hmac_configured=true, and the stream goes
// out carrying a MAC that a laptop brute-forces offline from a single captured
// delivery. The webhooks plugin next door already enforces exactly this floor on
// a caller-supplied secret (plugins/webhooks/handlers.go, minSuppliedSecretLen
// = 32); audit-export, whose payload is the audit log itself, enforces nothing.
//
// The floor must apply ONLY to what the request actually supplied. GET strips
// hmac_secret from the response, and updateDo therefore carries the stored
// secret forward when the incoming config omits it — validating the MERGED map
// would 400 every url-only PATCH against a destination created before the floor
// existed, with no way for the operator to satisfy it. That case is pinned open
// in hmac_empty_secret_test.go (in-package, seeded below the API).
//
// Every refusal here is paired with a POSITIVE CONTROL: a strong secret, an
// absent secret and the empty-string "stop signing" hatch must all still be
// accepted, and a destination whose PATCH is refused must still be delivering,
// signed, under its ORIGINAL secret.
package auditexport_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/plugins/auditexport"
)

// strongSecret is a 32+ character key — the shape the webhooks plugin already
// requires of a caller-supplied signing secret.
const strongSecret = "audit-export-signing-secret-0123456789ab"

// TestAuditDestinationCreate_RefusesAShortHMACSecret is the finding: the admin
// API accepts a signing key that is worth nothing, and then advertises the
// stream as signed.
func TestAuditDestinationCreate_RefusesAShortHMACSecret(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	res := createDestination(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"format": "json",
		"config": map[string]string{
			"url":         "https://siem.example.com/ingest",
			"hmac_secret": "hunter2",
		},
	})
	body := bodyOf(res)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("create with a 7-character hmac_secret: got %d, want 400: %s", res.StatusCode, body)
	}

	// STATE, not status: a refused create must leave no destination behind that
	// a drain worker could start signing with the weak key.
	got := listDestinations(t, env, tok)
	if len(got) != 0 {
		t.Fatalf("refused create persisted %d destination(s): %v", len(got), got)
	}
}

// TestAuditDestinationUpdate_RefusesAShortHMACSecret covers the other door.
// A create-time floor alone would be a formality: PATCH replaces the stored
// config, so the same weak key can be installed a second later.
func TestAuditDestinationUpdate_RefusesAShortHMACSecret(t *testing.T) {
	env, plug := newDeliveryEnv(t, deliveryConfig())
	defer env.stop()
	tok, _ := env.seedAdmin(t)
	recv := newCollector()
	defer recv.Close()

	created := createViaAPI(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"format": "json",
		"config": map[string]string{"url": recv.URL(), "hmac_secret": strongSecret},
	})
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("setup: create returned no id")
	}
	if !recv.waitForDelivery(1, 3*time.Second) {
		t.Fatalf("setup: the created destination delivered nothing (deliveries: %d)", recv.count())
	}
	deliveredBeforePatch := recv.count()

	res := env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+id, tok, map[string]any{
		"config": map[string]string{"url": recv.URL(), "hmac_secret": "hunter2"},
	})
	body := bodyOf(res)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("PATCH installing a 7-character hmac_secret: got %d, want 400: %s", res.StatusCode, body)
	}

	// STATE: the destination must still be signing with the secret it had. A
	// name-only PATCH writes an audit row, which gives us a fresh, unambiguously
	// post-refusal delivery to inspect.
	res = env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+id, tok, map[string]any{"name": "siem-renamed"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("follow-up name-only PATCH: want 200, got %d (%s)", res.StatusCode, bodyOf(res))
	}
	res.Body.Close()

	plug.Refresh()
	if !recv.waitForDelivery(deliveredBeforePatch+1, 3*time.Second) {
		t.Fatalf("nothing delivered after the refused PATCH (deliveries: %d, was %d)", recv.count(), deliveredBeforePatch)
	}
	head, wire := recv.last()
	sig := head.Get("X-Yauth-Signature")
	if sig == "" {
		t.Fatal("the stream is now UNSIGNED: a refused PATCH still dropped the destination's secret")
	}
	if err := auditexport.VerifyHMACSignature(strongSecret, sig, wire, time.Now(), 5*time.Minute); err != nil {
		t.Errorf("a refused PATCH still swapped the signing key: delivery no longer verifies under the original secret: %v", err)
	}
}

// TestAuditDestinationCreate_AcceptsStrongAbsentAndDisabledSecrets is the
// POSITIVE CONTROL for the floor. Three legitimate shapes must survive:
//
//   - a strong secret — the signing case the plugin exists to serve;
//   - no hmac_secret at all — an unsigned destination is a supported choice
//     (a syslog sidecar on a private link, say), and always has been;
//   - hmac_secret:"" — the documented "stop signing" hatch (webhook.md), which
//     updateDo turns into a delete of the key.
//
// A fix that refuses any of these has broken the feature rather than hardened it.
func TestAuditDestinationCreate_AcceptsStrongAbsentAndDisabledSecrets(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	cases := []struct {
		name           string
		body           map[string]any
		wantConfigured bool
	}{
		{
			name: "strong secret",
			body: map[string]any{
				"name":   "signed-siem",
				"kind":   "webhook",
				"config": map[string]string{"url": "https://siem.example.com/ingest", "hmac_secret": strongSecret},
			},
			wantConfigured: true,
		},
		{
			name: "no secret at all",
			body: map[string]any{
				"name":   "unsigned-collector",
				"kind":   "webhook",
				"config": map[string]string{"url": "http://otel-collector.observability.svc.cluster.local:4318/v1/logs"},
			},
			wantConfigured: false,
		},
		{
			name: "explicit disable hatch",
			body: map[string]any{
				"name":   "signing-off",
				"kind":   "webhook",
				"config": map[string]string{"url": "https://siem.example.com/plain", "hmac_secret": ""},
			},
			wantConfigured: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := createDestination(t, env, tok, tc.body)
			raw := bodyOf(res)
			if res.StatusCode != http.StatusCreated {
				t.Fatalf("POSITIVE CONTROL: create %q got %d, want 201: %s", tc.name, res.StatusCode, raw)
			}
			var out map[string]any
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatalf("decode create: %v", err)
			}
			if got := out["hmac_configured"] == true; got != tc.wantConfigured {
				t.Errorf("hmac_configured=%v, want %v", out["hmac_configured"], tc.wantConfigured)
			}
		})
	}

	if got := listDestinations(t, env, tok); len(got) != len(cases) {
		t.Fatalf("POSITIVE CONTROL: expected %d legitimate destinations to persist, got %d", len(cases), len(got))
	}
}

// TestAuditDestinationCreate_RefusalNamesTheSecret is a small usability guard:
// the 400 an operator gets must say which field is wrong. A bare "bad request"
// on a config map with six keys, one of which the API will never echo back,
// is a support ticket.
func TestAuditDestinationCreate_RefusalNamesTheSecret(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	res := createDestination(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"config": map[string]string{"url": "https://siem.example.com/ingest", "hmac_secret": "short"},
	})
	body := bodyOf(res)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("create with a short hmac_secret: got %d, want 400: %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "hmac_secret") {
		t.Errorf("the 400 does not name the offending field: %s", body)
	}
}
