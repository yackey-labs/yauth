// egress_guard_routes_test.go — the create/update half of the audit-export
// egress finding, driven through the real HTTP routes.
//
// createDo (routes.go) validates name, kind and format and then stores
// req.Config verbatim: config["url"] for a webhook destination and
// config["host"] for a syslog one are never parsed. updateDo is worse — it
// copies req.Config straight into the change set with no inspection at all.
// The worker later hands whichever string it finds to Dispatcher.SendOne,
// which POSTs to it (or opens a socket to it), so a deployment admin can aim
// the process's own network position at the cloud metadata service or at any
// internal listener, and read the outcome back off the outbox route.
//
// The refusals below use link-local 169.254.0.0/16 — the unambiguous case. No
// real install exports audit logs to the metadata service, so refusing it
// costs nobody anything, while a blanket ban on private addresses would lock
// out every install shipping to an in-cluster collector. The positive
// controls pin exactly that: a public URL and an in-cluster HOSTNAME must
// both still be accepted at create time (where a hostname resolves is a
// dial-time question, not a create-time one).
package auditexport_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func createDestination(t *testing.T, env *routeEnv, tok string, body map[string]any) *http.Response {
	t.Helper()
	return env.do(t, http.MethodPost, "/api/auth/audit/destinations", tok, body)
}

func listDestinations(t *testing.T, env *routeEnv, tok string) []map[string]any {
	t.Helper()
	res := env.do(t, http.MethodGet, "/api/auth/audit/destinations", tok, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list destinations: got %d", res.StatusCode)
	}
	var out []map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return out
}

// TestAuditDestinationCreate_RefusesLinkLocalWebhookURL is the finding: an
// admin registers the metadata service as an audit-export destination and the
// API answers 201.
func TestAuditDestinationCreate_RefusesLinkLocalWebhookURL(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	res := createDestination(t, env, tok, map[string]any{
		"name": "metadata",
		"kind": "webhook",
		"config": map[string]string{
			"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		},
	})
	body := bodyOf(res)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("create webhook destination at the metadata service: got %d, want 400: %s",
			res.StatusCode, body)
	}
	// STATE: a refused create must leave no destination the worker could pick up.
	if got := listDestinations(t, env, tok); len(got) != 0 {
		t.Fatalf("refused create persisted %d destination(s): %v", len(got), got)
	}
}

// TestAuditDestinationCreate_RefusesLinkLocalSyslogHost covers the other
// dialler: sendSyslog opens a socket to config["host"]:config["port"], which
// is equally unvalidated.
func TestAuditDestinationCreate_RefusesLinkLocalSyslogHost(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	res := createDestination(t, env, tok, map[string]any{
		"name":   "syslog-metadata",
		"kind":   "syslog",
		"format": "rfc5424",
		"config": map[string]string{
			"host":      "169.254.169.254",
			"port":      "80",
			"transport": "tcp",
		},
	})
	body := bodyOf(res)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("create syslog destination at a link-local host: got %d, want 400: %s",
			res.StatusCode, body)
	}
	if got := listDestinations(t, env, tok); len(got) != 0 {
		t.Fatalf("refused create persisted %d destination(s): %v", len(got), got)
	}
}

// TestAuditDestinationUpdate_RefusesRepointingAtLinkLocal covers updateDo,
// which today copies Config in with no inspection whatsoever — so even a
// perfect create-time check would be a formality.
func TestAuditDestinationUpdate_RefusesRepointingAtLinkLocal(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	res := createDestination(t, env, tok, map[string]any{
		"name":   "siem",
		"kind":   "webhook",
		"config": map[string]string{"url": "https://siem.example.com/ingest"},
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("seed create: got %d: %s", res.StatusCode, bodyOf(res))
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	res.Body.Close()

	res = env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+created.ID, tok, map[string]any{
		"config": map[string]string{"url": "http://169.254.169.254/latest/meta-data/"},
	})
	body := bodyOf(res)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("PATCH re-pointing a destination at the metadata service: got %d, want 400: %s",
			res.StatusCode, body)
	}

	got := listDestinations(t, env, tok)
	if len(got) != 1 {
		t.Fatalf("expected the destination to survive, got %d", len(got))
	}
	cfg, _ := got[0]["config"].(map[string]any)
	if cfg["url"] != "https://siem.example.com/ingest" {
		t.Fatalf("refused update still re-pointed the destination: url is now %v", cfg["url"])
	}
}

// TestAuditDestinationCreate_AcceptsRealDestinations is the POSITIVE CONTROL,
// and it is the guard against an over-broad fix: the in-cluster collector
// shape (a hostname, resolved at dial time) and a public SIEM must both still
// be accepted, and a legitimate re-point must still work.
func TestAuditDestinationCreate_AcceptsRealDestinations(t *testing.T) {
	env := newRouteEnv(t)
	defer env.stop()
	tok, _ := env.seedAdmin(t)

	cases := []map[string]any{
		{
			"name":   "public-siem",
			"kind":   "webhook",
			"config": map[string]string{"url": "https://siem.example.com/ingest"},
		},
		{
			"name":   "in-cluster-collector",
			"kind":   "webhook",
			"config": map[string]string{"url": "http://otel-collector.observability.svc.cluster.local:4318/v1/logs"},
		},
		{
			"name":   "syslog-sidecar",
			"kind":   "syslog",
			"format": "rfc5424",
			"config": map[string]string{"host": "syslog-sidecar", "port": "514", "transport": "tcp"},
		},
	}
	var firstID string
	for _, body := range cases {
		res := createDestination(t, env, tok, body)
		raw := bodyOf(res)
		if res.StatusCode != http.StatusCreated {
			t.Errorf("create %v: got %d, want 201: %s", body["name"], res.StatusCode, raw)
			continue
		}
		if firstID == "" {
			var created struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal([]byte(raw), &created); err != nil {
				t.Fatalf("decode create: %v", err)
			}
			firstID = created.ID
		}
	}
	if got := listDestinations(t, env, tok); len(got) != len(cases) {
		t.Fatalf("expected %d legitimate destinations to persist, got %d", len(cases), len(got))
	}

	// And a legitimate re-point still takes effect.
	res := env.do(t, http.MethodPatch, "/api/auth/audit/destinations/"+firstID, tok, map[string]any{
		"config": map[string]string{"url": "https://siem.example.com/ingest-v2"},
	})
	raw := bodyOf(res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("legitimate PATCH: got %d, want 200: %s", res.StatusCode, raw)
	}
}
