// safehttp_test.go — unit coverage for the shared egress guard.
//
// Two of yauth's plugins (webhooks, audit-export) let a deployment admin
// choose, over the admin API, a URL the server will then connect to on every
// auth event. Before this package existed neither plugin ever called url.Parse
// on that string, so "http://169.254.169.254/latest/meta-data/iam/
// security-credentials/" was a valid webhook receiver and the response came
// back on the delivery/outbox route. The classification below is what stops
// that, so it is worth pinning directly rather than only through the plugins.
//
// The positive cases are as load-bearing as the refusals: a public address, an
// in-cluster HOSTNAME, and a plain http scheme must all survive, because those
// are the shapes real installs ship.
package safehttp

import (
	"net/http"
	"testing"
	"time"
)

func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"127.0.0.1",
		"::1",
		"::ffff:127.0.0.1", // IPv4-mapped loopback — the classic bypass
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.169.254", // cloud instance metadata
		"0.0.0.0",
	}
	for _, addr := range private {
		if !IsPrivateIP(addr) {
			t.Errorf("IsPrivateIP(%q) = false, want true", addr)
		}
	}
	// POSITIVE CONTROL: public addresses (and non-addresses) must not be
	// classified as private, or the guard refuses every real destination.
	for _, addr := range []string{"93.184.216.34", "8.8.8.8", "2606:4700::1111", "not-an-ip"} {
		if IsPrivateIP(addr) {
			t.Errorf("IsPrivateIP(%q) = true, want false", addr)
		}
	}
}

// TestIsAlwaysDeniedIP pins the floor under the allow-private escape hatch:
// an operator turns it on for an in-cluster collector, not for IMDS.
func TestIsAlwaysDeniedIP(t *testing.T) {
	for _, addr := range []string{"169.254.169.254", "169.254.0.1", "0.0.0.0", "fe80::1"} {
		if !IsAlwaysDeniedIP(addr) {
			t.Errorf("IsAlwaysDeniedIP(%q) = false, want true", addr)
		}
	}
	// The addresses a private-egress deployment actually needs stay allowed.
	for _, addr := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "93.184.216.34"} {
		if IsAlwaysDeniedIP(addr) {
			t.Errorf("IsAlwaysDeniedIP(%q) = true, want false", addr)
		}
	}
}

func TestValidateDestinationURL(t *testing.T) {
	refuse := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:9200/_cluster/health",
		"http://[::1]:9200/",
		"file:///etc/passwd",
		"gopher://127.0.0.1:11211/_stats",
		"not-a-url-at-all",
		"https://",
	}
	for _, raw := range refuse {
		if err := ValidateDestinationURL(raw, false); err == nil {
			t.Errorf("ValidateDestinationURL(%q, allowPrivate=false) = nil, want an error", raw)
		}
	}

	// POSITIVE CONTROL: the shapes real installs ship. The in-cluster
	// hostname is the important one — resolving it here would refuse every
	// Kubernetes deployment, so a hostname is a dial-time question.
	accept := []string{
		"https://hooks.example.com/ingest",
		"http://otel-collector.observability.svc.cluster.local:4318/v1/logs",
		"https://siem.example.com/ingest?x=1",
	}
	for _, raw := range accept {
		if err := ValidateDestinationURL(raw, false); err != nil {
			t.Errorf("ValidateDestinationURL(%q, allowPrivate=false) = %v, want nil", raw, err)
		}
	}

	// With the knob on, a private literal is accepted — but link-local is
	// still refused, because that is not what the knob is for.
	if err := ValidateDestinationURL("http://127.0.0.1:4318/v1/logs", true); err != nil {
		t.Errorf("allowPrivate must accept loopback: %v", err)
	}
	if err := ValidateDestinationURL("http://169.254.169.254/", true); err == nil {
		t.Error("allowPrivate must NOT re-open the cloud metadata service")
	}
}

func TestValidateDestinationHost(t *testing.T) {
	if err := ValidateDestinationHost("169.254.169.254", false); err == nil {
		t.Error("link-local syslog host accepted")
	}
	if err := ValidateDestinationHost("", false); err == nil {
		t.Error("empty syslog host accepted")
	}
	// POSITIVE CONTROL: a sidecar hostname is the normal syslog shape.
	if err := ValidateDestinationHost("syslog-sidecar", false); err != nil {
		t.Errorf("sidecar hostname refused: %v", err)
	}
}

// TestClient_RedirectPolicyIndependentOfAllowPrivate pins the property that
// makes the redirect guard trustworthy: allowPrivate says where you may dial,
// never whether a 3xx is followed. If flipping the knob also disarmed
// CheckRedirect, the operators most likely to flip it would be the ones whose
// signed deliveries could be bounced off-host.
func TestClient_RedirectPolicyIndependentOfAllowPrivate(t *testing.T) {
	for _, allowPrivate := range []bool{false, true} {
		c := Client(allowPrivate, 7*time.Second, 0)
		if c.CheckRedirect == nil {
			t.Fatalf("allowPrivate=%v: CheckRedirect is nil — redirects would be followed", allowPrivate)
		}
		if err := c.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
			t.Errorf("allowPrivate=%v: maxRedirects=0 must stop at the 3xx, got %v", allowPrivate, err)
		}
		// The caller's timeout is used verbatim: callers size their context
		// budgets from it.
		if c.Timeout != 7*time.Second {
			t.Errorf("allowPrivate=%v: timeout was rewritten to %v", allowPrivate, c.Timeout)
		}
	}

	// A caller that genuinely needs discovery hops (issuer metadata) gets a
	// bounded number of them.
	c := Client(false, time.Second, 3)
	if err := c.CheckRedirect(nil, make([]*http.Request, 2)); err != nil {
		t.Errorf("hop 2 of 3 refused: %v", err)
	}
	if err := c.CheckRedirect(nil, make([]*http.Request, 3)); err == nil {
		t.Error("hop 3 of 3 allowed — the cap does not hold")
	}
}
