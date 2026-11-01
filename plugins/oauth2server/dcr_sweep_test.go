package oauth2server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newSweepHarness builds a yauth instance with DCR + the stale-client sweep
// enabled (short interval for the test). Returns the server + repo.
func newSweepHarness(t *testing.T, ttl, interval time.Duration) (*httptest.Server, *memrepo.Repo) {
	t.Helper()
	return newSweepHarnessWrapped(t, ttl, interval, nil)
}

// newSweepHarnessWrapped is newSweepHarness with the repo yauth sees
// optionally wrapped; the returned memrepo is the underlying store.
func newSweepHarnessWrapped(t *testing.T, ttl, interval time.Duration, wrap func(repo.Repository) repo.Repository) (*httptest.Server, *memrepo.Repo) {
	t.Helper()
	r := memrepo.New()
	var yr repo.Repository = r
	if wrap != nil {
		yr = wrap(r)
	}
	ya, err := yauth.New(yr, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:                "http://idp.test",
			BasePath:              "/api/auth",
			DCREnabled:            true,
			DCRStaleClientTTL:     ttl,
			DCRStaleSweepInterval: interval,
		})).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router())) // mounting triggers Routes → starts the sweep
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// TestDCR_MarksDynamicAndAudits proves an anonymously DCR-registered loopback
// client is flagged dynamically_registered and produces an oauth2.client.registered
// audit event (the durable record that survives a later sweep).
func TestDCR_MarksDynamicAndAudits(t *testing.T) {
	srv, r := newSweepHarness(t, 0, 0) // sweep disabled; just testing registration
	body := `{"redirect_uris":["http://127.0.0.1:51000/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"none","client_name":"Claude Code"}`
	resp, err := http.Post(srv.URL+"/api/auth/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("DCR register status %d", resp.StatusCode)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()

	cl, err := r.GetOAuth2ClientByClientID(context.Background(), reg.ClientID)
	if err != nil || cl == nil {
		t.Fatalf("get client: %v", err)
	}
	if !cl.DynamicallyRegistered {
		t.Fatal("DCR client must be marked dynamically_registered")
	}
	logs, _ := r.ListAuditLog(context.Background(), domain.ListAuditFilters{Limit: 50})
	var sawReg bool
	for _, e := range logs {
		if e.EventType == "oauth2.client.registered" {
			sawReg = true
		}
	}
	if !sawReg {
		t.Fatal("expected oauth2.client.registered audit event")
	}
}

// TestDCRSweep_ReclaimsStale proves the background sweep purges an unused DCR
// client, leaves admin-provisioned clients alone, and writes an
// oauth2.client.swept audit event.
func TestDCRSweep_ReclaimsStale(t *testing.T) {
	// Slow the audit write so the delete-then-audit gap the sweep has in
	// production is wide here too: a test that reads the audit log once,
	// as soon as the client disappears, fails every time against this.
	srv, r := newSweepHarnessWrapped(t, time.Hour, 40*time.Millisecond,
		func(inner repo.Repository) repo.Repository { return slowAuditRepo{inner} })
	_ = srv
	ctx := context.Background()
	old := time.Now().UTC().Add(-48 * time.Hour)

	// Stale DCR client (old, unused) + an old admin-provisioned client.
	mk := func(id, cid string, dyn bool) {
		if err := r.CreateOAuth2Client(ctx, domain.NewOAuth2Client{
			ID: id, ClientID: cid, IsPublic: true,
			RedirectURIs: jsonArr(), GrantTypes: jsonArr(), Scopes: jsonArr(),
			CreatedAt: old, DynamicallyRegistered: dyn,
		}); err != nil {
			t.Fatalf("create %s: %v", cid, err)
		}
	}
	mk("c_stale", "stale-dcr", true)
	mk("c_admin", "admin-prov", false)

	// Wait for the ticker to run a sweep.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got, _ := r.GetOAuth2ClientByClientID(ctx, "stale-dcr"); got == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stale DCR client was not swept within deadline")
		}
		time.Sleep(30 * time.Millisecond)
	}
	if got, _ := r.GetOAuth2ClientByClientID(ctx, "admin-prov"); got == nil {
		t.Fatal("admin-provisioned client must survive the sweep")
	}
	// The sweep goroutine deletes first and audits after, so the client can
	// vanish a moment before the audit row lands. Wait for it on the same
	// deadline rather than reading once (that raced under -race in CI).
	for !sawAuditEvent(ctx, t, r, "oauth2.client.swept") {
		if time.Now().After(deadline) {
			t.Fatal("expected oauth2.client.swept audit event")
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// slowAuditRepo delays every audit write.
type slowAuditRepo struct{ repo.Repository }

func (s slowAuditRepo) LogAuditEvent(ctx context.Context, in domain.NewAuditLog) error {
	time.Sleep(200 * time.Millisecond)
	return s.Repository.LogAuditEvent(ctx, in)
}

func sawAuditEvent(ctx context.Context, t *testing.T, r *memrepo.Repo, eventType string) bool {
	t.Helper()
	logs, err := r.ListAuditLog(ctx, domain.ListAuditFilters{Limit: 50})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	for _, e := range logs {
		if e.EventType == eventType {
			return true
		}
	}
	return false
}

func jsonArr() []byte { return []byte(`[]`) }
