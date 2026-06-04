package oauth2server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/gormrepo"
)

// newSweepHarness builds a yauth instance with DCR + the stale-client sweep
// enabled (short interval for the test). Returns the server + repo.
func newSweepHarness(t *testing.T, ttl, interval time.Duration) (*httptest.Server, *gormrepo.Repo) {
	t.Helper()
	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
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
	srv, r := newSweepHarness(t, time.Hour, 40*time.Millisecond)
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
	logs, _ := r.ListAuditLog(ctx, domain.ListAuditFilters{Limit: 50})
	var sawSwept bool
	for _, e := range logs {
		if e.EventType == "oauth2.client.swept" {
			sawSwept = true
		}
	}
	if !sawSwept {
		t.Fatal("expected oauth2.client.swept audit event")
	}
}

func jsonArr() []byte { return []byte(`[]`) }
