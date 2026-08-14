// ssrf_test.go — the SSO connection's discovery_url is an admin-chosen
// destination, and until this suite passes it was an unguarded one.
//
// Every outbound call this plugin makes — discovery, JWKS, the token
// exchange, the DCR registration POST, the federation grant redemption —
// goes through one helper, ssoOIDCPlugin.httpClient() in plugin.go. That
// helper hands back a bare &http.Client{Timeout, Transport:
// otelhttp.NewTransport(http.DefaultTransport)}: no dial filter, so the
// address it connects to is whatever the caller's discovery_url resolves
// to. The only validation on the way in is config.go's "must start with
// https:// or http://".
//
// Two things fall out of that, and both are tested here.
//
//  1. The request is made at all. An org admin (org creation is open to any
//     signed-up user) sets discovery_url = http://127.0.0.1:<port> and POSTs
//     /organizations/{id}/sso/connections/{cid}/test. handlers_admin.go's
//     test handler calls fetchDiscovery with the default client, so the
//     server's own network position — loopback, the RFC 1918 VPC, the cloud
//     metadata service on 169.254.169.254 — becomes a destination the caller
//     picks. yauth already owns exactly one answer to this shape:
//     auth/safehttp, the egress guard the webhook, audit-export and
//     oauth2server jwks_uri fetches were moved onto. ssooidc never got it.
//
//  2. What comes back is narrated to the caller. handlers_admin.go and
//     global_connections.go both return huma.Error502BadGateway(err.Error()),
//     and on the PUBLIC /sso/callback route handlers_login.go does the same
//     with the error from exchangeCode — which is
//     fmt.Errorf("ssooidc: token endpoint returned %d: %s", status, body)
//     carrying up to 1 MiB of the upstream response. Point a connection's
//     discovery document at a token_endpoint inside the perimeter and the
//     callback route reads it out for you, unauthenticated.
//
// The positive controls matter as much as the refusals. A guard that simply
// made /test fail, or made the callback return a fixed string for every
// outcome, would "pass" a refusal-only suite while breaking the feature:
// TestTestConnection_ReachableIdPStillPasses proves a legitimately reachable
// IdP still round-trips and still reports its issuer, and
// TestCallback_SucceedsAgainstHealthyIdP is guarded by the same client.
package ssooidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- harness ----------------------------------------------------------
//
// The package already has newFakeHost/seedAdmin/doJSON (ssooidc_test.go);
// what it lacks is a server whose plugin was built with a specific HTTP
// client, because every existing fixture takes newPlugin(t)'s default. These
// two helpers are that, and nothing more.

// newPluginWithClient builds the plugin with an explicit outbound client.
// hc == nil means "use the plugin's own default client" — the path the SSRF
// guard has to cover, since that is what every real deployment runs.
func newPluginWithClient(t *testing.T, hc *http.Client) *ssoOIDCPlugin {
	t.Helper()
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	p, err := New(Config{
		EncryptionKey:       key,
		StateTTL:            5 * time.Minute,
		JWKSCacheTTL:        time.Minute,
		JWKSRefreshCooldown: time.Nanosecond,
		HTTPClient:          hc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*ssoOIDCPlugin)
}

// ssoAdminServer mounts the plugin behind a resolver that reports an
// org-owner admin — the principal the connection-CRUD and /test routes are
// written for.
func ssoAdminServer(t *testing.T, p *ssoOIDCPlugin) (*httptest.Server, repo.Repository, domain.Organization) {
	t.Helper()
	r := memrepo.New()
	admin, org := seedAdmin(t, r)
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return srv, r, org
}

// createConn creates an oidc_client connection over the real admin route and
// returns its id.
func createConn(t *testing.T, srv *httptest.Server, orgID, discoveryURL, status string) string {
	t.Helper()
	resp := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/sso/connections", map[string]any{
		"name":                     "IdP",
		"status":                   status,
		"jit_provisioning_enabled": true,
		"oidc": map[string]any{
			"discovery_url": discoveryURL,
			"client_id":     "rp-1",
			"client_secret": "rp-secret",
		},
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		t.Fatalf("create connection: status=%d body=%s", resp.StatusCode, body)
	}
	var created connectionJSON
	decode(t, resp, &created)
	return created.ID
}

// internalIDPService stands in for anything reachable from the yauth process
// and not from the caller: a Redis admin port, the Kubernetes API, the cloud
// metadata service. It answers as a complete, healthy IdP so that today's
// behaviour is unambiguous — the /test route round-trips it successfully —
// and it counts every request that reaches it, which is the assertion that
// matters: a refusal that still dials has already leaked.
func internalIDPService(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	hits := &atomic.Int64{}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		set := jwk.NewSet()
		k, err := jwk.Import(&key.PublicKey)
		if err != nil {
			t.Error(err)
			return
		}
		_ = k.Set(jwk.KeyIDKey, "internal-1")
		_ = k.Set(jwk.AlgorithmKey, jwa.RS256())
		_ = set.AddKey(k)
		buf, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	})
	return srv, hits
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close() //nolint:errcheck
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

// --- 1. the outbound fetch is unfiltered ------------------------------

// TestTestConnection_RefusesLoopbackDiscoveryURL: the /test route must not
// open a connection to an address the admin picked inside the perimeter.
//
// The assertion that matters is hits == 0, not the status code: a refusal
// that still dials has already leaked (the timing and the reachability of
// the port are the primitive, whatever the handler prints afterwards).
func TestTestConnection_RefusesLoopbackDiscoveryURL(t *testing.T) {
	internal, hits := internalIDPService(t)

	// nil client on purpose: this is the client every real deployment uses.
	p := newPluginWithClient(t, nil)
	srv, _, org := ssoAdminServer(t, p)
	cid := createConn(t, srv, org.ID, internal.URL+"/.well-known/openid-configuration", "draft")

	resp := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/sso/connections/"+cid+"/test", nil)
	status := resp.StatusCode
	body := readAll(t, resp)

	if got := hits.Load(); got != 0 {
		t.Errorf("the loopback service received %d request(s); the plugin dialled an address chosen by the caller", got)
	}
	if status == http.StatusOK {
		t.Errorf("test route reported success against a loopback discovery_url: body=%s", body)
	}
	if strings.Contains(body, internal.URL) {
		t.Errorf("test route read the internal service's own document back to the caller: %s", body)
	}
}

// TestGlobalTestConnection_RefusesLoopbackDiscoveryURL: the org-less twin in
// global_connections.go is a second copy of the same handler and must not be
// left behind.
func TestGlobalTestConnection_RefusesLoopbackDiscoveryURL(t *testing.T) {
	internal, hits := internalIDPService(t)

	p := newPluginWithClient(t, nil)
	r := memrepo.New()
	ctx := context.Background()
	now := time.Now().UTC()
	admin, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "root@example.com", Role: auth.RoleAdmin,
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	resp := doJSON(t, http.MethodPost, srv.URL+"/sso/connections", map[string]any{
		"name": "Global IdP",
		"oidc": map[string]any{
			"discovery_url": internal.URL + "/.well-known/openid-configuration",
			"client_id":     "rp-1",
			"client_secret": "rp-secret",
		},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create global connection: status=%d body=%s", resp.StatusCode, readAll(t, resp))
	}
	var created connectionJSON
	decode(t, resp, &created)

	resp = doJSON(t, http.MethodPost, srv.URL+"/sso/connections/"+created.ID+"/test", nil)
	status := resp.StatusCode
	body := readAll(t, resp)

	if got := hits.Load(); got != 0 {
		t.Errorf("the loopback service received %d request(s) from the GLOBAL test route", got)
	}
	if status == http.StatusOK {
		t.Errorf("global test route reported success against a loopback discovery_url: body=%s", body)
	}
}

// TestTestConnection_ReachableIdPStillPasses is the positive control for both
// refusals above: with the deployment's own HTTP client in place (the
// documented escape hatch for an in-cluster IdP, and what the yauth tests
// themselves run on), the round-trip still happens and still reports the
// issuer. A guard that blanket-fails /test does not survive this.
func TestTestConnection_ReachableIdPStillPasses(t *testing.T) {
	idp := newFakeIDP(t, "rp-1")
	p := newPluginWithClient(t, &http.Client{Timeout: 5 * time.Second})
	srv, _, org := ssoAdminServer(t, p)
	cid := createConn(t, srv, org.ID, idp.issuer+"/.well-known/openid-configuration", "draft")

	resp := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/sso/connections/"+cid+"/test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legitimate IdP: status=%d body=%s", resp.StatusCode, readAll(t, resp))
	}
	var out testConnectionResponse
	decode(t, resp, &out)
	if !out.OK || out.Issuer != idp.issuer {
		t.Fatalf("legitimate IdP round-trip lost its result: %+v", out)
	}
	if out.JWKSKeys == 0 {
		t.Fatalf("legitimate IdP: expected the JWKS fetch to report keys, got %+v", out)
	}
}

// --- 2. the upstream response is narrated to the caller ---------------

// leakIDP serves a discovery document whose token_endpoint answers with an
// error carrying a body — the shape of an internal service that responds to
// an unauthenticated POST with something worth reading.
type leakIDP struct {
	srv    *httptest.Server
	marker string
}

func newLeakIDP(t *testing.T) *leakIDP {
	t.Helper()
	l := &leakIDP{marker: "AKIA-EXAMPLE-INTERNAL-CREDENTIAL"}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	l.srv = srv
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"secret_material":"` + l.marker + `"}`))
	})
	return l
}

// TestCallback_DoesNotEchoUpstreamTokenEndpointBody: /sso/callback is PUBLIC —
// no session, no admin, anyone who can reach the app. It must not read an
// upstream response body out loud.
//
// The plugin is given a plain HTTP client here on purpose, so the dial guard
// is out of the picture and this test isolates the error-hygiene defect: even
// a destination the deployment is willing to reach must not have its body
// relayed to an anonymous caller.
func TestCallback_DoesNotEchoUpstreamTokenEndpointBody(t *testing.T) {
	leak := newLeakIDP(t)
	p := newPluginWithClient(t, &http.Client{Timeout: 5 * time.Second})
	srv, _, org := ssoAdminServer(t, p)
	createConn(t, srv, org.ID, leak.srv.URL+"/.well-known/openid-configuration", "active")

	// "acme" is seedAdmin's org slug; /sso/login resolves the connection by it.
	state, _ := beginLogin(t, srv, "acme")
	resp := callback(t, srv, state)
	status := resp.StatusCode
	cookies := resp.Cookies()
	body := readAll(t, resp)

	if strings.Contains(body, leak.marker) {
		t.Errorf("the public callback relayed the upstream token endpoint's response body to an anonymous caller:\n%s", body)
	}
	if strings.Contains(body, "token endpoint returned 403") {
		t.Errorf("the public callback narrated the upstream status to an anonymous caller:\n%s", body)
	}
	if status == http.StatusOK {
		t.Errorf("callback returned 200 after a failed code exchange: %s", body)
	}
	for _, c := range cookies {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Fatalf("a session cookie was issued despite the failed code exchange: %q", c.Value)
		}
	}
}
