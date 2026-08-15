// oidc_concurrency_test.go — lazy discovery mutates shared state with no lock.
//
// oidcProvider resolves its endpoints on first use rather than in the
// constructor, and Config() runs that resolution on EVERY call:
//
//	func (p *oidcProvider) Config() *oauth2.Config {
//	    _ = p.ensureResolved(context.Background())
//	    return &oauth2.Config{ ... AuthURL: p.authURL, TokenURL: p.tokenURL ... }
//	}
//
// ensureResolved writes p.resolved, p.authURL, p.tokenURL and p.userInfoURL.
// There is no mutex anywhere in plugins/oauth — the package does not import
// sync at all. One *oidcProvider is shared by every request that starts a
// social login, so two concurrent logins are two goroutines writing the same
// four fields while a third reads them.
//
// Two distinct defects, one cause:
//
//   - A data race in the Go memory model sense. Unsynchronised concurrent
//     access to these fields is undefined behaviour, not merely "probably
//     fine"; the race detector is the correct instrument and this test is
//     written to be run under it.
//
//   - An observable torn read. ensureResolved begins by RESETTING the three
//     endpoint fields to their configured values — empty strings, on a
//     discovery-based provider — and only repopulates them after the network
//     fetch returns. Any goroutine that reads p.authURL inside that window
//     sees "". Config() cannot report the failure (it discards the error by
//     design, so AuthCodeURL can stay synchronous), so the caller receives an
//     oauth2.Config with an EMPTY AuthURL and redirects the user to nowhere.
//
// The fix must also keep the constructor's contract: OIDC() performs no
// network I/O, so resolution has to stay lazy. Serialising it is enough, and
// has the side benefit of collapsing a thundering herd of concurrent discovery
// fetches into one.
package providers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// discoveryServer is an IdP well-known endpoint that is deliberately slow, to
// widen the window in which the endpoint fields are zeroed.
func discoveryServer(t *testing.T, hits *atomic.Int64) string {
	t.Helper()
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		time.Sleep(15 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"userinfo_endpoint":      base + "/userinfo",
		})
	}))
	t.Cleanup(srv.Close)
	base = srv.URL
	return srv.URL + "/.well-known/openid-configuration"
}

// TestOIDCProvider_ConcurrentConfigNeverYieldsAnEmptyEndpoint is the assertion
// that holds without the race detector: whatever the interleaving, no caller
// may be handed a config it cannot redirect with.
//
// Run under -race it additionally reports the unsynchronised writes directly.
func TestOIDCProvider_ConcurrentConfigNeverYieldsAnEmptyEndpoint(t *testing.T) {
	var hits atomic.Int64
	p, err := OIDC(OIDCConfig{
		ProviderName: "concurrent-idp",
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  "https://app.example/callback",
		DiscoveryURL: discoveryServer(t, &hits),
	})
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	bad := make(chan string, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cfg := p.Config()
			if cfg.Endpoint.AuthURL == "" {
				bad <- "AuthURL"
				return
			}
			if cfg.Endpoint.TokenURL == "" {
				bad <- "TokenURL"
			}
		}()
	}
	close(start)
	wg.Wait()
	close(bad)

	if n := len(bad); n > 0 {
		field := <-bad
		t.Fatalf("%d of %d concurrent Config() calls returned an empty %s: a login started during "+
			"another goroutine's discovery is redirected to an empty authorization endpoint", n, goroutines, field)
	}
}

// TestOIDCProvider_DiscoveryRunsOnce pins the other half of the fix. Serialising
// resolution is only correct if the second caller then REUSES the result; a
// naive lock that still re-ran discovery per call would turn every login into
// an outbound fetch and hand the IdP a self-inflicted thundering herd.
func TestOIDCProvider_DiscoveryRunsOnce(t *testing.T) {
	var hits atomic.Int64
	p, err := OIDC(OIDCConfig{
		ProviderName: "once-idp",
		ClientID:     "client",
		DiscoveryURL: discoveryServer(t, &hits),
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Config()
		}()
	}
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected discovery to be fetched exactly once for 16 concurrent Config() calls, got %d", got)
	}
}

// TestOIDCProvider_ExplicitEndpointsNeedNoDiscovery is the control for the
// non-discovery configuration: a provider given its endpoints outright must
// keep working, and must not acquire a network dependency from this change.
func TestOIDCProvider_ExplicitEndpointsNeedNoDiscovery(t *testing.T) {
	p, err := OIDC(OIDCConfig{
		ProviderName: "explicit-idp",
		ClientID:     "client",
		AuthURL:      "https://idp.example/authorize",
		TokenURL:     "https://idp.example/token",
		UserInfoURL:  "https://idp.example/userinfo",
		DiscoveryURL: "http://127.0.0.1:1/should-never-be-fetched",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := p.Config()
	if cfg.Endpoint.AuthURL != "https://idp.example/authorize" {
		t.Fatalf("explicit AuthURL was not used: %q", cfg.Endpoint.AuthURL)
	}
	if cfg.Endpoint.TokenURL != "https://idp.example/token" {
		t.Fatalf("explicit TokenURL was not used: %q", cfg.Endpoint.TokenURL)
	}
}
