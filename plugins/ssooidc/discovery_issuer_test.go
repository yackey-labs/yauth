// discovery_issuer_test.go — the discovery document is allowed to name
// whatever issuer it likes, and every later check trusts that name.
//
// fetchDiscovery (discovery.go) GETs the configured discovery_url, parses the
// JSON, and presence-checks issuer / authorization_endpoint / token_endpoint /
// jwks_uri. It never compares the `issuer` the document claims against the
// origin the document was actually served from.
//
// That omission is what makes the id_token check downstream circular.
// handlers_login.go passes disco.Issuer into jwksCache.verifyIDToken as the
// expected `iss`, and disco.JWKSURL as the key source — both read out of the
// same untrusted document. So a document served by evil.example that claims
// `issuer: https://login.microsoftonline.com/...` and points jwks_uri at its
// own keys validates perfectly: the token's iss matches the claimed issuer,
// the signature matches the claimed keys, and nothing anywhere ties either
// back to the host the operator actually configured. The provider namespace
// that ExternalIdentity rows are keyed by (IssuerKeyFromDiscoveryURL) is the
// one place the real origin survives — which is why an issuer that lies is a
// cross-connection identity-collision primitive as well as a spoof.
//
// The pin has to be ORIGIN ONLY. Azure AD serves
// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
// with issuer https://login.microsoftonline.com/{tenant}/v2.0, and Google
// serves /.well-known/openid-configuration off accounts.google.com with
// issuer https://accounts.google.com — the PATH legitimately differs in both.
// TestFetchDiscovery_AcceptsIssuerWithDifferentPath is the positive control
// that keeps a path-sensitive comparison from shipping and locking out the
// two most common IdPs in the world.
package ssooidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// discoveryServing spins a server that answers <mount>/.well-known/
// openid-configuration with a document whose issuer is issuerFn(base), where
// base is this server's own origin (resolved at request time, since the port
// is not known until the listener is up).
func discoveryServing(t *testing.T, mount string, issuerFn func(base string) string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc(mount+"/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		issuer := issuerFn(srv.URL)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	})
	return srv
}

// TestFetchDiscovery_RejectsIssuerFromAnotherOrigin: a document that names an
// issuer on a host other than the one that served it is a document claiming
// to be someone else. Refuse it at the fetch, before disco.Issuer becomes the
// expected `iss` of every id_token this connection ever validates.
func TestFetchDiscovery_RejectsIssuerFromAnotherOrigin(t *testing.T) {
	srv := discoveryServing(t, "", func(string) string {
		return "https://login.microsoftonline.com/common/v2.0"
	})

	doc, err := fetchDiscovery(context.Background(), srv.Client(), srv.URL+"/.well-known/openid-configuration")
	if err == nil {
		t.Fatalf("fetchDiscovery accepted a document served by %s that claims issuer %q; "+
			"every id_token check downstream now compares iss against that claim",
			srv.URL, doc.Issuer)
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("rejected, but not for the issuer: %v", err)
	}
}

// TestFetchDiscovery_AcceptsIssuerWithDifferentPath is the positive control:
// same scheme, host and port, different path — the Azure AD / Google shape.
// This must keep working.
func TestFetchDiscovery_AcceptsIssuerWithDifferentPath(t *testing.T) {
	srv := discoveryServing(t, "/tenant-a/v2.0", func(base string) string {
		return base + "/tenant-a/v2.0"
	})

	doc, err := fetchDiscovery(context.Background(), srv.Client(), srv.URL+"/tenant-a/v2.0")
	if err != nil {
		t.Fatalf("a same-origin issuer with a different path was rejected — this is the Azure AD and "+
			"Google shape and must keep working: %v", err)
	}
	if want := srv.URL + "/tenant-a/v2.0"; doc.Issuer != want {
		t.Fatalf("issuer = %q, want %q", doc.Issuer, want)
	}
}
