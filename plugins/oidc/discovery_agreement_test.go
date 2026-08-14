package oidc_test

// yauth publishes TWO metadata documents describing ONE authorization server:
// /.well-known/openid-configuration (plugins/oidc/handlers.go, discovery) and
// /.well-known/oauth-authorization-server (plugins/oauth2server/metadata.go,
// handleAuthServerMetadata). A relying party picks whichever one its library
// prefers, so any disagreement between them is a client that mis-configures
// itself against a real endpoint.
//
// They disagree today, and the OIDC one also advertises things that do not
// exist:
//
//   - jwks_uri and id_token_signing_alg_values_supported are emitted
//     UNCONDITIONALLY. With no asymjwt plugin loaded there is no JWKS route at
//     all and no HS256 key an RP could ever fetch, yet discovery still names the
//     URL and claims HS256. metadata.go gets this right — it gates both on
//     host.JWTSigner() != nil.
//   - registration_endpoint is advertised whenever oauth2-server is loaded,
//     while metadata.go gates it on the DCREnabled flag that actually governs
//     the endpoint.
//   - grant_types_supported omits client_credentials and the device-code grant
//     that this same server implements.
//   - code_challenge_methods_supported is missing entirely, although PKCE S256
//     is mandatory at /oauth/authorize.
//   - scopes_supported disagrees: oidc says [openid email profile groups],
//     oauth2 says [openid email profile].
//
// The two tests below pin the invariants: advertise a JWKS only when one exists,
// and never let the two documents describe different servers.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// getJSONDoc fetches path and decodes the JSON body.
func getJSONDoc(t *testing.T, base, path string) map[string]any {
	t.Helper()
	res, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get %s: status=%d", path, res.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return doc
}

// TestDiscovery_NoSignerOmitsJWKSURI: with no asymmetric signer there is no JWKS
// route, so the discovery document must not name one — nor claim an id_token
// signing algorithm the deployment cannot produce a public key for.
func TestDiscovery_NoSignerOmitsJWKSURI(t *testing.T) {
	r := memrepo.New()
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oidc.New(oidc.Config{Issuer: "http://idp.test", BasePath: "/api/auth"})).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	doc := getJSONDoc(t, srv.URL, "/api/auth/.well-known/openid-configuration")

	// The advertised JWKS is not actually served — this is the proof the claim
	// is false, not merely a style preference.
	if jwks, ok := doc["jwks_uri"].(string); ok && jwks != "" {
		res, err := http.Get(srv.URL + "/api/auth/.well-known/jwks.json")
		if err != nil {
			t.Fatalf("fetch advertised jwks: %v", err)
		}
		defer res.Body.Close() //nolint:errcheck
		t.Fatalf("discovery advertises jwks_uri=%q with no signer loaded; fetching it returns %d", jwks, res.StatusCode)
	}
	if algs, ok := doc["id_token_signing_alg_values_supported"].([]any); ok && len(algs) > 0 {
		t.Fatalf("discovery advertises id_token_signing_alg_values_supported=%v with no signer loaded", algs)
	}
}

// TestDiscovery_AgreesWithAuthServerMetadata fetches both metadata documents from
// ONE server and requires them to describe the same authorization server.
func TestDiscovery_AgreesWithAuthServerMetadata(t *testing.T) {
	h := newOPHarness(t)
	oidcDoc := getJSONDoc(t, h.srv.URL, "/api/auth/.well-known/openid-configuration")
	oauthDoc := getJSONDoc(t, h.srv.URL, "/api/auth/.well-known/oauth-authorization-server")

	if oidcDoc["issuer"] != oauthDoc["issuer"] {
		t.Fatalf("issuer disagrees: oidc=%v oauth=%v", oidcDoc["issuer"], oauthDoc["issuer"])
	}
	for _, field := range []string{"authorization_endpoint", "token_endpoint"} {
		if oidcDoc[field] != oauthDoc[field] {
			t.Fatalf("%s disagrees: oidc=%v oauth=%v", field, oidcDoc[field], oauthDoc[field])
		}
	}
	// registration_endpoint: DCR is disabled on this harness, so the oauth2
	// document omits it. The OIDC document must not advertise it either.
	_, oidcHasReg := oidcDoc["registration_endpoint"]
	_, oauthHasReg := oauthDoc["registration_endpoint"]
	if oidcHasReg != oauthHasReg {
		t.Fatalf("registration_endpoint presence disagrees: oidc=%v oauth=%v (DCR is disabled on this server)",
			oidcDoc["registration_endpoint"], oauthDoc["registration_endpoint"])
	}
	for _, field := range []string{"grant_types_supported", "scopes_supported", "code_challenge_methods_supported"} {
		if !sameStringSet(oidcDoc[field], oauthDoc[field]) {
			t.Fatalf("%s disagrees: oidc=%v oauth=%v", field, oidcDoc[field], oauthDoc[field])
		}
	}
}

// TestDiscovery_DCREnabledAdvertisesRegistration is the POSITIVE CONTROL for the
// registration_endpoint gate. TestDiscovery_AgreesWithAuthServerMetadata proves
// the endpoint is not advertised when DCR is off; on its own that invariant is
// satisfiable by never advertising it at all, which would silently break every
// dynamic-registration client. With DCR ON the endpoint must be advertised, and
// both metadata documents must name the same URL.
func TestDiscovery_DCREnabledAdvertisesRegistration(t *testing.T) {
	r := memrepo.New()
	dir := t.TempDir()
	privPath, pubPath := writeRSAKeys(t, dir)
	asym, err := asymjwt.New(asymjwt.Config{KeyType: "RS256", PrivateKeyPath: privPath, PublicKeyPath: pubPath, KID: "test-kid"})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(asym).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer: "http://idp.test", BasePath: "/api/auth",
			AccessTTL: time.Minute, AuthCodeTTL: time.Minute, DCREnabled: true,
		})).
		WithPlugin(oidc.New(oidc.Config{Issuer: "http://idp.test", BasePath: "/api/auth"})).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	oidcDoc := getJSONDoc(t, srv.URL, "/api/auth/.well-known/openid-configuration")
	oauthDoc := getJSONDoc(t, srv.URL, "/api/auth/.well-known/oauth-authorization-server")

	reg, _ := oidcDoc["registration_endpoint"].(string)
	if reg == "" {
		t.Fatalf("DCR is enabled, but discovery omits registration_endpoint: %v", oidcDoc)
	}
	if reg != oauthDoc["registration_endpoint"] {
		t.Fatalf("registration_endpoint disagrees with DCR on: oidc=%q oauth=%v", reg, oauthDoc["registration_endpoint"])
	}
	// The advertised URL must actually be routed — the whole point of gating on
	// the routing table rather than on a duplicated config flag.
	res, err := http.Post(srv.URL+"/api/auth/oauth/register", "application/json", nil)
	if err != nil {
		t.Fatalf("post advertised registration_endpoint: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode == http.StatusNotFound {
		t.Fatalf("discovery advertises registration_endpoint=%q but it 404s", reg)
	}
}

// sameStringSet compares two decoded JSON arrays as unordered string sets.
func sameStringSet(a, b any) bool {
	toSet := func(v any) map[string]struct{} {
		out := map[string]struct{}{}
		list, _ := v.([]any)
		for _, item := range list {
			if s, ok := item.(string); ok {
				out[s] = struct{}{}
			}
		}
		return out
	}
	sa, sb := toSet(a), toSet(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if _, ok := sb[k]; !ok {
			return false
		}
	}
	return true
}
