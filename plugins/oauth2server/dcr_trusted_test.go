package oauth2server_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// peerIssuer is a fake registrant: it publishes OIDC discovery + a JWKS for a
// fresh RSA key and can sign software_statements with that key.
type peerIssuer struct {
	srv *httptest.Server
	key jwk.Key // private, with kid
}

func newPeerIssuer(t *testing.T) *peerIssuer {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, "peer-kid")
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256)
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": base, "jwks_uri": base + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL
	return &peerIssuer{srv: srv, key: key}
}

func (p *peerIssuer) sign(t *testing.T, iss string, redirectURIs []string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(iss).
		IssuedAt(now).
		Expiration(now.Add(5*time.Minute)).
		Claim("redirect_uris", redirectURIs).
		Claim("client_name", "Peer App").
		Claim("scope", "openid email").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, p.key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// trustedDCRServer builds an oauth2server that trusts `trusted` for software_statement DCR.
func trustedDCRServer(t *testing.T, trusted []string) (*httptest.Server, *memrepo.Repo) {
	t.Helper()
	r := memrepo.New()
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:                     "http://idp.test",
			BasePath:                   "/api/auth",
			DCREnabled:                 true,
			DCRTrustedIssuers:          trusted,
			AllowPrivateNetworkJWKSURI: true,
			DCRTrustedIssuerHTTPClient: http.DefaultClient,
		})).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

func postRegister(t *testing.T, srv *httptest.Server, body string) (int, map[string]any) {
	t.Helper()
	res, err := http.Post(srv.URL+"/api/auth/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close() //nolint:errcheck
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// Happy path: a statement signed by a trusted issuer self-registers a
// confidential client with NO admin credential.
func TestTrustedDCR_SelfRegistersConfidentialClient(t *testing.T) {
	peer := newPeerIssuer(t)
	srv, _ := trustedDCRServer(t, []string{peer.srv.URL})
	stmt := peer.sign(t, peer.srv.URL, []string{"https://app.test/api/auth/sso/callback"})

	code, out := postRegister(t, srv, `{"software_statement":"`+stmt+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%v", code, out)
	}
	if out["client_id"] == nil || out["client_secret"] == nil {
		t.Fatalf("expected confidential client creds, got %v", out)
	}
}

// An untrusted issuer is rejected even with a validly-signed statement.
func TestTrustedDCR_UntrustedIssuerRejected(t *testing.T) {
	peer := newPeerIssuer(t)
	srv, _ := trustedDCRServer(t, []string{"https://someone-else.test"}) // peer NOT trusted
	stmt := peer.sign(t, peer.srv.URL, []string{"https://app.test/api/auth/sso/callback"})

	code, _ := postRegister(t, srv, `{"software_statement":"`+stmt+`"}`)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for untrusted issuer", code)
	}
}

// A garbage statement is rejected.
func TestTrustedDCR_GarbageStatementRejected(t *testing.T) {
	peer := newPeerIssuer(t)
	srv, _ := trustedDCRServer(t, []string{peer.srv.URL})
	code, _ := postRegister(t, srv, `{"software_statement":"not-a-jwt"}`)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for garbage statement", code)
	}
}
