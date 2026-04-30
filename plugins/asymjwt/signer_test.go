package asymjwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/plugins/asymjwt"
	"github.com/yackey-labs/yauth-go/repo"
)

// writeRSAKeys generates a fresh RSA-2048 keypair, writes the private
// key (PKCS8) and public key (PKIX) as PEM into dir, and returns the
// two paths.
func writeRSAKeys(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	privPath = filepath.Join(dir, "rsa.key")
	pubPath = filepath.Join(dir, "rsa.pub")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return privPath, pubPath
}

// writeECKeys does the same for ECDSA P-256.
func writeECKeys(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	privPath = filepath.Join(dir, "ec.key")
	pubPath = filepath.Join(dir, "ec.pub")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return privPath, pubPath
}

func TestSigner_RS256_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := writeRSAKeys(t, dir)

	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPath: priv, PublicKeyPath: pub, KID: "test-rs",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if signer.Algo() != "RS256" || signer.KID() != "test-rs" {
		t.Fatalf("algo/kid mismatch: %s/%s", signer.Algo(), signer.KID())
	}

	tok, err := signer.Sign(map[string]any{
		"sub":   "user-123",
		"email": "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims["sub"] != "user-123" || claims["email"] != "alice@example.com" {
		t.Fatalf("claims roundtrip mismatch: %#v", claims)
	}
}

func TestSigner_ES256_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := writeECKeys(t, dir)

	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType: "ES256", PrivateKeyPath: priv, PublicKeyPath: pub, KID: "test-es",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := signer.Sign(map[string]any{"sub": "u-42"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims["sub"] != "u-42" {
		t.Fatalf("claims mismatch: %#v", claims)
	}
}

func TestSigner_PublicJWKS_ContainsKey(t *testing.T) {
	dir := t.TempDir()
	priv, pub := writeRSAKeys(t, dir)
	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPath: priv, PublicKeyPath: pub, KID: "yauth-2026",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	body, err := signer.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(parsed.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(parsed.Keys))
	}
	k := parsed.Keys[0]
	if k["kid"] != "yauth-2026" {
		t.Fatalf("kid mismatch: %v", k["kid"])
	}
	if k["alg"] != "RS256" {
		t.Fatalf("alg mismatch: %v", k["alg"])
	}
	if k["kty"] != "RSA" {
		t.Fatalf("kty mismatch: %v", k["kty"])
	}
	if k["use"] != "sig" {
		t.Fatalf("use mismatch: %v", k["use"])
	}
	// JWK MUST NOT leak private fields.
	for _, forbidden := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, has := k[forbidden]; has {
			t.Fatalf("public JWKS leaked private field %q", forbidden)
		}
	}
}

func TestPlugin_RoutesJWKS(t *testing.T) {
	dir := t.TempDir()
	priv, pub := writeRSAKeys(t, dir)

	p, err := asymjwt.New(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPath: priv, PublicKeyPath: pub, KID: "k1",
	})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}
	host := &captureHost{}
	mux := http.NewServeMux()
	p.Routes(host, mux, "")

	if host.signer == nil {
		t.Fatalf("expected SetJWTSigner to be called")
	}
	if host.signer.KID() != "k1" || host.signer.Algo() != "RS256" {
		t.Fatalf("registered signer mismatch: %s/%s", host.signer.Algo(), host.signer.KID())
	}

	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct == "" || ct[:16] != "application/json" {
		t.Fatalf("unexpected content-type: %q", ct)
	}
}

// captureHost records the JWTSigner registered via SetJWTSigner. It
// satisfies plugin.PluginHost so it can be passed to Plugin.Routes.
type captureHost struct {
	signer plugin.JWTSigner
}

func (h *captureHost) SetJWTSigner(s plugin.JWTSigner)            { h.signer = s }
func (h *captureHost) Repo() repo.Repository                      { return nil }
func (h *captureHost) Middleware() *middleware.Middleware         { return nil }
func (h *captureHost) SessionTTL() time.Duration                  { return 0 }
func (h *captureHost) CookieName() string                         { return "" }
func (h *captureHost) CookieDomain() string                       { return "" }
func (h *captureHost) CookieSecure() bool                         { return false }
func (h *captureHost) CookiePath() string                         { return "/" }
func (h *captureHost) CookieSameSite() http.SameSite              { return http.SameSiteLaxMode }
func (h *captureHost) RegisterEventHandler(_ events.Handler)      {}
func (h *captureHost) RegisterAuthResolver(_ plugin.AuthResolver) {}
func (h *captureHost) PluginNames() []string                      { return nil }
func (h *captureHost) JWTSigner() plugin.JWTSigner                { return h.signer }
func (h *captureHost) JWTSecret() []byte                          { return nil }
func (h *captureHost) Emit(_ context.Context, _ events.AuthEvent) (events.Decision, error) {
	return events.Continue(), nil
}
func (h *captureHost) RateLimit(_ string, _ int, _ time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

var _ plugin.PluginHost = (*captureHost)(nil)
