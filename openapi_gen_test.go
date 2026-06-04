// OpenAPI spec generation + freshness gate.
//
// huma owns BOTH serving and the spec: YAuth.OpenAPI() returns huma's
// auto-derived *huma.OpenAPI for every route the plugins registered. There is
// no hand-written spec to drift against any more, so the published openapi.json
// at the repo root is generated FROM the full plugin stack and checked into git.
//
// Two tests keep that file honest:
//
//   - TestGenerateOpenAPI (gated by YAUTH_GEN_OPENAPI=1) regenerates
//     openapi.json on disk. Run it whenever a route or schema changes:
//
//	YAUTH_GEN_OPENAPI=1 go test -run TestGenerateOpenAPI .
//
//   - TestOpenAPISpecUpToDate runs in the default suite (UNgated). It rebuilds
//     the spec in memory and asserts byte-equality with the committed
//     openapi.json, so a route/schema change that forgets to regenerate fails
//     CI rather than silently shipping a stale spec.
//
// The build is deterministic: encoding/json sorts map keys, and the only
// per-run-random input (buildFullStack's RSA key) never reaches the spec — its
// KID is a constant and no key material is serialized into any operation.

package yauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/plugins/admin"
	"github.com/yackey-labs/yauth-go/plugins/apikey"
	"github.com/yackey-labs/yauth-go/plugins/asymjwt"
	"github.com/yackey-labs/yauth-go/plugins/auditexport"
	"github.com/yackey-labs/yauth-go/plugins/bearer"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/plugins/lockout"
	"github.com/yackey-labs/yauth-go/plugins/magiclink"
	"github.com/yackey-labs/yauth-go/plugins/mfa"
	"github.com/yackey-labs/yauth-go/plugins/oauth"
	"github.com/yackey-labs/yauth-go/plugins/oauth/providers"
	"github.com/yackey-labs/yauth-go/plugins/oauth2server"
	"github.com/yackey-labs/yauth-go/plugins/oidc"
	"github.com/yackey-labs/yauth-go/plugins/organizations"
	"github.com/yackey-labs/yauth-go/plugins/passkey"
	"github.com/yackey-labs/yauth-go/plugins/scim"
	"github.com/yackey-labs/yauth-go/plugins/ssooidc"
	"github.com/yackey-labs/yauth-go/plugins/ssosaml"
	"github.com/yackey-labs/yauth-go/plugins/status"
	"github.com/yackey-labs/yauth-go/plugins/webhooks"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

// openapiSpecPath is the committed spec at the repo root.
const openapiSpecPath = "openapi.json"

// renderSpec builds the full plugin stack and marshals huma's auto-derived
// OpenAPI document exactly as it is written to openapi.json (indented, with a
// trailing newline). Both the generator and the freshness gate go through this
// single function so they can never diverge.
func renderSpec(t *testing.T) []byte {
	t.Helper()
	ya := buildFullStack(t)
	body, err := json.MarshalIndent(ya.OpenAPI(), "", "  ")
	if err != nil {
		t.Fatalf("marshal openapi: %v", err)
	}
	return append(body, '\n')
}

// TestGenerateOpenAPI regenerates the committed openapi.json from huma's
// auto-derived spec. It is gated behind YAUTH_GEN_OPENAPI=1 so a normal
// `go test ./...` never rewrites the file:
//
//	YAUTH_GEN_OPENAPI=1 go test -run TestGenerateOpenAPI .
func TestGenerateOpenAPI(t *testing.T) {
	if os.Getenv("YAUTH_GEN_OPENAPI") == "" {
		t.Skip("set YAUTH_GEN_OPENAPI=1 to regenerate openapi.json")
	}
	if err := os.WriteFile(openapiSpecPath, renderSpec(t), 0o644); err != nil {
		t.Fatalf("write %s: %v", openapiSpecPath, err)
	}
	t.Logf("wrote %s from huma-derived spec", openapiSpecPath)
}

// TestOpenAPISpecUpToDate is the freshness gate: it regenerates the spec in
// memory and asserts byte-equality with the committed openapi.json. A route or
// schema change that forgets to run TestGenerateOpenAPI fails here.
func TestOpenAPISpecUpToDate(t *testing.T) {
	want, err := os.ReadFile(openapiSpecPath)
	if err != nil {
		t.Fatalf("read %s: %v", openapiSpecPath, err)
	}
	got := renderSpec(t)
	if string(got) != string(want) {
		t.Fatalf("%s is stale; regenerate with:\n\tYAUTH_GEN_OPENAPI=1 go test -run TestGenerateOpenAPI .", openapiSpecPath)
	}
}

// buildFullStack builds a YAuth with every plugin enabled, configured just
// enough that each plugin's New() succeeds and registers its full route set
// (notably oauth2server with DCR enabled so /oauth/register is served). The
// repo is an in-memory sqlite — no route registration depends on the data, only
// on construction succeeding.
func buildFullStack(t *testing.T) *yauth.YAuth {
	t.Helper()

	db, err := gormrepo.OpenSQLite("file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// Migrate so background workers (e.g. webhooks claimer, which starts in
	// Routes regardless of WorkerCount) don't log missing-table warnings.
	// Route registration itself touches no data.
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := gormrepo.New(db)

	// A real RSA key so asymjwt.New (and thus the oidc id_token signer path)
	// constructs cleanly. The key is regenerated each run but never reaches the
	// spec (its KID is the constant below), so spec output stays deterministic.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	asym, err := asymjwt.New(asymjwt.Config{
		KeyType:       "RS256",
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		KID:           "openapi-gen-key",
	})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}

	var encKey [32]byte
	for i := range encKey {
		encKey[i] = byte(i + 1)
	}

	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: encKey, Issuer: "yauth"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}

	oauthPlugin, err := oauth.New(oauth.Config{
		EncryptionKey: encKey,
		StateTTL:      5 * time.Minute,
		Providers: []oauth.Provider{
			providers.Google(providers.GoogleConfig{ClientID: "x", ClientSecret: "y", RedirectURL: "https://localhost/cb"}),
		},
	})
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}

	passkeyPlugin, err := passkey.New(passkey.Config{
		RPID:      "localhost",
		RPName:    "yauth",
		RPOrigins: []string{"https://localhost"},
	})
	if err != nil {
		t.Fatalf("passkey.New: %v", err)
	}

	ssoOIDCPlugin, err := ssooidc.New(ssooidc.Config{
		EncryptionKey:       encKey,
		StateTTL:            5 * time.Minute,
		JWKSCacheTTL:        time.Minute,
		JWKSRefreshCooldown: time.Second,
	})
	if err != nil {
		t.Fatalf("ssooidc.New: %v", err)
	}

	ssoSAMLPlugin, err := ssosaml.New(ssosaml.Config{
		EncryptionKey:   encKey,
		AuthnRequestTTL: 5 * time.Minute,
		ReplayCacheTTL:  5 * time.Minute,
		ClockSkew:       time.Minute,
	})
	if err != nil {
		t.Fatalf("ssosaml.New: %v", err)
	}

	const apiKeyPrefix = "yauth_ak"

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(bearer.New(bearer.Config{JWTSecret: []byte("test-secret-for-openapi-gen-32by")})).
		WithPlugin(apikey.New(apikey.Config{Prefix: apiKeyPrefix})).
		WithPlugin(magiclink.New(magiclink.Config{})).
		WithPlugin(lockout.New(lockout.Config{})).
		WithPlugin(status.New()).
		WithPlugin(admin.New()).
		WithPlugin(mfaPlugin).
		WithPlugin(passkeyPlugin).
		WithPlugin(oauthPlugin).
		WithPlugin(webhooks.New(webhooks.Config{})).
		WithPlugin(asym).
		WithPlugin(oidc.New(oidc.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{DCREnabled: true})).
		WithPlugin(organizations.New(organizations.Config{APIKeyPrefix: apiKeyPrefix})).
		WithPlugin(ssoOIDCPlugin).
		WithPlugin(ssoSAMLPlugin).
		WithPlugin(scim.New(scim.Config{APIKeyPrefix: apiKeyPrefix})).
		WithPlugin(auditexport.New(auditexport.Config{})).
		Build()
	if err != nil {
		t.Fatalf("build full stack: %v", err)
	}
	return ya
}
