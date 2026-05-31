// Command oauth2server-example is a runnable demo of the
// oauth2-server plugin alongside email-password and bearer.
//
// On startup it:
//   - opens an in-memory SQLite database and runs migrations,
//   - registers a confidential demo client with grant_types
//     authorization_code + refresh_token + client_credentials and
//     redirect_uri http://localhost:3000/callback,
//   - prints a curl walkthrough through the full authorize → consent
//     → token flow.
//
// Try it:
//
//	go run ./examples/oauth2server
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/bearer"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/plugins/oauth2server"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

func main() {
	dsn := "file::memory:?cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)

	jwtSecret := []byte("dev-only-jwt-secret-change-me-please-32b")

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret(jwtSecret).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:          "http://localhost:3000",
			BasePath:        "/api/auth",
			VerificationURI: "http://localhost:3000/api/auth/oauth2/device",
		})).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	// Pre-register a demo OAuth2 client and dump a sample PKCE pair
	// the curl walkthrough uses.
	ctx := context.Background()
	clientID, clientSecret := registerDemoClient(ctx, r)
	verifier, challenge := pkcePair()

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	log.Printf("yauth-go oauth2-server example listening on %s", addr)
	log.Printf("")
	log.Printf("  demo client_id     = %s", clientID)
	log.Printf("  demo client_secret = %s", clientSecret)
	log.Printf("  pkce code_verifier = %s", verifier)
	log.Printf("  pkce code_challenge= %s (S256)", challenge)
	log.Printf("")
	log.Printf("walkthrough:")
	log.Printf("  1) register a user:")
	log.Printf("     curl -i -c jar.txt -X POST http://localhost%s/api/auth/register \\", addr)
	log.Printf("       -H 'Content-Type: application/json' \\")
	log.Printf("       -d '{\"email\":\"alice@example.com\",\"password\":\"correct horse battery staple\"}'")
	log.Printf("")
	log.Printf("  2) GET /authorize  (returns either {redirect_url} or {client, scopes, csrf_token, request_id}):")
	log.Printf("     curl -s -b jar.txt 'http://localhost%s/api/auth/oauth/authorize?response_type=code&client_id=%s&redirect_uri=http://localhost:3000/callback&scope=openid+read&state=xyz&code_challenge=%s&code_challenge_method=S256'", addr, clientID, challenge)
	log.Printf("")
	log.Printf("  3) POST /consent with the request_id+csrf_token from step 2 → {redirect_url}")
	log.Printf("     curl -s -b jar.txt -X POST http://localhost%s/api/auth/oauth2/consent \\", addr)
	log.Printf("       -H 'Content-Type: application/json' \\")
	log.Printf("       -d '{\"request_id\":\"<id>\",\"csrf_token\":\"<csrf>\",\"approved\":true}'")
	log.Printf("")
	log.Printf("  4) extract code= from the redirect URL, then exchange:")
	log.Printf("     curl -s -X POST http://localhost%s/api/auth/oauth2/token \\", addr)
	log.Printf("       -d 'grant_type=authorization_code' -d 'code=<code>' \\")
	log.Printf("       -d 'redirect_uri=http://localhost:3000/callback' \\")
	log.Printf("       -d 'client_id=%s' -d 'client_secret=%s' \\", clientID, clientSecret)
	log.Printf("       -d 'code_verifier=%s'", verifier)
	log.Printf("")
	log.Printf("  5) introspect the issued access token:")
	log.Printf("     curl -s -X POST -u '%s:%s' \\", clientID, clientSecret)
	log.Printf("       --data-urlencode 'token=<access_token>' http://localhost%s/api/auth/oauth2/introspect", addr)
	log.Printf("")
	log.Printf("  6) revoke (idempotent):")
	log.Printf("     curl -i -X POST -u '%s:%s' \\", clientID, clientSecret)
	log.Printf("       --data-urlencode 'token=<refresh_token>' http://localhost%s/api/auth/oauth2/revoke", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func registerDemoClient(ctx context.Context, r *gormrepo.Repo) (string, string) {
	clientID := mustHex(16)
	rawSecret := mustHex(24)
	hash, err := auth.HashPassword(rawSecret)
	if err != nil {
		log.Fatalf("hash secret: %v", err)
	}
	method := "client_secret_post"
	name := "demo client"
	now := time.Now().UTC()
	if err := r.CreateOAuth2Client(ctx, domain.NewOAuth2Client{
		ID:                      uuid.NewString(),
		ClientID:                clientID,
		ClientSecretHash:        &hash,
		RedirectURIs:            mustJSON([]string{"http://localhost:3000/callback"}),
		ClientName:              &name,
		GrantTypes:              mustJSON([]string{"authorization_code", "refresh_token", "client_credentials"}),
		Scopes:                  mustJSON([]string{"openid", "read"}),
		IsPublic:                false,
		CreatedAt:               now,
		TokenEndpointAuthMethod: &method,
	}); err != nil {
		log.Fatalf("create client: %v", err)
	}
	return clientID, rawSecret
}

func mustHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(buf)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	return b
}

func pkcePair() (verifier, challenge string) {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}
