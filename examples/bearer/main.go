// Command bearer-example is a runnable demonstration of the bearer
// (JWT) plugin alongside email-password.
//
// It opens an in-memory repository, builds a
// YAuth instance with email-password + bearer plugins, and serves it
// under /api/auth/* on :3000.
//
// Try it:
//
//	go run ./examples/bearer
//
//	# in another shell:
//	curl -i -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	# Mint an access + refresh token:
//	curl -s -X POST http://localhost:3000/api/auth/token \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	# Use the access token:
//	curl -i -H 'Authorization: Bearer <ACCESS>' http://localhost:3000/api/auth/session
//
//	# Rotate the refresh token:
//	curl -s -X POST http://localhost:3000/api/auth/token/refresh \
//	  -H 'Content-Type: application/json' \
//	  -d '{"refresh_token":"<REFRESH>"}'
//
//	# Revoke a refresh token (auth required — pass either a Bearer access
//	# token or the session cookie):
//	curl -i -X POST http://localhost:3000/api/auth/token/revoke \
//	  -H 'Authorization: Bearer <ACCESS>' \
//	  -H 'Content-Type: application/json' \
//	  -d '{"refresh_token":"<REFRESH>"}'
package main

import (
	"log"
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func main() {
	repo := memrepo.New()

	// In production load this from a secret store and use ≥ 32 bytes.
	jwtSecret := []byte("dev-only-jwt-secret-change-me-please-32b")

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithJWTSecret(jwtSecret).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(bearer.New(bearer.Config{})). // picks up jwtSecret from host
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	log.Printf("yauth-go bearer example listening on %s", addr)
	log.Printf("  1) register:")
	log.Printf("     curl -i -X POST http://localhost%s/api/auth/register \\", addr)
	log.Printf("       -H 'Content-Type: application/json' \\")
	log.Printf("       -d '{\"email\":\"alice@example.com\",\"password\":\"correct horse battery staple\"}'")
	log.Printf("  2) mint tokens:")
	log.Printf("     curl -s -X POST http://localhost%s/api/auth/token \\", addr)
	log.Printf("       -H 'Content-Type: application/json' \\")
	log.Printf("       -d '{\"email\":\"alice@example.com\",\"password\":\"correct horse battery staple\"}'")
	log.Printf("  3) use access token:")
	log.Printf("     curl -i -H 'Authorization: Bearer <ACCESS>' http://localhost%s/api/auth/session", addr)
	log.Printf("  4) rotate refresh token:")
	log.Printf("     curl -s -X POST http://localhost%s/api/auth/token/refresh \\", addr)
	log.Printf("       -H 'Content-Type: application/json' \\")
	log.Printf("       -d '{\"refresh_token\":\"<REFRESH>\"}'")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
