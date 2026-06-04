// Command apikey-example is a runnable demonstration of the api-key
// plugin alongside email-password.
//
// It opens an in-memory repository, builds a YAuth
// instance with the email-password and api-key plugins, and serves it
// under /api/auth/* on :3000.
//
// Try it:
//
//	go run ./examples/apikey
//
//	# in another shell:
//	curl -i -c jar.txt -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	# Mint a key (auth via session cookie). The plaintext is in the
//	# response's "key" field — capture it now, the server never returns
//	# it again.
//	curl -s -b jar.txt -X POST http://localhost:3000/api/auth/api-keys \
//	  -H 'Content-Type: application/json' \
//	  -d '{"name":"ci-bot","scopes":["read:users"]}'
//
//	# Use the key on a protected endpoint:
//	curl -i -H 'X-Api-Key: <KEY>' http://localhost:3000/api/auth/session
//
//	# List the user's keys (no secret material returned):
//	curl -s -b jar.txt http://localhost:3000/api/auth/api-keys
//
//	# Revoke a key by id:
//	curl -i -b jar.txt -X DELETE http://localhost:3000/api/auth/api-keys/<ID>
package main

import (
	"log"
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func main() {
	repo := memrepo.New()

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(apikey.New(apikey.Config{})).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	log.Printf("yauth-go api-key example listening on %s", addr)
	log.Printf("  1) register (sets a session cookie):")
	log.Printf("     curl -i -c jar.txt -X POST http://localhost%s/api/auth/register \\", addr)
	log.Printf("       -H 'Content-Type: application/json' \\")
	log.Printf("       -d '{\"email\":\"alice@example.com\",\"password\":\"correct horse battery staple\"}'")
	log.Printf("  2) mint an api key (one-shot plaintext in 'key'):")
	log.Printf("     curl -s -b jar.txt -X POST http://localhost%s/api/auth/api-keys \\", addr)
	log.Printf("       -H 'Content-Type: application/json' \\")
	log.Printf("       -d '{\"name\":\"ci-bot\"}'")
	log.Printf("  3) use the key:")
	log.Printf("     curl -i -H 'X-Api-Key: <KEY>' http://localhost%s/api/auth/session", addr)
	log.Printf("  4) revoke:")
	log.Printf("     curl -i -b jar.txt -X DELETE http://localhost%s/api/auth/api-keys/<ID>", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
