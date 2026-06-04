// Command passkey-example demonstrates the WebAuthn / passkey plugin.
//
// It boots an in-memory repository, builds yauth-go with both the
// email-password and passkey plugins, and serves them under /api/auth/.
//
// End-to-end exercise of the passkey ceremonies (register/finish,
// login/finish) requires a real authenticator (browser + platform/security
// key) — this example only stands up the endpoints. Pair it with the Vue
// frontend example to exercise the full flow.
//
// Try it:
//
//	go run ./examples/passkey
//
// Then, with a real browser:
//
//	# 1. register an email/password account to get a session cookie
//	curl -i -c jar -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	# 2. start a passkey registration ceremony (returns CredentialCreation
//	#    options + request_id; pass these to navigator.credentials.create)
//	curl -i -b jar -X POST http://localhost:3000/api/auth/passkeys/register/begin
//
//	# 3. POST the resulting attestation back to /passkeys/register/finish
//	#    with {request_id, response: PublicKeyCredential}
//
//	# 4. start a login ceremony (no body or {"email":"..."} for allow-list)
//	curl -i -X POST http://localhost:3000/api/auth/passkey/login/begin
//
//	# 5. POST {request_id, response} to /passkey/login/finish to get a cookie
package main

import (
	"log"
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/passkey"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func main() {
	repo := memrepo.New()

	pkPlugin, err := passkey.New(passkey.Config{
		RPID:      "localhost",
		RPOrigins: []string{"http://localhost:3000"},
		RPName:    "yauth-example",
	})
	if err != nil {
		log.Fatalf("passkey.New: %v", err)
	}

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(pkPlugin).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	log.Printf("yauth-go passkey example listening on %s", addr)
	log.Printf("note: end-to-end passkey ceremonies require a browser-based authenticator")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
