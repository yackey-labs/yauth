// Command mfa-example demonstrates the MFA plugin end-to-end.
//
// It boots an in-memory repository, builds yauth-go with both the
// email-password and MFA plugins, and serves them under /api/auth/.
// The mfa plugin's event handler intercepts the email-password
// login.succeeded event for users with verified TOTP secrets, returning
// a pending_session_id instead of a real session cookie. The caller
// finalizes login by POSTing to /api/auth/verify with the
// pending_session_id and a code (TOTP or backup code).
//
// Try it:
//
//	go run ./examples/mfa
//
// Then walk through:
//
//	# 1. register (no mfa yet → real session)
//	curl -i -c jar -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	# 2. start mfa setup (auth-required) — copy `secret` and `backup_codes`
//	curl -i -b jar -X POST http://localhost:3000/api/auth/totp/setup
//
//	# 3. compute a TOTP code (e.g. via `oathtool --totp -b SECRET`) and confirm
//	curl -i -b jar -X POST http://localhost:3000/api/auth/totp/confirm \
//	  -H 'Content-Type: application/json' -d '{"code":"123456"}'
//
//	# 4. logout, then login again — should now return require_mfa+pending_session_id
//	curl -i -b jar -X POST http://localhost:3000/api/auth/logout
//	curl -i -X POST http://localhost:3000/api/auth/login \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	# 5. complete with a TOTP or backup code
//	curl -i -X POST http://localhost:3000/api/auth/verify \
//	  -H 'Content-Type: application/json' \
//	  -d '{"pending_session_id":"...","code":"123456"}'
package main

import (
	"crypto/rand"
	"log"
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func main() {
	repo := memrepo.New()

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatalf("read key: %v", err)
	}
	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: "yauth-example"})
	if err != nil {
		log.Fatalf("mfa.New: %v", err)
	}

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(mfaPlugin).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	log.Printf("yauth-go mfa example listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
