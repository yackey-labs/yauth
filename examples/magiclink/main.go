// Command magiclink-example is a runnable demonstration of the magic-link
// plugin.
//
// It opens an in-memory SQLite database, runs migrations, builds a YAuth
// instance with the magic-link plugin (signup enabled), and serves it
// under /api/auth/* on :3001. The default LoggingMailer prints the
// generated link to stderr; copy and paste the token from there to
// complete the verify step.
//
// Try it:
//
//	go run ./examples/magiclink
//
//	# in another shell:
//	curl -i -X POST http://localhost:3001/api/auth/magic-link/send \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com"}'
//
//	# copy the token printed to stderr by the server, then:
//	curl -i -c jar.txt -X POST http://localhost:3001/api/auth/magic-link/verify \
//	  -H 'Content-Type: application/json' \
//	  -d '{"token":"<paste-here>"}'
package main

import (
	"context"
	"log"
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/magiclink"
	"github.com/yackey-labs/yauth/repo/gormrepo"
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

	repo := gormrepo.New(db)

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(magiclink.New(magiclink.Config{
			SignupEnabled: true,
			LinkBaseURL:   "http://localhost:3001/api/auth/magic-link/verify",
		})).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3001"
	log.Printf("yauth-go magic-link example listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
