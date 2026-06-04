// Command sqlite-example is a runnable demonstration of yauth-go.
//
// It opens an in-memory SQLite database, runs migrations, builds a YAuth
// instance with the email-password plugin, and serves it under
// /api/auth/* on :3000.
//
// PRODUCTION NOTE: this example calls gormrepo.Migrate at startup for
// simplicity. In production with multiple replicas, that would race —
// run `yauth migrate` as a one-shot Job (see examples/k8s) and let the
// app boot via yauth.NewFromConfig with database.auto_migrate=false.
// See examples/config/ for the config-driven pattern.
//
// Try it:
//
//	go run ./examples/sqlite
//
//	# in another shell:
//	curl -i -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	curl -i -c jar.txt -X POST http://localhost:3000/api/auth/login \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	curl -i -b jar.txt http://localhost:3000/api/auth/session
package main

import (
	"context"
	"log"
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
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
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	log.Printf("yauth-go example listening on %s", addr)
	log.Printf("try:")
	log.Printf("  curl -i -X POST http://localhost%s/api/auth/register \\", addr)
	log.Printf("    -H 'Content-Type: application/json' \\")
	log.Printf("    -d '{\"email\":\"alice@example.com\",\"password\":\"correct horse battery staple\"}'")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
