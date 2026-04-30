// Command lockout-example is a runnable demonstration of the lockout
// plugin paired with email-password.
//
// It opens an in-memory SQLite database, runs migrations, builds a YAuth
// instance with the email-password and lockout plugins, and serves it
// under /api/auth/* on :3002. The lockout plugin's LoggingMailer prints
// any unlock-token link to stderr; copy and paste the token from there
// to drive the unlock flow.
//
// Try it:
//
//	go run ./examples/lockout
//
//	# register, then trip the lockout with bad passwords:
//	curl -i -X POST http://localhost:3002/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	for i in 1 2 3 4 5; do
//	  curl -i -X POST http://localhost:3002/api/auth/login \
//	    -H 'Content-Type: application/json' \
//	    -d '{"email":"alice@example.com","password":"WRONG"}'
//	done
//
//	# the next correct-password attempt will return 429 (locked):
//	curl -i -X POST http://localhost:3002/api/auth/login \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	# request an unlock email; copy the token from stderr:
//	curl -i -X POST http://localhost:3002/api/auth/unlock/request \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com"}'
//
//	curl -i -X POST http://localhost:3002/api/auth/unlock \
//	  -H 'Content-Type: application/json' \
//	  -d '{"token":"<paste-here>"}'
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/plugins/lockout"
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

	repo := gormrepo.New(db)

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(lockout.New(lockout.Config{
			MaxAttempts: 5,
			LockoutDurations: []time.Duration{
				30 * time.Second,
				2 * time.Minute,
				10 * time.Minute,
				1 * time.Hour,
			},
			LinkBaseURL: "http://localhost:3002/api/auth/unlock",
		})).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3002"
	log.Printf("yauth-go lockout example listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
