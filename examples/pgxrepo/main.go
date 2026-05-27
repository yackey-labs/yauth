// Command pgxrepo-example demonstrates using the native pgx/v5 + sqlc
// backend (pgxrepo) with goose migrations.
//
// Requires a running PostgreSQL instance. Set DATABASE_URL:
//
//	export DATABASE_URL="postgres://yauth:yauth@localhost/yauth_example?sslmode=disable"
//	go run ./examples/pgxrepo
//
// Or with Docker:
//
//	docker run -d --rm -p 5432:5432 \
//	  -e POSTGRES_USER=yauth -e POSTGRES_PASSWORD=yauth -e POSTGRES_DB=yauth_example \
//	  postgres:16-alpine
//	go run ./examples/pgxrepo
//
// Then in another shell:
//
//	curl -i -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	curl -i -c jar.txt -X POST http://localhost:3000/api/auth/login \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	curl -i -b jar.txt http://localhost:3000/api/auth/session
//
// Migration note: this example calls migrate.Run at startup as a
// convenience. In production with multiple replicas, run migrations as a
// one-shot job (e.g. a Kubernetes init-container) before the app starts:
//
//	yauth migrate -c yauth.yaml
//
// Then set database.auto_migrate=false (the default).
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/migrate"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/repo/pgxrepo"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://yauth:yauth@localhost/yauth_example?sslmode=disable"
	}

	ctx := context.Background()

	// Open the connection pool. Use PoolOption helpers to tune sizing
	// beyond what the DSN provides.
	pool, err := pgxrepo.Open(ctx, dsn,
		pgxrepo.WithMaxConns(25),
		pgxrepo.WithMinConns(5),
		pgxrepo.WithMaxConnLifetime(time.Hour),
		pgxrepo.WithMaxConnIdleTime(15*time.Minute),
	)
	if err != nil {
		log.Fatalf("pgxrepo: open pool: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("pgxrepo: ping: %v", err)
	}

	// Run goose migrations (idempotent — safe to call every startup in dev).
	// In production use `yauth migrate -c yauth.yaml` before rolling out replicas.
	if err := migrate.Run(ctx, pgxrepo.StdDB(pool), "pgx"); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	// Build the YAuth instance.
	repo := pgxrepo.New(pool)
	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "yauth pgxrepo example — try POST /api/auth/register")
	})

	addr := ":3000"
	log.Printf("listening on %s (Postgres: %s)", addr, dsn)
	log.Fatal(http.ListenAndServe(addr, mux))
}
