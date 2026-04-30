// Command telemetry-example runs the same email-password yauth stack as
// examples/sqlite, but boots the OpenTelemetry SDK first so HTTP requests
// produce spans exported via OTLP gRPC.
//
// Try it:
//
//	# in one shell, run a collector:
//	docker run --rm -p 4317:4317 -p 16686:16686 jaegertracing/all-in-one
//
//	# in another:
//	go run ./examples/telemetry
//	curl -i -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//
//	# open http://localhost:16686 to inspect traces.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
	"github.com/yackey-labs/yauth-go/telemetry"
)

func main() {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:4317"
	}
	log.Printf("send traces to otel collector at %s. Run `docker run -p 4317:4317 -p 16686:16686 jaegertracing/all-in-one` to see traces.", endpoint)

	shutdown, err := telemetry.Init(context.Background(), telemetry.DefaultConfig())
	if err != nil {
		log.Fatalf("init telemetry: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(ctx); err != nil {
			log.Printf("telemetry shutdown: %v", err)
		}
	}()

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
	log.Printf("yauth-go telemetry example listening on %s", addr)
	if err := http.ListenAndServe(addr, middleware.TraceMiddleware(mux)); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
