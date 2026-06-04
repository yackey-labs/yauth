// Command config-example demonstrates building a YAuth instance from a
// yauth.yaml config file via yauth.NewFromConfig.
//
// In production, run migrations OUTSIDE app runtime:
//
//	yauth migrate -c yauth.yaml
//	./your-app           # NewFromConfig never auto-migrates
//
// For local development you can flip database.auto_migrate=true in the
// config; NewFromConfig will then migrate before returning and emit a
// stderr WARN to make sure nobody ships that to prod.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/yauthcfg"
)

func main() {
	cfgPath := flag.String("c", "yauth.yaml", "path to yauth config")
	flag.Parse()

	cfg, err := yauthcfg.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load %s: %v", *cfgPath, err)
	}

	ctx := context.Background()

	// Preflight schema check — fails loudly when the DB is unmigrated
	// instead of erroring later on the first SQL call.
	if !cfg.Database.AutoMigrate {
		if err := yauth.SchemaCheck(ctx, cfg); err != nil {
			log.Fatalf("schema check: %v\n\nrun `yauth migrate -c %s` first", err, *cfgPath)
		}
	}

	ya, err := yauth.NewFromConfig(ctx, cfg)
	if err != nil {
		log.Fatalf("NewFromConfig: %v", err)
	}
	defer func() { _ = ya.TelemetryShutdown(ctx) }()

	mux := http.NewServeMux()
	prefix := cfg.Server.Prefix
	if prefix == "" {
		prefix = "/api/auth"
	}
	mux.Handle(prefix+"/", http.StripPrefix(prefix, ya.Router()))

	addr := cfg.Server.Addr
	if addr == "" {
		addr = ":3000"
	}
	log.Printf("yauth-go (config-driven) listening on %s, prefix=%s", addr, prefix)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
