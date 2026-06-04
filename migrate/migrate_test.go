package migrate_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/yackey-labs/yauth/migrate"
)

// pgx (Postgres) is the only supported SQL dialect. The suite runs against an
// isolated testcontainers Postgres (its own DB, no shared state) and skips
// gracefully when Docker is unavailable.
func TestMigrateUpIdempotentDown(t *testing.T) {
	ctx := context.Background()
	ctr, err := tcpostgres.Run(ctx, "docker.io/library/postgres:16-alpine",
		tcpostgres.WithDatabase("yauth_migrate_test"),
		tcpostgres.WithUsername("yauth"),
		tcpostgres.WithPassword("yauth"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Skipf("Docker not available; migrate test skipped: %v", err)
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Up creates the schema.
	if err := migrate.Run(ctx, db, "pgx"); err != nil {
		t.Fatalf("Run(pgx): %v", err)
	}
	for _, table := range []string{"yauth_users", "yauth_sessions", "yauth_api_keys", "yauth_organizations"} {
		var name string
		if err := db.QueryRowContext(ctx,
			"SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename=$1", table).Scan(&name); err != nil {
			t.Errorf("expected table %s after Up: %v", table, err)
		}
	}

	// Running again is idempotent (goose no-ops when already at latest).
	if err := migrate.Run(ctx, db, "pgx"); err != nil {
		t.Fatalf("Run(pgx) idempotent: %v", err)
	}

	// Down removes every yauth table.
	if err := migrate.Down(ctx, db, "pgx"); err != nil {
		t.Fatalf("Down(pgx): %v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'yauth_%'").Scan(&count); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 yauth tables after Down, got %d", count)
	}
}
