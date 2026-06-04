package migrate_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"

	"github.com/yackey-labs/yauth/migrate"
)

func TestRun_SQLite(t *testing.T) {
	dir := t.TempDir()
	dsn := fmt.Sprintf("file:%s/migrate_test.db?_foreign_keys=1", dir)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := migrate.Run(ctx, db, "sqlite"); err != nil {
		t.Fatalf("Run(sqlite): %v", err)
	}

	// Verify a representative set of tables exist.
	for _, table := range []string{"yauth_users", "yauth_sessions", "yauth_api_keys", "yauth_organizations"} {
		var name string
		err := db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("expected table %s: %v", table, err)
		}
	}

	// Running again is idempotent (goose no-ops when already at latest).
	if err := migrate.Run(ctx, db, "sqlite"); err != nil {
		t.Fatalf("Run(sqlite) idempotent: %v", err)
	}
}

func TestDown_SQLite(t *testing.T) {
	dir := t.TempDir()
	dsn := fmt.Sprintf("file:%s/migrate_down_test.db?_foreign_keys=1", dir)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := migrate.Run(ctx, db, "sqlite"); err != nil {
		t.Fatalf("Run(sqlite): %v", err)
	}
	if err := migrate.Down(ctx, db, "sqlite"); err != nil {
		t.Fatalf("Down(sqlite): %v", err)
	}

	// All yauth tables should be gone.
	var count int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'yauth_%'").Scan(&count)
	if err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 yauth tables after Down, got %d", count)
	}
}

func TestRun_Postgres(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; postgres migrate test skipped")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := migrate.Run(ctx, db, "pgx"); err != nil {
		t.Fatalf("Run(pgx): %v", err)
	}
}

func TestRun_MySQL(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL_MYSQL")
	if dsn == "" {
		t.Skip("DATABASE_URL_MYSQL not set; mysql migrate test skipped")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := migrate.Run(ctx, db, "mysql"); err != nil {
		t.Fatalf("Run(mysql): %v", err)
	}
}
