// Package migrate provides goose-based database migrations for yauth-go.
//
// # Standalone usage
//
//	migrate.Run(ctx, db, "pgx")  // or "postgres", "mysql", "sqlite"
//
// # Integrating into your own migration pipeline
//
// Applications that run their own goose migrations can obtain a
// pre-configured [*goose.Provider] and orchestrate it alongside their own:
//
//	yauthProvider, err := migrate.NewProvider(db, "pgx")
//	if err != nil { ... }
//	if _, err := yauthProvider.Up(ctx); err != nil { ... }
//
// yauth tracks its schema version in a separate table
// ("goose_db_version_yauth") so it never collides with the application's
// own goose version table.
//
// The embedded SQL files are also exported as [MigrationFS] so callers can
// merge them with their own [io/fs.FS] using standard library tools if
// needed.
package migrate

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
)

//go:embed postgres mysql sqlite
var migrationFS embed.FS

// MigrationFS is the embedded SQL migration files for all supported
// dialects (subdirectories: postgres, mysql, sqlite). Callers that want to
// merge yauth migrations with their own can pass this to
// [goose.NewProvider] directly.
var MigrationFS fs.FS = migrationFS

// VersionTable is the goose version-tracking table yauth uses. It is
// intentionally distinct from the default ("goose_db_version") so that
// yauth and application migrations can share the same database without
// colliding.
const VersionTable = "goose_db_version_yauth"

// NewProvider returns a [*goose.Provider] configured for the given driver.
// The provider uses [VersionTable] to avoid conflicting with the
// application's own goose version table.
//
// Use this when you want to orchestrate yauth migrations alongside your
// own rather than calling [Run] as a fire-and-forget step.
func NewProvider(db *sql.DB, driver string) (*goose.Provider, error) {
	dialect, dir, err := dialectAndDir(driver)
	if err != nil {
		return nil, err
	}
	subFS, err := fs.Sub(MigrationFS, dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: sub fs %q: %w", dir, err)
	}
	return goose.NewProvider(goose.Dialect(dialect), db, subFS,
		goose.WithTableName(VersionTable),
	)
}

// Run applies all pending up-migrations for the given driver against db.
// driver must be one of "postgres", "pgx", "mysql", or "sqlite".
//
// For integration with an existing goose pipeline use [NewProvider] instead.
func Run(ctx context.Context, db *sql.DB, driver string) error {
	p, err := NewProvider(db, driver)
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}

// Down rolls back all migrations for the given driver (to version 0).
func Down(ctx context.Context, db *sql.DB, driver string) error {
	p, err := NewProvider(db, driver)
	if err != nil {
		return err
	}
	_, err = p.DownTo(ctx, 0)
	return err
}

// Status prints migration status to stdout.
func Status(ctx context.Context, db *sql.DB, driver string) error {
	p, err := NewProvider(db, driver)
	if err != nil {
		return err
	}
	results, err := p.Status(ctx)
	if err != nil {
		return err
	}
	for _, r := range results {
		fmt.Printf("%-3s %-40s %s\n", r.Source.Type, r.Source.Path, r.State)
	}
	return nil
}

func dialectAndDir(driver string) (dialect, dir string, err error) {
	switch driver {
	case "postgres", "pgx":
		return "postgres", "postgres", nil
	case "mysql":
		return "mysql", "mysql", nil
	case "sqlite":
		return "sqlite3", "sqlite", nil
	default:
		return "", "", fmt.Errorf("migrate: unsupported driver %q", driver)
	}
}
