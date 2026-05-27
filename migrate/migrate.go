// Package migrate provides goose-based database migrations for yauth-go.
// Migrations are embedded in the binary and run via Run(). Supports
// postgres, mysql, and sqlite drivers.
package migrate

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed postgres mysql sqlite
var migrationFS embed.FS

// Run applies all pending up-migrations for the given driver against db.
// driver must be one of "postgres", "pgx", "mysql", or "sqlite".
func Run(ctx context.Context, db *sql.DB, driver string) error {
	goose.SetBaseFS(migrationFS)
	defer goose.SetBaseFS(nil)

	dialect, dir, err := dialectAndDir(driver)
	if err != nil {
		return err
	}
	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("migrate: set dialect: %w", err)
	}
	return goose.UpContext(ctx, db, dir)
}

// Down rolls back all migrations for the given driver (to version 0).
func Down(ctx context.Context, db *sql.DB, driver string) error {
	goose.SetBaseFS(migrationFS)
	defer goose.SetBaseFS(nil)

	dialect, dir, err := dialectAndDir(driver)
	if err != nil {
		return err
	}
	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("migrate: set dialect: %w", err)
	}
	return goose.DownToContext(ctx, db, dir, 0)
}

// Status prints migration status to stdout.
func Status(ctx context.Context, db *sql.DB, driver string) error {
	goose.SetBaseFS(migrationFS)
	defer goose.SetBaseFS(nil)

	dialect, dir, err := dialectAndDir(driver)
	if err != nil {
		return err
	}
	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("migrate: set dialect: %w", err)
	}
	return goose.StatusContext(ctx, db, dir)
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
