// Package gormbackend wires the gorm-backed drivers (sqlite, postgres, mysql)
// into yauth.NewFromConfig / yauth.Migrate / yauth.SchemaCheck.
//
// It exists as a separate package so the root yauth package never imports gorm.
// Consumers that use a gorm driver opt in with a blank import:
//
//	import _ "github.com/yackey-labs/yauth/repo/gormrepo/gormbackend"
//
// A pgx-only consumer omits this import and links neither gorm nor the
// mysql/sqlite drivers into its binary.
package gormbackend

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"

	yauth "github.com/yackey-labs/yauth"
	yauthrepo "github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/gormrepo"
	"github.com/yackey-labs/yauth/yauthcfg"
	"gorm.io/gorm"
)

func init() {
	b := backend{}
	yauth.RegisterBackend("sqlite", b)
	yauth.RegisterBackend("postgres", b)
	yauth.RegisterBackend("mysql", b)
}

// backend implements yauth.Backend on top of gormrepo.
type backend struct{}

func (backend) OpenRepository(ctx context.Context, d yauthcfg.DatabaseConfig, telemetry bool) (yauthrepo.Repository, error) {
	db, err := openDB(d)
	if err != nil {
		return nil, err
	}
	if err := pingDB(ctx, db); err != nil {
		return nil, fmt.Errorf("yauth: database unreachable: %w", err)
	}
	if telemetry {
		if err := gormrepo.ApplyOTel(db, dbNameFromDSN(d.Driver, d.DSN)); err != nil {
			return nil, fmt.Errorf("yauth: gorm otel: %w", err)
		}
	}
	if d.AutoMigrate {
		fmt.Fprintln(os.Stderr, "yauth: WARNING database.auto_migrate=true is for DEV/TEST only — use `yauth migrate` in production")
		if err := gormrepo.Migrate(ctx, db); err != nil {
			return nil, fmt.Errorf("yauth: auto_migrate failed: %w", err)
		}
	}
	return gormrepo.New(db), nil
}

func (backend) Migrate(ctx context.Context, d yauthcfg.DatabaseConfig) error {
	db, err := openDB(d)
	if err != nil {
		return err
	}
	return gormrepo.Migrate(ctx, db)
}

func (backend) OpenSQLDB(_ context.Context, d yauthcfg.DatabaseConfig) (*sql.DB, error) {
	db, err := openDB(d)
	if err != nil {
		return nil, err
	}
	return db.DB()
}

func openDB(d yauthcfg.DatabaseConfig) (*gorm.DB, error) {
	switch d.Driver {
	case "sqlite":
		return gormrepo.OpenSQLite(d.DSN)
	case "postgres":
		return gormrepo.OpenPostgresSchema(d.DSN, d.Schema)
	case "mysql":
		return gormrepo.OpenMySQL(d.DSN)
	default:
		return nil, fmt.Errorf("yauth: unsupported database driver %q (gorm backend serves: sqlite | postgres | mysql)", d.Driver)
	}
}

func pingDB(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// dbNameFromDSN extracts the database name from a driver DSN for use as the
// db.namespace OTel attribute. Returns "" when the name cannot be determined.
func dbNameFromDSN(driver, dsn string) string {
	switch driver {
	case "pgx", "postgres":
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, err := url.Parse(dsn)
			if err != nil {
				return ""
			}
			return strings.TrimPrefix(u.Path, "/")
		}
		for _, part := range strings.Fields(dsn) {
			if strings.HasPrefix(part, "dbname=") {
				return strings.Trim(strings.TrimPrefix(part, "dbname="), "'\"")
			}
		}
	case "mysql":
		// user:pass@tcp(host:port)/dbname?params
		if idx := strings.Index(dsn, ")/"); idx >= 0 {
			rest := dsn[idx+2:]
			if q := strings.IndexByte(rest, '?'); q >= 0 {
				return rest[:q]
			}
			return rest
		}
	}
	return ""
}
