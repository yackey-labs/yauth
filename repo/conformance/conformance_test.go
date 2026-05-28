package conformance_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/repo/conformance"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
	"github.com/yackey-labs/yauth-go/repo/redisrepo"
)

func TestConformance(t *testing.T) {
	conformance.Suite{
		Name: "memrepo",
		New: func(t *testing.T) repo.Repository {
			return memrepo.New()
		},
	}.Run(t)

	conformance.Suite{
		Name: "gorm-sqlite",
		New: func(t *testing.T) repo.Repository {
			t.Helper()
			// Each test gets its own private in-memory DB. Using a unique DSN per
			// invocation prevents cache=shared from leaking state across cases.
			id := atomic.AddUint64(&sqliteCounter, 1)
			dsn := fmt.Sprintf("file:conformance-%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", id)
			db, err := gormrepo.OpenSQLite(dsn)
			if err != nil {
				t.Fatalf("open sqlite: %v", err)
			}
			if err := gormrepo.Migrate(context.Background(), db); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			return gormrepo.New(db)
		},
	}.Run(t)

	// redisrepo decorating memrepo, backed by miniredis. Exercises every
	// pass-through operation as well as the cached hot paths.
	conformance.Suite{
		Name: "redisrepo+memrepo",
		New: func(t *testing.T) repo.Repository {
			t.Helper()
			mr := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			t.Cleanup(func() { _ = client.Close() })
			id := atomic.AddUint64(&redisCounter, 1)
			return redisrepo.New(memrepo.New(), client, redisrepo.Options{
				KeyPrefix: fmt.Sprintf("conf-%d:", id),
			})
		},
	}.Run(t)

	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		// Open and migrate once; each case truncates the yauth_* tables
		// before running so per-test isolation matches the in-memory backends.
		//
		// Pin to the "gorm_conformance" schema so goose-run migrations in
		// the public schema (from migrate_test.go) don't collide with GORM's
		// auto-generated constraint names.
		db, err := gormrepo.OpenPostgresSchema(dsn, "gorm_conformance")
		if err != nil {
			t.Fatalf("open postgres: %v", err)
		}
		if err := db.Exec("CREATE SCHEMA IF NOT EXISTS gorm_conformance").Error; err != nil {
			t.Fatalf("create schema: %v", err)
		}
		if err := gormrepo.Migrate(context.Background(), db); err != nil {
			t.Fatalf("migrate postgres: %v", err)
		}
		conformance.Suite{
			Name: "gorm-postgres",
			New: func(t *testing.T) repo.Repository {
				t.Helper()
				if err := truncateYauthTables(db); err != nil {
					t.Fatalf("truncate postgres: %v", err)
				}
				return gormrepo.New(db)
			},
		}.Run(t)
	}

	if dsn := os.Getenv("DATABASE_URL_MYSQL"); dsn != "" {
		db, err := gormrepo.OpenMySQL(dsn)
		if err != nil {
			t.Fatalf("open mysql: %v", err)
		}
		if err := gormrepo.Migrate(context.Background(), db); err != nil {
			t.Fatalf("migrate mysql: %v", err)
		}
		conformance.Suite{
			Name: "gorm-mysql",
			New: func(t *testing.T) repo.Repository {
				t.Helper()
				if err := truncateMySQLYauthTables(db); err != nil {
					t.Fatalf("truncate mysql: %v", err)
				}
				return gormrepo.New(db)
			},
		}.Run(t)
	}
}

var (
	sqliteCounter uint64
	redisCounter  uint64
)

// truncateYauthTables clears all yauth_* tables in a Postgres database.
// Called once per conformance case so each case sees an empty schema.
func truncateYauthTables(db *gorm.DB) error {
	var tables []string
	if err := db.Raw(
		`SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'yauth_%'`,
	).Scan(&tables).Error; err != nil {
		return err
	}
	if len(tables) == 0 {
		return nil
	}
	stmt := "TRUNCATE "
	for i, tn := range tables {
		if i > 0 {
			stmt += ", "
		}
		stmt += `"` + tn + `"`
	}
	stmt += " RESTART IDENTITY CASCADE"
	return db.Exec(stmt).Error
}

// truncateMySQLYauthTables clears all yauth_* tables in a MySQL database.
// FK checks are toggled around the truncates so cross-table references
// (none today, but defensively) don't reject the wipe.
func truncateMySQLYauthTables(db *gorm.DB) error {
	var tables []string
	if err := db.Raw(
		`SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema = DATABASE() AND TABLE_NAME LIKE 'yauth_%'`,
	).Scan(&tables).Error; err != nil {
		return err
	}
	if len(tables) == 0 {
		return nil
	}
	if err := db.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
		return err
	}
	for _, tn := range tables {
		if err := db.Exec("TRUNCATE TABLE `" + tn + "`").Error; err != nil {
			_ = db.Exec("SET FOREIGN_KEY_CHECKS = 1").Error
			return err
		}
	}
	return db.Exec("SET FOREIGN_KEY_CHECKS = 1").Error
}
