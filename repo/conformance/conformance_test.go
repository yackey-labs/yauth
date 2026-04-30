package conformance_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"

	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/repo/conformance"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
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

	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		// Open and migrate once; each case truncates the yauth_* tables
		// before running so per-test isolation matches the in-memory backends.
		db, err := gormrepo.OpenPostgres(dsn)
		if err != nil {
			t.Fatalf("open postgres: %v", err)
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
}

var sqliteCounter uint64

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
