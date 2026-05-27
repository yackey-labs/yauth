package pgxrepo_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	yauthMigrate "github.com/yackey-labs/yauth-go/migrate"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/repo/conformance"
	"github.com/yackey-labs/yauth-go/repo/pgxrepo"
)

var (
	sharedPool  *pgxpool.Pool
	sharedStdDB *sql.DB
	caseCounter uint64
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	ctr, err := tcpostgres.Run(ctx, "docker.io/library/postgres:16-alpine",
		tcpostgres.WithDatabase("yauth_test"),
		tcpostgres.WithUsername("yauth"),
		tcpostgres.WithPassword("yauth"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		fmt.Printf("pgxrepo tests skipped: testcontainers start failed: %v\n", err)
		return
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Printf("pgxrepo tests skipped: connection string: %v\n", err)
		return
	}

	pool, err := pgxrepo.Open(ctx, dsn)
	if err != nil {
		fmt.Printf("pgxrepo tests skipped: open pool: %v\n", err)
		return
	}
	sharedPool = pool

	// Verify connectivity before running migrations.
	if err := pool.Ping(ctx); err != nil {
		fmt.Printf("pgxrepo tests skipped: ping failed: %v\n", err)
		return
	}
	sharedStdDB = pgxrepo.StdDB(pool)

	if err := yauthMigrate.Run(ctx, sharedStdDB, "pgx"); err != nil {
		fmt.Printf("pgxrepo tests skipped: migrate: %v\n", err)
		return
	}

	m.Run()
}

func TestConformance_pgxrepo(t *testing.T) {
	if sharedPool == nil {
		t.Skip("Docker not available; pgxrepo conformance skipped")
	}
	conformance.Suite{
		Name: "pgxrepo",
		New: func(t *testing.T) repo.Repository {
			t.Helper()
			_ = atomic.AddUint64(&caseCounter, 1)
			if err := truncatePgxTables(t, sharedStdDB); err != nil {
				t.Fatalf("truncate: %v", err)
			}
			return pgxrepo.New(sharedPool)
		},
	}.Run(t)
}

func truncatePgxTables(t *testing.T, db *sql.DB) error {
	t.Helper()
	ctx := context.Background()
	rows, err := db.QueryContext(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'yauth_%'`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		tables = append(tables, name)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
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
	_, err = db.ExecContext(ctx, stmt)
	return err
}
