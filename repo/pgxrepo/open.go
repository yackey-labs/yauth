package pgxrepo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// PoolOption configures a [pgxpool.Config] before the pool is opened.
// DSN query parameters (pool_max_conns, pool_min_conns, etc.) are parsed
// first; opts are applied after and take precedence.
type PoolOption func(*pgxpool.Config)

// WithMaxConns sets the maximum number of connections the pool will hold.
func WithMaxConns(n int32) PoolOption {
	return func(c *pgxpool.Config) { c.MaxConns = n }
}

// WithMinConns sets the minimum number of connections kept alive.
func WithMinConns(n int32) PoolOption {
	return func(c *pgxpool.Config) { c.MinConns = n }
}

// WithMaxConnLifetime sets the maximum lifetime of a single connection.
func WithMaxConnLifetime(d time.Duration) PoolOption {
	return func(c *pgxpool.Config) { c.MaxConnLifetime = d }
}

// WithMaxConnIdleTime sets the maximum time a connection may sit idle.
func WithMaxConnIdleTime(d time.Duration) PoolOption {
	return func(c *pgxpool.Config) { c.MaxConnIdleTime = d }
}

// WithHealthCheckPeriod sets how often idle connections are health-checked.
func WithHealthCheckPeriod(d time.Duration) PoolOption {
	return func(c *pgxpool.Config) { c.HealthCheckPeriod = d }
}

// Open creates a pgxpool from the given DSN (postgres:// or keyword=value form).
// DSN query parameters such as pool_max_conns and pool_min_conns are
// respected; any opts are applied after parsing and take precedence.
//
// Callers that need full control over the pool config can call
// [pgxpool.NewWithConfig] directly and pass the resulting pool to [New].
func Open(ctx context.Context, dsn string, opts ...PoolOption) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxrepo: parse DSN: %w", err)
	}
	for _, opt := range opts {
		opt(cfg)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgxrepo: open pool: %w", err)
	}
	return pool, nil
}

// StdDB returns a *sql.DB backed by the pool (needed by goose).
func StdDB(pool *pgxpool.Pool) *sql.DB {
	return stdlib.OpenDBFromPool(pool)
}
