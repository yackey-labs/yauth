package yauth

import (
	"context"
	"database/sql"
	"fmt"

	yauthrepo "github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yauthcfg"
)

// Backend builds repositories and runs migrations for a family of database
// drivers handled by NewFromConfig, Migrate, and SchemaCheck.
//
// The pgx driver is handled inline by the root package (it is gorm-free).
// Every other driver (sqlite, postgres, mysql) is served by a Backend that
// registers itself via RegisterBackend from an init() in its own package.
// This keeps the root yauth package free of any concrete-backend imports:
// a pgx-only consumer that never imports a gorm backend does not link gorm
// (and its mysql/sqlite drivers) into its binary.
//
// Consumers opt into the gorm-backed drivers with a blank import:
//
//	import _ "github.com/yackey-labs/yauth-go/repo/gormrepo/gormbackend"
type Backend interface {
	// OpenRepository opens the database described by db and returns a ready
	// Repository. Implementations must ping the connection, enable OTel
	// tracing when telemetry is true, and run migrations when db.AutoMigrate
	// is true.
	OpenRepository(ctx context.Context, db yauthcfg.DatabaseConfig, telemetry bool) (yauthrepo.Repository, error)
	// Migrate applies all pending migrations for db.
	Migrate(ctx context.Context, db yauthcfg.DatabaseConfig) error
	// OpenSQLDB returns a *sql.DB for schema inspection (used by SchemaCheck).
	OpenSQLDB(ctx context.Context, db yauthcfg.DatabaseConfig) (*sql.DB, error)
}

// registeredBackends maps driver name -> Backend. Populated by RegisterBackend
// at init() time; never written after program startup, so no locking is needed.
var registeredBackends = map[string]Backend{}

// RegisterBackend registers b as the handler for the given driver name. A
// backend package calls this from an init() so a blank import is all a consumer
// needs to enable the driver. It panics on a nil backend or a duplicate driver
// registration — both are programmer errors detectable at startup.
func RegisterBackend(driver string, b Backend) {
	if b == nil {
		panic("yauth: RegisterBackend called with a nil Backend")
	}
	if _, dup := registeredBackends[driver]; dup {
		panic("yauth: RegisterBackend called twice for driver " + driver)
	}
	registeredBackends[driver] = b
}

// lookupBackend resolves the Backend for driver, returning an actionable error
// when none is registered (the usual cause being a missing blank import).
func lookupBackend(driver string) (Backend, error) {
	b, ok := registeredBackends[driver]
	if !ok {
		return nil, fmt.Errorf("yauth: no backend registered for database driver %q — "+
			"for sqlite|postgres|mysql add `import _ \"github.com/yackey-labs/yauth-go/repo/gormrepo/gormbackend\"`, "+
			"or set database.driver=pgx", driver)
	}
	return b, nil
}
