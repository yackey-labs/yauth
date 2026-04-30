package gormrepo

import (
	"net/url"
	"strings"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OpenPostgres opens a GORM DB backed by Postgres.
func OpenPostgres(dsn string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
}

// OpenPostgresSchema opens a GORM DB backed by Postgres and pins the
// session search_path to "<schema>,public" so yauth tables resolve in
// the supplied schema while shared lookups (extensions, common
// utilities) continue to fall back through the public schema. An empty
// schema is equivalent to OpenPostgres. A caller-supplied search_path
// in the DSN is preserved.
func OpenPostgresSchema(dsn, schema string) (*gorm.DB, error) {
	if schema == "" {
		return OpenPostgres(dsn)
	}
	return OpenPostgres(addPostgresSchema(dsn, schema))
}

// addPostgresSchema rewrites a Postgres DSN to set
// search_path=<schema>,public. URL-style (postgres://...) and
// keyword-style (host=... dbname=...) DSNs are both supported. If
// search_path is already set on the DSN it is left in place so callers
// that pin it explicitly win.
func addPostgresSchema(dsn, schema string) string {
	if schema == "" {
		return dsn
	}
	value := schema + ",public"
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return dsn
		}
		q := u.Query()
		if q.Get("search_path") == "" {
			q.Set("search_path", value)
			u.RawQuery = q.Encode()
		}
		return u.String()
	}
	if strings.Contains(dsn, "search_path=") {
		return dsn
	}
	if strings.TrimSpace(dsn) == "" {
		return "search_path=" + value
	}
	return dsn + " search_path=" + value
}

// OpenSQLite opens a GORM DB backed by SQLite.
func OpenSQLite(dsn string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
}

// OpenMySQL opens a GORM DB backed by MySQL/MariaDB.
//
// The DSN follows go-sql-driver/mysql syntax, e.g.:
//
//	user:pass@tcp(host:3306)/dbname?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci
//
// parseTime=true is required for time.Time scanning to work.
//
// DefaultStringSize=255 keeps plain `string` columns at varchar(255) so
// they remain indexable under utf8mb4 (4 bytes/char × 255 = 1020 bytes,
// inside InnoDB's 3072-byte key limit). Columns that need longer
// payloads (JSON, encrypted tokens, webhook bodies) opt in via
// `gorm:"type:text"` on the model field.
func OpenMySQL(dsn string) (*gorm.DB, error) {
	return gorm.Open(mysql.New(mysql.Config{
		DSN:               dsn,
		DefaultStringSize: 255,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
}
