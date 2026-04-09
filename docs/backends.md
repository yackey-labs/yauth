# Database Backends

yauth uses a `DatabaseBackend` trait with pluggable implementations. All persistent data (users, passwords, sessions, API keys, etc.) is accessed through repository traits, making the auth logic fully database-agnostic. All backends accept pools or connections you create — yauth does not manage database connections.

Generate migration files with `cargo yauth generate`, apply them with your ORM's CLI, then pass the pool to yauth.

## Backend Summary

| Backend | Feature Flag | Constructor | Use case |
|---|---|---|---|
| `DieselPgBackend` | `diesel-pg-backend` (default) | `from_pool(pool)` | Production Postgres |
| `DieselMysqlBackend` | `diesel-mysql-backend` | `from_pool(pool)` | MySQL/MariaDB production |
| `DieselSqliteBackend` | `diesel-sqlite-backend` | `from_pool(pool)` | Embedded, local dev |
| `DieselLibsqlBackend` | `diesel-libsql-backend` | `from_pool(pool)` | Turso edge databases |
| `SqlxPgBackend` | `sqlx-pg-backend` | `from_pool(pool)` | sqlx users, compile-time SQL |
| `SqlxMysqlBackend` | `sqlx-mysql-backend` | `from_pool(pool)` | sqlx + MySQL |
| `SqlxSqliteBackend` | `sqlx-sqlite-backend` | `from_pool(pool)` | sqlx + SQLite |
| `SeaOrmPgBackend` | `seaorm-pg-backend` | `from_connection(db)` | SeaORM users, entity-based |
| `SeaOrmMysqlBackend` | `seaorm-mysql-backend` | `from_connection(db)` | SeaORM + MySQL |
| `SeaOrmSqliteBackend` | `seaorm-sqlite-backend` | `from_connection(db)` | SeaORM + SQLite |
| `InMemoryBackend` | `memory-backend` | `new()` | Tests, prototyping |

yauth does not run migrations. Use `cargo yauth generate` to produce migration files for your ORM, then apply them with your ORM's CLI (`diesel migration run`, `sqlx migrate run`, `sea-orm-cli migrate`, etc.).

## Diesel + PostgreSQL (default)

```bash
cargo add yauth --features email-password
cargo yauth init --orm diesel --dialect postgres --plugins email-password
diesel migration run
```

```rust
use yauth::backends::diesel_pg::DieselPgBackend;

let pool = /* your diesel-async deadpool */;
let backend = DieselPgBackend::from_pool(pool);
// Or with a custom PostgreSQL schema:
let backend = DieselPgBackend::from_pool_with_schema(pool, "auth");

let yauth = YAuthBuilder::new(backend, config).build().await?;
```

## Diesel + MySQL / MariaDB

```bash
cargo add yauth --features email-password,diesel-mysql-backend --no-default-features
cargo yauth init --orm diesel --dialect mysql --plugins email-password
diesel migration run
```

```rust
use yauth::backends::diesel_mysql::DieselMysqlBackend;

let pool = /* your diesel-async deadpool */;
let backend = DieselMysqlBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

## Diesel + SQLite / Turso (diesel-libsql)

```bash
cargo add yauth --features email-password,diesel-libsql-backend --no-default-features
cargo yauth init --orm diesel --dialect sqlite --plugins email-password
diesel migration run
```

```rust
use yauth::backends::diesel_libsql::DieselLibsqlBackend;

let pool = /* your diesel-libsql connection pool */;
let backend = DieselLibsqlBackend::from_pool(pool);

let yauth = YAuthBuilder::new(backend, config).build().await?;
```

## Diesel + Native SQLite

> Requires `libsqlite3-dev` (Debian/Ubuntu) or `sqlite3` (macOS Homebrew) system package.

```bash
cargo add yauth --features email-password,diesel-sqlite-backend --no-default-features
cargo yauth init --orm diesel --dialect sqlite --plugins email-password
diesel migration run
```

```rust
use yauth::backends::diesel_sqlite::DieselSqliteBackend;

let pool = /* your diesel SyncConnectionWrapper pool */;
let backend = DieselSqliteBackend::from_pool(pool);

let yauth = YAuthBuilder::new(backend, config).build().await?;
```

## sqlx + PostgreSQL

```bash
cargo add yauth --features email-password,sqlx-pg-backend --no-default-features
cargo yauth init --orm sqlx --dialect postgres --plugins email-password
sqlx migrate run
```

```rust
use yauth::backends::sqlx_pg::SqlxPgBackend;

let pool = sqlx::PgPool::connect(&database_url).await?;
let backend = SqlxPgBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

> **Note:** If you use sqlx's compile-time `query!()` macros in your own code, you'll need `DATABASE_URL` set at build time. yauth itself uses runtime queries, so `cargo check` and `cargo build` work without it. Either way, run migrations first: `sqlx migrate run`.
>
> You'll need `sqlx` as a direct dependency: `cargo add sqlx --features runtime-tokio,postgres`.

## sqlx + MySQL

```bash
cargo add yauth --features email-password,sqlx-mysql-backend --no-default-features
cargo yauth init --orm sqlx --dialect mysql --plugins email-password
sqlx migrate run
```

```rust
use yauth::backends::sqlx_mysql::SqlxMysqlBackend;

let pool = sqlx::MySqlPool::connect(&database_url).await?;
let backend = SqlxMysqlBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

> yauth uses runtime queries, so `DATABASE_URL` is not required at compile time. Run migrations first: `sqlx migrate run`.
>
> You'll need `sqlx` as a direct dependency: `cargo add sqlx --features runtime-tokio,mysql`.

## sqlx + SQLite

```bash
cargo add yauth --features email-password,sqlx-sqlite-backend --no-default-features
cargo yauth init --orm sqlx --dialect sqlite --plugins email-password
sqlx migrate run
```

```rust
use yauth::backends::sqlx_sqlite::SqlxSqliteBackend;

let pool = sqlx::SqlitePool::connect(&database_url).await?;
let backend = SqlxSqliteBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

> Use an **absolute path** for SQLite: `DATABASE_URL=sqlite:/absolute/path/to/yauth.db`.
>
> You'll need `sqlx` as a direct dependency: `cargo add sqlx --features runtime-tokio,sqlite`.

## SeaORM + PostgreSQL

```bash
cargo add yauth --no-default-features --features email-password,seaorm-pg-backend
cargo yauth init --orm seaorm --dialect postgres --plugins email-password
sea-orm-cli migrate up
```

```rust
use yauth::backends::seaorm_pg::SeaOrmPgBackend;

let db = sea_orm::Database::connect(&database_url).await?;
let backend = SeaOrmPgBackend::from_connection(db);
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

SeaORM backends export their entity types publicly, so you can use yauth tables in your own SeaORM queries:

```rust
use yauth::backends::seaorm_pg::entities::users;
let user = users::Entity::find_by_id(id).one(&db).await?;
```

## SeaORM + MySQL

```bash
cargo add yauth --no-default-features --features email-password,seaorm-mysql-backend
cargo yauth init --orm seaorm --dialect mysql --plugins email-password
sea-orm-cli migrate up
```

```rust
use yauth::backends::seaorm_mysql::SeaOrmMysqlBackend;

let db = sea_orm::Database::connect(&database_url).await?;
let backend = SeaOrmMysqlBackend::from_connection(db);
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

## SeaORM + SQLite

```bash
cargo add yauth --no-default-features --features email-password,seaorm-sqlite-backend
cargo yauth init --orm seaorm --dialect sqlite --plugins email-password
sea-orm-cli migrate up
```

```rust
use yauth::backends::seaorm_sqlite::SeaOrmSqliteBackend;

let db = sea_orm::Database::connect("sqlite:./yauth.db?mode=rwc").await?;
let backend = SeaOrmSqliteBackend::from_connection(db);
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

## Toasty Backends (experimental)

Toasty backends are in a separate `yauth-toasty` crate (due to a Cargo `links` conflict with sqlx). Toasty is a pre-1.0 ORM — add it from [crates.io](https://crates.io/crates/toasty).

**`push_schema()`** creates or updates the database tables to match the Toasty model definitions. It is idempotent — safe to call on every startup. Unlike other backends where you run `cargo yauth generate` + your ORM's migration CLI, Toasty manages schema directly. You still run `cargo yauth init --orm toasty` to generate Toasty model files.

### Toasty + PostgreSQL

```bash
cargo add yauth --no-default-features --features email-password
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features postgresql
cargo add toasty --no-default-features --features postgresql
cargo yauth init --orm toasty --dialect postgres --plugins email-password
```

```rust
use yauth_toasty::pg::ToastyPgBackend;

let schema = toasty::schema::from_file("schema/app.toasty").unwrap();
let db = toasty::Db::builder(schema, toasty::driver::postgresql::Driver::connect(&database_url).await?).build();
db.push_schema().await?;
let backend = ToastyPgBackend::from_db(db.clone());
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

### Toasty + MySQL

```bash
cargo add yauth --no-default-features --features email-password
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features mysql
cargo add toasty --no-default-features --features mysql
cargo yauth init --orm toasty --dialect mysql --plugins email-password
```

```rust
use yauth_toasty::mysql::ToastyMysqlBackend;

let schema = toasty::schema::from_file("schema/app.toasty").unwrap();
let db = toasty::Db::builder(schema, toasty::driver::mysql::Driver::connect(&database_url).await?).build();
db.push_schema().await?;
let backend = ToastyMysqlBackend::from_db(db.clone());
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

### Toasty + SQLite

```bash
cargo add yauth --no-default-features --features email-password
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features sqlite
cargo add toasty --no-default-features --features sqlite
cargo yauth init --orm toasty --dialect sqlite --plugins email-password
```

```rust
use yauth_toasty::sqlite::ToastySqliteBackend;

let schema = toasty::schema::from_file("schema/app.toasty").unwrap();
let db = toasty::Db::builder(schema, toasty::driver::sqlite::Driver::open("yauth.db").await?).build();
db.push_schema().await?;
let backend = ToastySqliteBackend::from_db(db.clone());
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

## In-Memory (no database)

```bash
cargo add yauth --features email-password,memory-backend --no-default-features
```

```rust
use yauth::backends::memory::InMemoryBackend;

let backend = InMemoryBackend::new();
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

## Redis Caching

Redis wraps repository traits as a caching decorator. The database remains the source of truth.

```bash
cargo add yauth --features email-password,redis
```

```rust
let redis_client = redis::Client::open("redis://127.0.0.1:6379")?;
let redis_conn = redis_client.get_connection_manager().await?;

let yauth = YAuthBuilder::new(backend, config)
    .with_redis(redis_conn)  // caches sessions, rate limits, challenges, revocation
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

`.with_redis()` adds a caching layer around repository operations for sessions, rate limits, challenges, and token revocation. The database backend remains the source of truth.

**When to use Redis:** multi-replica deployments (shared sessions), high-traffic apps (sub-millisecond session lookups), or when you need instant JWT revocation across all nodes.

## Configurable PostgreSQL Schema

By default, yauth tables live in the `public` schema. Use `from_pool_with_schema()` to isolate them:

```rust
let backend = DieselPgBackend::from_pool_with_schema(pool, "auth");
```

See [migrating-to-diesel.md](migrating-to-diesel.md) for a migration guide if upgrading from yauth v0.1.x (which supported SeaORM).
