# Database Backends

yauth uses a `DatabaseBackend` trait with pluggable implementations. All persistent data (users, passwords, sessions, API keys, etc.) is accessed through repository traits, making the auth logic fully database-agnostic. All backends accept pools or connections you create — yauth does not manage database connections.

Generate migration files with `cargo yauth generate`, apply them with your ORM's CLI, then pass the pool to yauth.

Every Rust example below drops into the same `main()` skeleton — create the pool, build the backend, build yauth, mount the router:

```rust
use yauth::prelude::*;

#[tokio::main]
async fn main() {
    // --- backend-specific pool + backend setup (see each section below) ---

    let app = axum::Router::new()
        .nest("/api/auth", yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

Copy the backend-specific block from any section below, paste it where the comment is, and you have a running app.

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

## Diesel Backends

All Diesel backends use `diesel-async` 0.8 with deadpool for connection pooling. The Diesel PG backend re-exports pool types (`DieselPool`, `AsyncDieselConnectionManager`, `AsyncPgConnection`) so you only need `diesel` as a direct dependency. MySQL and native SQLite backends need `diesel-async@0.8` as a direct dependency for pool construction — pin the version to avoid conflicts with older releases.

### Diesel + PostgreSQL (default)

```bash
cargo add yauth --features email-password
cargo add diesel --features postgres
cargo yauth init --orm diesel --dialect postgres --plugins email-password
diesel migration run
```

```rust
use yauth::prelude::*;
use yauth::backends::diesel_pg::{DieselPgBackend, DieselPool, AsyncDieselConnectionManager, AsyncPgConnection};

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
let pool = DieselPool::builder(manager).build().unwrap();

let backend = DieselPgBackend::from_pool(pool);
// Or isolate yauth tables in a custom PostgreSQL schema:
// let backend = DieselPgBackend::from_pool_with_schema(pool, "auth")?;

let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

### Diesel + MySQL / MariaDB

```bash
cargo add yauth --features email-password,diesel-mysql-backend --no-default-features
cargo add diesel --features mysql_backend
cargo add diesel-async@0.8 --features mysql,deadpool
cargo yauth init --orm diesel --dialect mysql --plugins email-password
diesel migration run
```

```rust
use yauth::prelude::*;
use yauth::backends::diesel_mysql::DieselMysqlBackend;
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, deadpool::Pool};
use diesel_async::AsyncMysqlConnection;

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let manager = AsyncDieselConnectionManager::<AsyncMysqlConnection>::new(&database_url);
let pool = Pool::builder(manager).build().unwrap();

let backend = DieselMysqlBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

### Diesel + SQLite / Turso (diesel-libsql)

```bash
cargo add yauth --features email-password,diesel-libsql-backend --no-default-features
cargo add diesel-libsql --features async,deadpool
cargo yauth init --orm diesel --dialect sqlite --plugins email-password
diesel migration run
```

```rust
use yauth::prelude::*;
use yauth::backends::diesel_libsql::DieselLibsqlBackend;

// Local file:
let pool = diesel_libsql::deadpool::new_pool("file:yauth.db").unwrap();
// Or remote Turso:
// let pool = diesel_libsql::deadpool::new_pool("libsql://your-db.turso.io?authToken=...").unwrap();

let backend = DieselLibsqlBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

### Diesel + Native SQLite

> Requires `libsqlite3-dev` (Debian/Ubuntu) or `sqlite3` (macOS Homebrew) system package.
>
> `SqliteAsyncConn` and `SqlitePool` are re-exported by yauth. You need `diesel-async@0.8` as a direct dependency for `AsyncDieselConnectionManager`.

```bash
cargo add yauth --features email-password,diesel-sqlite-backend --no-default-features
cargo add diesel --features sqlite
cargo add diesel-async@0.8 --features deadpool,sqlite
cargo yauth init --orm diesel --dialect sqlite --plugins email-password
diesel migration run
```

```rust
use yauth::prelude::*;
use yauth::backends::diesel_sqlite::{DieselSqliteBackend, SqlitePool, SqliteAsyncConn};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;

let database_url = "yauth.db"; // path to SQLite file
let manager = AsyncDieselConnectionManager::<SqliteAsyncConn>::new(database_url);
let pool = SqlitePool::builder(manager).build().unwrap();

let backend = DieselSqliteBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

## sqlx + PostgreSQL

```bash
cargo add yauth --features email-password,sqlx-pg-backend --no-default-features
cargo yauth init --orm sqlx --dialect postgres --plugins email-password
sqlx migrate run
```

```rust
use yauth::prelude::*;
use yauth::backends::sqlx_pg::SqlxPgBackend;

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let pool = sqlx::PgPool::connect(&database_url).await?;
let backend = SqlxPgBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
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
use yauth::prelude::*;
use yauth::backends::sqlx_mysql::SqlxMysqlBackend;

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let pool = sqlx::MySqlPool::connect(&database_url).await?;
let backend = SqlxMysqlBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
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
use yauth::prelude::*;
use yauth::backends::sqlx_sqlite::SqlxSqliteBackend;

let pool = sqlx::SqlitePool::connect("sqlite:yauth.db?mode=rwc").await?;
let backend = SqlxSqliteBackend::from_pool(pool);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

> `?mode=rwc` creates the file if it doesn't exist. You'll need `sqlx` as a direct dependency: `cargo add sqlx --features runtime-tokio,sqlite`.

## SeaORM Backends

SeaORM backends use SeaORM 2.0 (pre-release). You'll need `sea-orm` as a direct dependency.

SeaORM backends export their entity types publicly, so you can use yauth tables in your own SeaORM queries.

### SeaORM + PostgreSQL

```bash
cargo add yauth --no-default-features --features email-password,seaorm-pg-backend
cargo add sea-orm --version '=2.0.0-rc.37' --features sqlx-postgres,runtime-tokio-rustls
cargo yauth init --orm seaorm --dialect postgres --plugins email-password
sea-orm-cli migrate up
```

```rust
use yauth::prelude::*;
use yauth::backends::seaorm_pg::SeaOrmPgBackend;

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let db = sea_orm::Database::connect(&database_url).await?;
let backend = SeaOrmPgBackend::from_connection(db);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;

// Use yauth entities in your own queries:
// use yauth::backends::seaorm_pg::entities::users;
// let user = users::Entity::find_by_id(id).one(&db).await?;
```

### SeaORM + MySQL

```bash
cargo add yauth --no-default-features --features email-password,seaorm-mysql-backend
cargo add sea-orm --version '=2.0.0-rc.37' --features sqlx-mysql,runtime-tokio-rustls
cargo yauth init --orm seaorm --dialect mysql --plugins email-password
sea-orm-cli migrate up
```

```rust
use yauth::prelude::*;
use yauth::backends::seaorm_mysql::SeaOrmMysqlBackend;

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let db = sea_orm::Database::connect(&database_url).await?;
let backend = SeaOrmMysqlBackend::from_connection(db);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

### SeaORM + SQLite

```bash
cargo add yauth --no-default-features --features email-password,seaorm-sqlite-backend
cargo add sea-orm --version '=2.0.0-rc.37' --features sqlx-sqlite,runtime-tokio-rustls
cargo yauth init --orm seaorm --dialect sqlite --plugins email-password
sea-orm-cli migrate up
```

```rust
use yauth::prelude::*;
use yauth::backends::seaorm_sqlite::SeaOrmSqliteBackend;

let db = sea_orm::Database::connect("sqlite:/absolute/path/to/yauth.db?mode=rwc").await?;
let backend = SeaOrmSqliteBackend::from_connection(db);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

> Use an **absolute path** for SQLite: `sqlite:/absolute/path/to/yauth.db?mode=rwc`.

## Toasty Backends (experimental)

Toasty backends are in a separate `yauth-toasty` crate (due to a Cargo `links` conflict with sqlx).

**Important:** Enable auth plugin features (e.g., `email-password`) on `yauth-toasty`, not on `yauth` directly. `yauth-toasty` re-exports yauth's features and needs them to compile its own repository implementations. If you enable `email-password` only on `yauth`, the `Repositories` struct will expect fields that `yauth-toasty` hasn't compiled, causing a build error.

```toml
# Correct — features on yauth-toasty
[dependencies]
yauth = { path = "...", default-features = false }
yauth-toasty = { path = "...", features = ["sqlite", "email-password"] }

# Wrong — features on yauth but not yauth-toasty (will not compile)
# yauth = { path = "...", features = ["email-password"] }
# yauth-toasty = { path = "...", features = ["sqlite"] }
```

**`create_tables()`** (which calls Toasty's `push_schema()`) creates or updates database tables. It is idempotent — safe to call on every startup. Unlike other backends where you run `cargo yauth generate` + your ORM's migration CLI, Toasty manages schema directly via `#[derive(toasty::Model)]` structs compiled into the crate.

Each Toasty backend has a `new(url)` constructor that handles schema registration and connection internally, plus a `from_db(db)` for advanced cases where you share a `Db` with your own models. Call `create_tables()` after construction to run `push_schema()`.

### Toasty + PostgreSQL

```bash
cargo add yauth --no-default-features
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features postgresql,email-password
cargo add toasty@0.3 --no-default-features --features postgresql
```

```rust
use yauth::prelude::*;
use yauth_toasty::pg::ToastyPgBackend;

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let backend = ToastyPgBackend::new(&database_url).await.unwrap();
backend.create_tables().await.unwrap(); // runs push_schema() — idempotent, safe on every startup

let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

### Toasty + MySQL

```bash
cargo add yauth --no-default-features
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features mysql,email-password
cargo add toasty@0.3 --no-default-features --features mysql
```

```rust
use yauth::prelude::*;
use yauth_toasty::mysql::ToastyMysqlBackend;

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let backend = ToastyMysqlBackend::new(&database_url).await.unwrap();
backend.create_tables().await.unwrap();

let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

### Toasty + SQLite

```bash
cargo add yauth --no-default-features
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features sqlite,email-password
cargo add toasty@0.3 --no-default-features --features sqlite
```

```rust
use yauth::prelude::*;
use yauth_toasty::sqlite::ToastySqliteBackend;

let backend = ToastySqliteBackend::new("sqlite://yauth.db").await.unwrap();
backend.create_tables().await.unwrap();

let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

For advanced usage (sharing a `Db` with your own Toasty models), use `from_db()`:

```rust
let db = toasty::Db::builder()
    .table_name_prefix("yauth_")
    .models(toasty::models!(crate::*, yauth_toasty::*))
    .connect("sqlite://app.db")
    .await?;
let backend = ToastySqliteBackend::from_db(db);
```

## In-Memory (no database)

```bash
cargo add yauth --features email-password,memory-backend --no-default-features
```

```rust
use yauth::prelude::*;
use yauth::backends::memory::InMemoryBackend;

let backend = InMemoryBackend::new();
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
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
