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
| `ToastyPgBackend` | `yauth-toasty`: `postgresql` | `from_db(db)` | PostgreSQL via Toasty (experimental, embedded migrations) |
| `ToastyMysqlBackend` | `yauth-toasty`: `mysql` | `from_db(db)` | MySQL via Toasty (experimental, embedded migrations) |
| `ToastySqliteBackend` | `yauth-toasty`: `sqlite` | `from_db(db)` | SQLite via Toasty (experimental, embedded migrations) |

yauth does not run migrations. Use `cargo yauth generate` to produce migration files for your ORM, then apply them with your ORM's CLI (`diesel migration run`, `sqlx migrate run`, `sea-orm-cli migrate`) or via `diesel-async`'s `AsyncMigrationHarness` for a libpq-free alternative (see [Async Migrations](#async-migrations-diesel-backends)). The Toasty backend is the exception — it embeds its own migration chain; call `yauth_toasty::apply_migrations(&db).await?` at startup instead of running `cargo yauth generate`.

## Diesel Backends

All Diesel backends use `diesel-async` 0.8 with deadpool for connection pooling — **no libpq required at runtime**. The Diesel PG backend re-exports pool types (`DieselPool`, `AsyncDieselConnectionManager`, `AsyncPgConnection`), so you don't need `diesel` or `diesel-async` as direct dependencies. If you use diesel's query DSL in your own code, add `diesel` with the types-only backend feature (e.g., `postgres_backend`, `mysql_backend`) — not the full driver feature (e.g., `postgres`, `mysql`) which links native client libraries. MySQL and native SQLite backends need `diesel-async@0.8` as a direct dependency for pool construction — pin the version to avoid conflicts with older releases.

### Diesel + PostgreSQL (default)

```bash
cargo add yauth --features email-password
cargo yauth init --orm diesel --dialect postgres --plugins email-password
# Apply migrations — pick one:
#   diesel migration run            (requires diesel_cli + libpq, dev-only)
#   cargo run --bin migrate -- up   (async, libpq-free — see "Async Migrations" below)
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
cargo add diesel-async@0.8 --features mysql,deadpool
cargo yauth init --orm diesel --dialect mysql --plugins email-password
# Apply migrations — pick one:
#   diesel migration run            (requires diesel_cli + libmysqlclient, dev-only)
#   cargo run --bin migrate -- up   (async — see "Async Migrations" below)
```

```rust
use yauth::prelude::*;
use yauth::backends::diesel_mysql::DieselMysqlBackend;
use diesel_async::pooled_connection::{deadpool::Pool, AsyncDieselConnectionManager};
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
# Apply migrations — pick one:
#   diesel migration run            (requires diesel_cli + libsqlite3, dev-only)
#   cargo run --bin migrate -- up   (async — see "Async Migrations" below)
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
cargo add diesel-async@0.8 --features deadpool,sqlite
cargo yauth init --orm diesel --dialect sqlite --plugins email-password
# Apply migrations — pick one:
#   diesel migration run            (requires diesel_cli + libsqlite3, dev-only)
#   cargo run --bin migrate -- up   (async — see "Async Migrations" below)
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

Toasty backends live in a separate [`yauth-toasty`](../crates/yauth-toasty/) crate (due to a Cargo `links` conflict with sqlx's SQLite driver). One crate covers PostgreSQL, MySQL, and SQLite — you pick the driver via feature flag and the rest of the code is identical.

**Important:** Enable auth plugin features (e.g., `email-password`) on `yauth-toasty`, not on `yauth` directly. `yauth-toasty` re-exports yauth's features and needs them to compile its own repository implementations. If you enable `email-password` only on `yauth`, the `Repositories` struct will expect fields that `yauth-toasty` hasn't compiled, causing a build error.

```toml
# Correct — features on yauth-toasty
[dependencies]
yauth = { version = "0.12", default-features = false }
yauth-toasty = { path = "../yauth-toasty", features = ["sqlite", "email-password"] }
toasty = { version = "0.4", default-features = false, features = ["sqlite"] }

# Wrong — features on yauth but not yauth-toasty (will not compile)
# yauth = { version = "0.12", features = ["email-password"] }
# yauth-toasty = { path = "../yauth-toasty", features = ["sqlite"] }
```

### Migrations: `apply_migrations` vs `push_schema`

Unlike other backends where you run `cargo yauth generate` + your ORM's migration CLI, Toasty ships its own chain of embedded migrations inside `yauth-toasty`:

- **Production / any file-backed database:** call `yauth_toasty::apply_migrations(&db).await?` once at startup. It creates a `__yauth_toasty_migrations` tracking table, applies pending migrations in sequential order, and validates checksums on previously-applied files. Idempotent — safe to call every start-up.
- **Tests / ephemeral databases:** call `backend.create_tables()` (which delegates to Toasty's `push_schema()`). Faster, no tracking table, not intended for production.

### Key differences from diesel / sqlx backends

- **One crate, three databases.** Pick the driver via feature flag; entity definitions, repositories, and API surface are identical across PG / MySQL / SQLite.
- **Embedded migrations.** `apply_migrations(&db)` is a single function call — no external CLI, no `diesel migration run` step. The migration files live under `crates/yauth-toasty/toasty/`.
- **Code-first schema.** Models (`#[derive(toasty::Model)]` with `#[belongs_to]` / `#[has_many]` / `jiff::Timestamp`) are the source of truth. `cargo run --bin toasty-dev ... migration generate` diffs the models against the last snapshot and emits the next migration file.
- **Shared `Db` support.** `Backend::from_db(db)` accepts a `toasty::Db` that also registers your own models, so yauth lives alongside application data under one connection.

### Toasty + PostgreSQL

```bash
cargo add yauth --no-default-features
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features postgresql,email-password
cargo add toasty@0.4 --no-default-features --features postgresql
```

```rust
use yauth::prelude::*;
use yauth_toasty::{ToastyPgBackend, apply_migrations};

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let db = toasty::Db::builder()
    .table_name_prefix("yauth_")
    .models(yauth_toasty::all_models!())
    .connect(&database_url)
    .await?;

// Production: apply tracked, checksummed migrations.
apply_migrations(&db).await?;

let backend = ToastyPgBackend::from_db(db);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

### Toasty + MySQL

```bash
cargo add yauth --no-default-features
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features mysql,email-password
cargo add toasty@0.4 --no-default-features --features mysql
```

```rust
use yauth::prelude::*;
use yauth_toasty::{ToastyMysqlBackend, apply_migrations};

let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let db = toasty::Db::builder()
    .table_name_prefix("yauth_")
    .models(yauth_toasty::all_models!())
    .connect(&database_url)
    .await?;

apply_migrations(&db).await?;

let backend = ToastyMysqlBackend::from_db(db);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

### Toasty + SQLite

```bash
cargo add yauth --no-default-features
cargo add yauth-toasty --git https://github.com/yackey-labs/yauth --features sqlite,email-password
cargo add toasty@0.4 --no-default-features --features sqlite
```

```rust
use yauth::prelude::*;
use yauth_toasty::{ToastySqliteBackend, apply_migrations};

// Use a file-backed DB in production — the SQLite driver opens a new
// connection per query, so `:memory:` gives each query a blank schema.
let db = toasty::Db::builder()
    .table_name_prefix("yauth_")
    .models(yauth_toasty::all_models!())
    .connect("sqlite:./yauth.db")
    .await?;

apply_migrations(&db).await?;

let backend = ToastySqliteBackend::from_db(db);
let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

For tests, skip `apply_migrations` and call `backend.create_tables()` on a fresh `:memory:` or tempfile-backed connection instead — it runs `push_schema()` without the tracking table.

### Sharing a `Db` with your own models

Mount yauth's models alongside your app's Toasty models in a single `Db`:

```rust
let db = toasty::Db::builder()
    .table_name_prefix("yauth_")
    .models(toasty::models!(crate::*, yauth_toasty::entities::*))
    .connect("sqlite://app.db")
    .await?;

apply_migrations(&db).await?;
let backend = ToastySqliteBackend::from_db(db);
```

See [`crates/yauth-toasty/examples/toasty_backend.rs`](../crates/yauth-toasty/examples/toasty_backend.rs) for a complete runnable example and [`examples/toasty_full_flow.rs`](../crates/yauth-toasty/examples/toasty_full_flow.rs) for a repository-layer walkthrough.

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

## Async Migrations (Diesel backends)

The `diesel_cli` (`diesel migration run`) works but requires native client libraries (libpq, libmysqlclient, libsqlite3) at dev time. For a fully async, libpq-free alternative, use `diesel-async`'s `AsyncMigrationHarness` with `diesel_migrations::embed_migrations!`. This compiles your SQL migration files into the binary at build time, then applies them at runtime over the same async connection pool your app uses — no native client libraries required in your runtime image.

### Setup

Add these dependencies alongside yauth:

```toml
[dependencies]
diesel-async = { version = "0.8", features = ["postgres", "deadpool", "migrations"] }
diesel_migrations = "2.3"
```

> Swap `postgres` for `mysql` or `sqlite` to match your backend.

### Migration module

Create a shared module that both your app and a standalone `migrate` binary can use:

```rust
use diesel_async::AsyncMigrationHarness;
use diesel_migrations::EmbeddedMigrations;
use yauth::backends::diesel_pg::{
    AsyncDieselConnectionManager, AsyncPgConnection, DieselPool,
};

pub const MIGRATIONS: EmbeddedMigrations =
    diesel_migrations::embed_migrations!("migrations");

pub async fn build_pool(database_url: &str, max_size: usize) -> DieselPool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
    DieselPool::builder(manager)
        .max_size(max_size)
        .build()
        .expect("failed to build pool")
}

pub async fn run_pending_migrations(
    pool: &DieselPool<AsyncPgConnection>,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let mut harness = AsyncMigrationHarness::new(conn);
    harness.run_pending_migrations(MIGRATIONS)?;
    Ok(())
}
```

### Standalone `migrate` binary

Add a `[[bin]]` entry in your `Cargo.toml` and create `src/bin/migrate.rs`:

```rust
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool = your_crate::db::build_pool(&database_url, 1).await;

    let cmd = std::env::args().nth(1).unwrap_or_else(|| "up".into());
    match cmd.as_str() {
        "up" => your_crate::db::run_pending_migrations(&pool).await.unwrap(),
        _ => panic!("usage: migrate up"),
    }
}
```

> **`multi_thread` is required.** `AsyncMigrationHarness` calls `tokio::task::block_in_place` internally, which panics on a current-thread runtime. Any code that runs migrations — binaries, integration tests — must use `flavor = "multi_thread"`.

### When to use which

| Approach | Pros | Cons |
|---|---|---|
| `diesel migration run` (CLI) | Zero app code, familiar workflow | Requires native client library (libpq, etc.) installed; sync-only |
| `AsyncMigrationHarness` (binary) | Libpq-free, same pool/driver as app, embeds into container image | Requires `multi_thread` tokio runtime, small amount of app code |

For containerized deployments, the async approach eliminates native client libraries from your runtime image entirely. Run the `migrate` binary as a Kubernetes init container or Helm pre-install Job before the app starts.

## Pool Ownership

yauth accepts pre-built pools via `from_pool()` — it never creates its own connections. This means your app decides the pool topology. There are two common patterns:

### One shared pool (recommended)

Create a single pool and pass `pool.clone()` to both yauth and your own service layer. Deadpool wraps the inner state in `Arc`, so cloning is cheap — both sides draw from the same connection set.

```rust
let pool = build_pool(&database_url, 20).await;

// yauth gets a clone
let backend = DieselPgBackend::from_pool(pool.clone());
let yauth = YAuthBuilder::new(backend, config).build().await?;

// Your services get the same pool
let app_state = AppState { pool, yauth_state: yauth.state().clone() };
```

**Advantages:**
- **Single source of truth** for connection count — one `max_size` knob to tune
- **Better resource efficiency** — auth queries and app queries share idle connections rather than reserving separate pools
- **Simpler mental model** — total connections to the database = pool max size, period
- **Easier to monitor** — one pool's metrics (checkout latency, queue depth) tell the full story

**Tradeoff:** A pathological query pattern in either yauth or your app code can starve the other side. In practice this is rare — yauth queries are simple key lookups that complete in single-digit milliseconds.

### Separate pools

Create two pools with independent sizes — one for yauth, one for your app:

```rust
let auth_pool = build_pool(&database_url, 5).await;
let app_pool = build_pool(&database_url, 15).await;

let backend = DieselPgBackend::from_pool(auth_pool);
let yauth = YAuthBuilder::new(backend, config).build().await?;

let app_state = AppState { pool: app_pool, yauth_state: yauth.state().clone() };
```

**Advantages:**
- **Blast radius isolation** — a slow migration or lock in your app can't block auth middleware
- **Independent sizing** — right-size each pool for its workload
- **Clearer ownership** — easier to attribute connection usage in monitoring

**Tradeoff:** More total connections to the database (both pools reserve their max independently), harder to reason about total connection count, and idle connections in one pool can't serve demand spikes in the other.

### Guidance

**Start with one shared pool.** It's simpler, more efficient, and yauth's auth queries are lightweight. If you later observe pool contention where auth latency spikes because of app-side long-running queries (visible as `deadpool::PoolError::Timeout` in auth middleware), split into separate pools at that point. Don't pre-optimize for a problem you may never have.

## Configurable PostgreSQL Schema

By default, yauth tables live in the `public` schema. Use `from_pool_with_schema()` to isolate them:

```rust
let backend = DieselPgBackend::from_pool_with_schema(pool, "auth");
```

See [migrating-to-diesel.md](migrating-to-diesel.md) for a migration guide if upgrading from yauth v0.1.x (which supported SeaORM).
