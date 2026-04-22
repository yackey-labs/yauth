# yauth-toasty

Toasty ORM backend for [yauth](https://github.com/yackey-labs/yauth) — the
plugin-based authentication library for Rust / Axum.

> **Status: Experimental** (`publish = false`). API surface and migration
> file format may change between 0.x releases. Not recommended for
> production yet.

## Features

- All yauth plugins supported (email-password, passkey, MFA, OAuth, bearer,
  API keys, admin, OAuth2 server, magic links, account lockout, webhooks).
- PostgreSQL, MySQL, and SQLite via Toasty's driver system — one crate,
  three databases, one set of entity definitions.
- Idiomatic Toasty 0.4: `#[belongs_to]` / `#[has_many]` / `#[has_one]`
  relationships, `jiff::Timestamp`, `#[serialize(json)]` for structured
  columns.
- Embedded migrations — `yauth_toasty::apply_migrations(&db)` at startup;
  no CLI required for consumers.
- 65+ conformance tests that verify behavioral parity with the diesel and
  sqlx backends.

## Quick Start

```toml
# Cargo.toml
[dependencies]
yauth = { version = "0.12", default-features = false }
yauth-toasty = { path = "../yauth-toasty", features = [
    "email-password",
    "sqlite",
] }
toasty = { version = "0.4", features = ["sqlite"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

```rust
use yauth::{YAuthBuilder, YAuthConfig};
use yauth::plugins::EmailPasswordConfig;
use yauth_toasty::{ToastySqliteBackend, apply_migrations};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build a Toasty Db with every yauth model registered.
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .models(yauth_toasty::all_models!())
        .connect("sqlite:./myapp.db")
        .await?;

    // 2. Apply embedded migrations (idempotent — safe on every startup).
    apply_migrations(&db).await?;

    // 3. Wrap the Db as a yauth backend.
    let backend = ToastySqliteBackend::from_db(db);
    let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
        .with_email_password(EmailPasswordConfig::default())
        .build()
        .await?;

    // 4. Mount on Axum.
    let app = axum::Router::new()
        .merge(yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

> **Enable plugin features on `yauth-toasty`, not on `yauth` directly.**
> `yauth-toasty` re-exports yauth's plugin features (`email-password`,
> `passkey`, `mfa`, `bearer`, `api-key`, `admin`, `oauth`, `oauth2-server`,
> `magic-link`, `account-lockout`, `webhooks`, and `full`) so feature
> unification across the workspace graph stays predictable.

## Backends

| Backend | Feature | Driver |
|---------|---------|--------|
| `ToastyPgBackend` | `postgresql` | PostgreSQL via `toasty-driver-postgresql` |
| `ToastyMysqlBackend` | `mysql` | MySQL 8.0+ via `toasty-driver-mysql` |
| `ToastySqliteBackend` | `sqlite` | SQLite via `toasty-driver-sqlite` |

Each backend offers two constructors:

- `Backend::new(url)` — connect directly from a URL and register all yauth
  models.
- `Backend::from_db(db)` — wrap a `toasty::Db` you constructed yourself
  (e.g. because you want to register additional Toasty models alongside
  yauth's).

## Migrations

yauth-toasty ships an embedded migration chain inside the crate. Call
`apply_migrations(&db)` once at startup:

- Creates a `__yauth_toasty_migrations` tracking table.
- Reads committed migration files (embedded via `include_dir!`) in
  sequential order.
- Skips migrations already recorded in the tracking table.
- Validates checksums of previously-applied migrations — rejects edits to
  already-committed migration files.
- Executes pending migrations one statement-breakpoint block at a time.

```rust
yauth_toasty::apply_migrations(&db).await?;
```

`apply_migrations` is **idempotent** — safe to call on every start-up.

### `push_schema()` for tests

For in-memory test databases, use `backend.create_tables()` (which
delegates to Toasty's `push_schema()`). It's fast, skips the tracking
table, and is designed for ephemeral fixtures — not production.

### Evolving the schema

When a developer changes entity models, regenerate the migration chain
with the dev binary:

```bash
cargo run --manifest-path crates/yauth-toasty/Cargo.toml \
    --bin toasty-dev --features dev-cli,sqlite -- \
    migration generate --name describe_the_change
```

Then commit the new files under `crates/yauth-toasty/toasty/` alongside
the model change.

## Plugin Features

Enable plugins by feature flag (these mirror yauth core):

| Feature | Plugin |
|---------|--------|
| `email-password` | Registration, login, verification, forgot / reset password |
| `passkey` | WebAuthn registration + login |
| `mfa` | TOTP + backup codes |
| `oauth` | OAuth2 provider linking |
| `bearer` | JWT access / refresh tokens |
| `api-key` | API key generation + validation |
| `admin` | User management, ban / unban, impersonation |
| `oauth2-server` | OAuth2 authorization server (authorization code + PKCE, device flow, client_credentials) |
| `account-lockout` | Brute-force lockout |
| `magic-link` | Passwordless email login |
| `webhooks` | Event webhooks |
| `full` | All plugins |

## Examples

- [`examples/toasty_backend.rs`](examples/toasty_backend.rs) — minimal
  runnable app exposing `/auth/register` over Axum using the SQLite
  driver.
- [`examples/toasty_full_flow.rs`](examples/toasty_full_flow.rs) —
  demonstrates create / query / update / cascade-delete against the
  repository layer.

Run them with:

```bash
cargo run --manifest-path crates/yauth-toasty/Cargo.toml \
    --example toasty_backend --features email-password,sqlite

cargo run --manifest-path crates/yauth-toasty/Cargo.toml \
    --example toasty_full_flow --features email-password,sqlite
```

## See Also

- [`docs/backends.md`](../../docs/backends.md) — setup guide for every
  yauth backend, including the Toasty section.
- Repository root [`CLAUDE.md`](../../CLAUDE.md) — architecture,
  conventions, commands.
