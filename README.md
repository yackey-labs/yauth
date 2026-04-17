# yauth

Modular, plugin-based authentication library for Rust (Axum) with a generated TypeScript client, Vue 3 components, and SolidJS components.

- **Plugin system** — enable only the auth features you need via feature flags
- **11 database backends** — Diesel, sqlx, SeaORM, Toasty, or in-memory, across Postgres, MySQL, and SQLite
- **No runtime migrations** — `cargo yauth generate` produces ORM-native migration files; apply them with your ORM's CLI or via `diesel-async`'s `AsyncMigrationHarness` ([docs](docs/backends.md#async-migrations-diesel-backends))
- **Tri-mode auth** — session cookies, JWT bearer tokens, and API keys all work simultaneously
- **Full OAuth2 / OIDC provider** — authorization code + PKCE, device flow, client credentials, `private_key_jwt` (RFC 7523), published JWKS for cross-trust-domain validation
- **TypeScript included** — auto-generated HTTP client + pre-built Vue 3 and SolidJS components

## Try It in 30 Seconds

No database needed. Copy, paste, run:

```bash
cargo add yauth --no-default-features --features memory-backend,email-password
cargo add axum
cargo add tokio --features full
```

```rust
use yauth::prelude::*;
use yauth::backends::memory::InMemoryBackend;

#[tokio::main]
async fn main() {
    let yauth = YAuthBuilder::new(InMemoryBackend::new(), YAuthConfig::default())
        .with_email_password(EmailPasswordConfig {
            require_email_verification: false,
            ..Default::default()
        })
        .build()
        .await
        .unwrap();

    let app = axum::Router::new()
        .nest("/api/auth", yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Xk9#mP2$vL5nQ8wR"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Xk9#mP2$vL5nQ8wR"}'
```

## How It Works

**Plugins** implement the `YAuthPlugin` trait — each provides public routes (login, register), protected routes (change password, manage passkeys), and event handlers (MFA intercepts login, lockout blocks login). Enable plugins with feature flags and wire them up via `YAuthBuilder`.

**Tri-mode auth middleware** checks credentials in order: session cookie, then `Authorization: Bearer <jwt>` (requires `bearer` feature), then `X-Api-Key` header (requires `api-key` feature). The authenticated user is injected as `Extension<AuthUser>`.

**Event system** — all auth operations emit an `AuthEvent` (`UserRegistered`, `LoginSucceeded`, `LoginFailed`, etc.). Plugins respond with `Continue`, `RequireMfa { pending_session_id }`, or `Block { status, message }`.

Custom plugins can be added via `builder.with_plugin(Box::new(MyPlugin))`.

## Add to Your Project

### 1. Pick a backend

| Backend | Feature flag | ORM | Database |
|---|---|---|---|
| `DieselPgBackend` | `diesel-pg-backend` (default) | Diesel | PostgreSQL |
| `DieselMysqlBackend` | `diesel-mysql-backend` | Diesel | MySQL/MariaDB |
| `DieselSqliteBackend` | `diesel-sqlite-backend` | Diesel | SQLite |
| `DieselLibsqlBackend` | `diesel-libsql-backend` | Diesel | SQLite/Turso |
| `SqlxPgBackend` | `sqlx-pg-backend` | sqlx | PostgreSQL |
| `SqlxMysqlBackend` | `sqlx-mysql-backend` | sqlx | MySQL |
| `SqlxSqliteBackend` | `sqlx-sqlite-backend` | sqlx | SQLite |
| `SeaOrmPgBackend` | `seaorm-pg-backend` | SeaORM | PostgreSQL |
| `SeaOrmMysqlBackend` | `seaorm-mysql-backend` | SeaORM | MySQL |
| `SeaOrmSqliteBackend` | `seaorm-sqlite-backend` | SeaORM | SQLite |
| `ToastySqliteBackend` | `sqlite` (on `yauth-toasty`) | Toasty | SQLite |
| `ToastyPgBackend` | `postgresql` (on `yauth-toasty`) | Toasty | PostgreSQL |
| `ToastyMysqlBackend` | `mysql` (on `yauth-toasty`) | Toasty | MySQL |
| `InMemoryBackend` | `memory-backend` | -- | None |

Toasty backends are experimental and live in a [separate `yauth-toasty` crate](docs/backends.md#toasty-backends-experimental) — enable plugin features on `yauth-toasty`, not `yauth`.

All backends accept pools/connections you create. **Each backend has a complete, copy-paste-ready example** in [docs/backends.md](docs/backends.md) — including `Cargo.toml` dependencies, pool construction, and full `main.rs`.

### 2. Pick your plugins

| Plugin | Feature flag | What it does |
|---|---|---|
| `email-password` | `email-password` (default) | Registration, login, email verification, forgot/reset/change password, HIBP breach checking |
| `passkey` | `passkey` | WebAuthn registration + passwordless login |
| `mfa` | `mfa` | TOTP setup/verify with backup codes |
| `oauth` | `oauth` | OAuth2 client — multi-provider linking (Google, GitHub, etc.) |
| `bearer` | `bearer` | JWT access/refresh tokens with token family tracking |
| `api-key` | `api-key` | Scoped API key generation with optional expiration |
| `magic-link` | `magic-link` | Passwordless email login with optional signup |
| `admin` | `admin` | User management, ban/unban, impersonation |
| `status` | `status` | Protected endpoint listing enabled plugins |
| `oauth2-server` | `oauth2-server` | Full OAuth2 authorization server (auth code + PKCE, device flow, **M2M client_credentials with JWT validation**, **RFC 7523 private_key_jwt** when paired with `asymmetric-jwt`) |
| `account-lockout` | `account-lockout` | Brute-force protection with exponential backoff |
| `webhooks` | `webhooks` | HMAC-signed HTTP callbacks on auth events |
| `oidc` | `oidc` | OpenID Connect Provider (id_token, discovery, JWKS, /userinfo) |
| `asymmetric-jwt` | `asymmetric-jwt` | RS256/ES256 JWT signing + populated `/.well-known/jwks.json` for cross-trust-domain validation |

Infrastructure features: `telemetry` (OpenTelemetry), `openapi` (utoipa spec generation), `redis` (caching decorator).

Use `full` to enable all auth plugins, then add one backend: `features = ["full", "diesel-pg-backend"]`.

### 3. Wire it up

Two complete examples below — pick the one closest to your stack. Every other backend follows the same pattern; see [docs/backends.md](docs/backends.md) for the full list with copy-paste-ready examples.

#### Diesel + PostgreSQL (default)

```bash
cargo add yauth --features email-password
cargo yauth init --orm diesel --dialect postgres --plugins email-password
cargo run --bin migrate -- up   # or: diesel migration run
```

> yauth re-exports the diesel-async pool types (`DieselPool`, `AsyncDieselConnectionManager`, `AsyncPgConnection`), so you don't need `diesel` or `diesel-async` as direct dependencies. If you use diesel's query DSL in your own code, add `diesel` with the **`postgres_backend`** feature (types + DSL only, no libpq): `cargo add diesel --no-default-features --features postgres_backend`.

```rust
// prelude re-exports YAuthBuilder, YAuthConfig, EmailPasswordConfig,
// PasskeyConfig, MfaConfig, and other plugin config types.
use yauth::prelude::*;
use yauth::backends::diesel_pg::{DieselPgBackend, DieselPool, AsyncDieselConnectionManager, AsyncPgConnection};

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
    let pool = DieselPool::builder(manager).build().unwrap();
    let backend = DieselPgBackend::from_pool(pool);

    let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
        .with_email_password(EmailPasswordConfig::default())
        // Enable additional plugins by adding their feature flags to Cargo.toml
        // (e.g., features = ["email-password", "passkey", "mfa"]):
        // .with_passkey(PasskeyConfig { rp_id: "...".into(), rp_origin: "...".into(), rp_name: "...".into() })
        // .with_mfa(MfaConfig::default())
        .build()
        .await
        .expect("Failed to build YAuth");

    let app = axum::Router::new()
        .nest("/api/auth", yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

#### sqlx + SQLite (no external database needed)

```bash
cargo add yauth --no-default-features --features email-password,sqlx-sqlite-backend
cargo add sqlx --features runtime-tokio,sqlite
cargo add axum
cargo add tokio --features full
cargo yauth init --orm sqlx --dialect sqlite --plugins email-password
sqlx migrate run
```

```rust
use yauth::prelude::*;
use yauth::backends::sqlx_sqlite::SqlxSqliteBackend;

#[tokio::main]
async fn main() {
    let pool = sqlx::SqlitePool::connect("sqlite:yauth.db?mode=rwc").await.unwrap();
    let backend = SqlxSqliteBackend::from_pool(pool);

    let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
        .with_email_password(EmailPasswordConfig::default())
        .build()
        .await
        .expect("Failed to build YAuth");

    let app = axum::Router::new()
        .nest("/api/auth", yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### 4. Add a frontend (optional)

```bash
bun add @yackey-labs/yauth-client
```

```typescript
import { createYAuthClient } from "@yackey-labs/yauth-client";

const auth = createYAuthClient({ baseUrl: "/api/auth" });

await auth.emailPassword.register({ email: "user@example.com", password: "s3cure!Pass" });
await auth.emailPassword.login({ email: "user@example.com", password: "s3cure!Pass" });
const user = await auth.getSession();
await auth.logout();
```

Pre-built UI components are available for [Vue 3](docs/typescript.md#yackey-labsyauth-ui-vue) and [SolidJS](docs/typescript.md#yackey-labsyauth-ui-solidjs).

## Schema Generation CLI

`cargo-yauth` generates migration files for your ORM from a declarative config. It produces files — it does not run migrations or connect to a database.

```bash
cargo install cargo-yauth

cargo yauth init --orm diesel --dialect postgres --plugins email-password,passkey
cargo yauth add-plugin mfa
cargo yauth remove-plugin passkey
cargo yauth status
cargo yauth generate              # Regenerate migration files
cargo yauth generate --check      # CI: verify freshness
```

All commands accept `-f <path>` to specify a config file (default: `yauth.toml`).

**What each ORM generates:**
- **diesel**: `up.sql` + `down.sql` migration files + `schema.rs` with `diesel::table!` macros
- **sqlx**: Numbered `.sql` migration files for `sqlx migrate run`
- **seaorm**: `up.sql` + `down.sql` + `entities/*.rs` with `DeriveEntityModel` structs
- **toasty**: `#[derive(toasty::Model)]` Rust files (no SQL — Toasty manages schema via `push_schema()`)

### yauth.toml

```toml
[migration]
orm = "diesel"           # "diesel" | "sqlx" | "seaorm" | "toasty"
dialect = "postgres"     # "postgres" | "mysql" | "sqlite"
migrations_dir = "migrations"
table_prefix = "yauth_"

[plugins]
enabled = ["email-password", "passkey", "mfa"]
```

No secrets in config -- database URLs come from environment variables only.

## Security

- **Argon2id** password hashing with timing-safe dummy hash on failed lookups
- **HaveIBeenPwned** k-anonymity password breach checking (fail-open)
- **Password policy** — configurable complexity, common password rejection, history tracking
- **Rate limiting** per operation (login, register, forgot-password, magic-link)
- **Account lockout** — per-account brute-force protection with exponential backoff
- **Session binding** — optional IP + User-Agent binding for hijacking detection
- **Session tokens** stored as SHA-256 hashes
- **JWT refresh token family tracking** — automatic revocation on reuse detection
- **CSRF protection** — HttpOnly + SameSite=Lax cookies; bearer/API key via headers
- **Email enumeration prevention** — consistent responses for non-existent accounts
- **Audit logging** — all auth events written to `yauth_audit_log` table
- **WebAuthn challenge TTL** — 5-minute expiry with credential exclusion
- **Webhook signing** — HMAC-SHA256 signatures for payload integrity
- **PKCE S256** — required for all OAuth2 authorization code flows

## Packages

| Package | Type | Purpose |
|---|---|---|
| `yauth` | Rust crate | Main library — plugins, middleware, builder, auth logic, backends |
| `yauth-entity` | Rust crate | Domain types (User, Session, Password, etc.) |
| `yauth-migration` | Rust crate | Schema types, DDL generation, diff engine (zero ORM deps) |
| `cargo-yauth` | Rust crate | CLI binary — `cargo yauth init/add-plugin/remove-plugin/status/generate` |
| `yauth-toasty` | Rust crate | Toasty ORM backends (experimental) |
| `@yackey-labs/yauth-client` | npm | Auto-generated HTTP client for all auth endpoints |
| `@yackey-labs/yauth-shared` | npm | Shared types (`AuthUser`, `AuthSession`, AAGUID map) |
| `@yackey-labs/yauth-ui-vue` | npm | Vue 3 components + composables |
| `@yackey-labs/yauth-ui-solidjs` | npm | SolidJS components + context provider |

## Reference Docs

- [Backend setup guides](docs/backends.md) — detailed examples for all 14 backends + Redis caching
- [API routes](docs/api-routes.md) — complete route tables for every plugin
- [Configuration](docs/configuration.md) — session binding, password policy, lockout, webhooks, OIDC
- [Database schema](docs/schema.md) — full table definitions by plugin
- [TypeScript packages](docs/typescript.md) — client API, Vue composables/components, SolidJS components

## Development

```bash
# Rust
cargo test --workspace --features full,all-backends --lib   # Unit tests
cargo clippy --workspace --features full,all-backends -- -D warnings
cargo fmt --check

# TypeScript
bun install
bun validate          # lint:fix + typecheck + build
bun generate          # regenerate TS client from Rust types
bun generate:check    # CI: fail if client is out of date

# Integration testing (requires docker compose up -d)
docker compose up -d
cargo test --features full,all-backends --test repo_conformance  # 65 tests across 7 backends
cargo test --features full,all-backends --test pentest           # OWASP pentest suite

# Migration CLI
cargo yauth generate --check -f yauth-diesel-pg.toml   # Verify generated artifacts are fresh
```

## Versioning

Automated via [knope](https://knope.tech) from conventional commits. Never manually edit version numbers. All Rust crates and npm packages share a single unified version.

## License

MIT
