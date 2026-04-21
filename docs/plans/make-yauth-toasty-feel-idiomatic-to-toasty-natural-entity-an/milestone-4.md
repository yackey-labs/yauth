# Milestone 4: Documentation + Examples

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone delivers the documentation, examples, and tooling updates that make yauth-toasty discoverable and adoptable. After this milestone, a developer can read the README, copy the example, and have a working yauth app on the Toasty backend in under 5 minutes.

**Toasty version: 0.4** (consistent with M1, M2, M3).

---

## Goal

Provide complete documentation for yauth-toasty: a standalone README, updated project-wide docs (`CLAUDE.md`, `docs/backends.md`), a minimal runnable example app, and updated `cargo yauth generate --orm toasty` scaffolding output.

---

## Deliverables

### 1. `crates/yauth-toasty/README.md`

A standalone README for the crate covering:

```markdown
# yauth-toasty

Toasty ORM backend for [yauth](https://github.com/yackey-labs/yauth) — the plugin-based authentication library for Rust/Axum.

> **Status: Experimental** (`publish = false`). API may change. Not yet recommended for production.

## Features

- All 14 yauth plugins supported (email-password, passkey, MFA, OAuth, bearer, API keys, admin, OAuth2 server, etc.)
- PostgreSQL, MySQL, and SQLite via Toasty's driver system
- Native Toasty idioms: `#[belongs_to]`/`#[has_many]` relationships, `jiff::Timestamp`, `#[serialize(json)]`
- Embedded migrations — one function call at startup, no CLI required for consumers
- 65+ conformance tests verifying behavioral parity with diesel/sqlx backends

## Quick Start

```toml
# Cargo.toml
[dependencies]
yauth = { version = "0.12", default-features = false, features = ["email-password", "passkey"] }
yauth-toasty = { path = "../yauth-toasty", features = ["full", "sqlite"] }
toasty = { version = "0.4", features = ["sqlite"] }
```

```rust
use yauth::{YAuthBuilder, YAuthConfig};
use yauth::plugins::EmailPasswordConfig;
use yauth_toasty::{ToastySqliteBackend, apply_migrations};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create Toasty database
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .register_models(yauth_toasty::all_models!())
        .connect("sqlite:./myapp.db")
        .await?;

    // 2. Apply migrations (idempotent — safe on every startup)
    apply_migrations(&db).await?;

    // 3. Build yauth with Toasty backend
    let backend = ToastySqliteBackend::from_db(db);
    let config = YAuthConfig::default();
    let yauth = YAuthBuilder::new(backend, config)
        .with_email_password(EmailPasswordConfig::default())
        .build()
        .await?;

    // 4. Mount on Axum
    let app = axum::Router::new()
        .merge(yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Backends

| Backend | Feature | Driver |
|---------|---------|--------|
| `ToastyPgBackend` | `postgresql` | PostgreSQL via `toasty-driver-postgresql` |
| `ToastyMysqlBackend` | `mysql` | MySQL 8.0+ via `toasty-driver-mysql` |
| `ToastySqliteBackend` | `sqlite` | SQLite via `toasty-driver-sqlite` |

## Migrations

yauth-toasty ships with embedded migrations. Call `apply_migrations(&db)` once at startup:

- Creates a `__yauth_toasty_migrations` tracking table
- Applies pending migrations in order
- Validates checksums (rejects tampered migration files)
- Idempotent — safe to call on every app start

For development/testing, use `push_schema()` instead (faster, no tracking).

## Plugin Features

Enable plugins via feature flags (same as yauth core):

| Feature | Plugin |
|---------|--------|
| `email-password` | Registration, login, verification, forgot/reset password |
| `passkey` | WebAuthn registration + login |
| `mfa` | TOTP + backup codes |
| `oauth` | OAuth2 provider linking |
| `bearer` | JWT access/refresh tokens |
| `api-key` | API key generation + validation |
| `admin` | User management, ban/unban, impersonation |
| `oauth2-server` | OAuth2 authorization server |
| `account-lockout` | Brute-force lockout |
| `magic-link` | Passwordless email login |
| `webhooks` | Event webhooks |
| `full` | All plugins |
```

### 2. Minimal Runnable Example App

Create `examples/toasty_backend.rs` (≤30 lines of wiring):

```rust
//! Minimal yauth app using the Toasty ORM backend.
//!
//! Run with:
//!   cargo run -p yauth-toasty --example toasty_backend --features full,sqlite
//!
//! Then test:
//!   curl -X POST http://localhost:3000/auth/register \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "test@example.com", "password": "SecureP@ss123!"}'

use yauth::{YAuthBuilder, YAuthConfig};
use yauth::plugins::EmailPasswordConfig;
use yauth_toasty::{ToastySqliteBackend, apply_migrations};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Build Toasty DB + apply migrations (creates tables if needed)
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .register_models(yauth_toasty::all_models!())
        .connect("sqlite:./example.db")
        .await?;
    apply_migrations(&db).await?;

    // Wire yauth with Toasty backend
    let backend = ToastySqliteBackend::from_db(db);
    let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
        .with_email_password(EmailPasswordConfig::default())
        .build()
        .await?;

    // Serve
    let app = axum::Router::new()
        .merge(yauth.router())
        .with_state(yauth.state().clone());

    println!("Listening on http://0.0.0.0:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

This example demonstrates the full consumer adoption path in **20 lines of meaningful code** (excluding imports and comments):
1. Create Toasty Db with models
2. Apply migrations (one call)
3. Create backend from Db
4. Build yauth with plugins
5. Mount and serve

### 3. Full-Stack Flow Example

Create `examples/toasty_full_flow.rs` — demonstrates create user, query, update, and relationship traversal:

```rust
//! Full-stack flow demonstrating Toasty backend capabilities.
//!
//! Run with:
//!   cargo run -p yauth-toasty --example toasty_full_flow --features full,sqlite

use uuid::Uuid;
use yauth::repo::DatabaseBackend;
use yauth_toasty::{ToastySqliteBackend, apply_migrations};
use yauth_entity::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .register_models(yauth_toasty::all_models!())
        .connect("sqlite::memory:")
        .await?;
    apply_migrations(&db).await?;
    let backend = ToastySqliteBackend::from_db(db);
    let repos = backend.repositories();

    // === Create a user ===
    let user_id = Uuid::now_v7();
    let user = repos.users.create(NewUser {
        id: user_id,
        email: "alice@example.com".to_string(),
        display_name: Some("Alice".to_string()),
        email_verified: false,
        role: "user".to_string(),
        banned: false,
        banned_reason: None,
        banned_until: None,
        created_at: chrono::Utc::now().naive_utc(),
        updated_at: chrono::Utc::now().naive_utc(),
    }).await?;
    println!("Created user: {} ({})", user.email, user.id);

    // === Query by email (case-insensitive) ===
    let found = repos.users.find_by_email("ALICE@EXAMPLE.COM").await?;
    assert!(found.is_some());
    println!("Found by email: {:?}", found.unwrap().display_name);

    // === Update user ===
    let updated = repos.users.update(user_id, UpdateUser {
        email_verified: Some(true),
        display_name: Some(Some("Alice Wonderland".to_string())),
        ..Default::default()
    }).await?;
    println!("Updated: email_verified={}, name={:?}", updated.email_verified, updated.display_name);

    // === Create a session (relationship: user has_many sessions) ===
    let session_id = repos.session_ops.create_session(
        user_id,
        "token_hash_abc123".to_string(),
        Some("127.0.0.1".to_string()),
        Some("Mozilla/5.0".to_string()),
        std::time::Duration::from_secs(3600),
    ).await?;
    println!("Created session: {}", session_id);

    // === Validate session ===
    let session = repos.session_ops.validate_session("token_hash_abc123").await?;
    assert!(session.is_some());
    println!("Session valid for user: {}", session.unwrap().user_id);

    // === Cascade delete: deleting user removes sessions ===
    repos.users.delete(user_id).await?;
    let session_after = repos.session_ops.validate_session("token_hash_abc123").await?;
    assert!(session_after.is_none());
    println!("After user delete: session gone (cascade works)");

    println!("\n✓ All operations succeeded!");
    Ok(())
}
```

### 4. `CLAUDE.md` Updates

Add yauth-toasty to the workspace structure table:

```markdown
### Rust Crates (`crates/`)

| Crate | Purpose |
|---|---|
| `yauth` | Main library — plugins, middleware, builder, auth logic, backends, repository traits |
| `yauth-entity` | Domain types (User, Session, Password, etc.) — ORM-agnostic |
| `yauth-migration` | Schema types, DDL generation, diff engine, migration file gen |
| `cargo-yauth` | CLI binary — `cargo yauth init/add-plugin/remove-plugin/status/generate` |
| `yauth-toasty` | Toasty ORM backend — idiomatic entities, embedded migrations, PG/MySQL/SQLite |
```

Add to the Key Commands section:

```markdown
# Toasty backend
cargo test -p yauth-toasty --features full,sqlite --test conformance   # Conformance tests (SQLite)
cargo test -p yauth-toasty --features full,sqlite --test migrations    # Migration tests
cargo clippy -p yauth-toasty --features full,sqlite -- -D warnings     # Lint

# With databases:
DATABASE_URL=postgres://yauth:yauth@127.0.0.1:5433/yauth_test \
  cargo test -p yauth-toasty --features full,postgresql --test conformance

MYSQL_DATABASE_URL=mysql://yauth:yauth@127.0.0.1:3307/yauth_test \
  cargo test -p yauth-toasty --features full,mysql --test conformance
```

Add to the Backend Features table:

```markdown
| `toasty-backend` | Toasty ORM backend (experimental) — PG, MySQL, SQLite via Toasty's driver system | No |
```

Add a note in the Architecture > Database Backends section:

```markdown
| `ToastyPgBackend` | `yauth-toasty` | `from_db(db)` | PostgreSQL via Toasty (experimental) |
| `ToastyMysqlBackend` | `yauth-toasty` | `from_db(db)` | MySQL via Toasty (experimental) |
| `ToastySqliteBackend` | `yauth-toasty` | `from_db(db)` | SQLite via Toasty (experimental) |
```

### 5. `docs/backends.md` Update

Add a new section for the Toasty backend:

```markdown
## Toasty (Experimental)

> Status: Experimental. Not published to crates.io yet.

### Dependencies

```toml
[dependencies]
yauth = { version = "0.12", default-features = false, features = ["full"] }
yauth-toasty = { path = "crates/yauth-toasty", features = ["full", "sqlite"] }
toasty = { version = "0.4", features = ["sqlite"] }
axum = "0.7"
tokio = { version = "1", features = ["full"] }
```

### Setup

```rust
use yauth_toasty::{ToastySqliteBackend, apply_migrations};

let db = toasty::Db::builder()
    .table_name_prefix("yauth_")
    .register_models(yauth_toasty::all_models!())
    .connect("sqlite:./myapp.db")  // or "postgres://..." or "mysql://..."
    .await?;

// Apply embedded migrations (idempotent)
apply_migrations(&db).await?;

let backend = ToastySqliteBackend::from_db(db);
// For PostgreSQL: ToastyPgBackend::from_db(db)
// For MySQL: ToastyMysqlBackend::from_db(db)
```

### Key Differences from Diesel/SQLx Backends

- **One crate covers all three databases.** Pick the driver via feature flag, same code otherwise.
- **Embedded migrations.** Call `apply_migrations(&db)` — no external CLI needed.
- **Code-first schema.** Models are the source of truth. Migrations are generated from model diffs.
- **`push_schema()` for development.** Instant schema creation without migration tracking.
```

### 6. `cargo yauth generate --orm toasty` Output Update

Update the `cargo-yauth` CLI to emit idiomatic Toasty 0.4 patterns when `--orm toasty` is specified.

**File:** `crates/cargo-yauth/src/generate.rs` (or equivalent)

**Before (pre-M4):** `cargo yauth generate --orm toasty` is either unimplemented or emits the old-style entities (String timestamps, no relationships).

**After (M4):** Emits idiomatic entity structs matching the patterns established in M1:

```rust
// Generated by `cargo yauth generate --orm toasty`

#[derive(Debug, toasty::Model)]
#[toasty(table = "yauth_users")]
pub struct YauthUser {
    #[key]
    pub id: Uuid,

    #[unique]
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,

    #[has_many]
    pub sessions: toasty::HasMany<YauthSession>,
    // ...
}
```

The generated output should:
- Use `jiff::Timestamp` for all datetime fields (not `String`)
- Use `#[belongs_to]`/`#[has_many]`/`#[has_one]` for all relationships
- Use `#[serialize(json)]` for JSON fields
- Include the `Toasty.toml` configuration file
- Include a `toasty-dev.rs` stub binary for migration generation
- NOT include any hand-rolled SQL files

**Template files to update in `cargo-yauth`:**
- `templates/toasty/Cargo.toml.tmpl` — deps including `jiff`, `include_dir`, toasty with `jiff` feature
- `templates/toasty/Toasty.toml.tmpl` — migration config
- `templates/toasty/entities/*.rs.tmpl` — per-entity templates with relationships + jiff timestamps
- `templates/toasty/bin/toasty-dev.rs.tmpl` — dev CLI binary stub

### 7. Example Verifying the Full Pipeline

Add a CI integration test or script that exercises the complete user-facing workflow:

```bash
#!/bin/bash
# scripts/test-toasty-example.sh
# Verifies the example app starts and handles a request

set -euo pipefail

# Build and start the example in background
cargo run -p yauth-toasty --example toasty_backend --features full,sqlite &
PID=$!
sleep 2  # Wait for server startup

# Register a user
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "SecureP@ss123!"}')

kill $PID 2>/dev/null || true
rm -f example.db

if [ "$RESPONSE" = "200" ] || [ "$RESPONSE" = "201" ]; then
  echo "✓ Toasty backend example works end-to-end"
  exit 0
else
  echo "✗ Expected 200/201, got $RESPONSE"
  exit 1
fi
```

---

## File-by-File Changes

| File | Change |
|------|--------|
| `crates/yauth-toasty/README.md` | **New.** Standalone crate README with quick start, backend table, migration docs, feature table. |
| `crates/yauth-toasty/examples/toasty_backend.rs` | **New.** Minimal runnable example (≤30 lines of wiring). |
| `crates/yauth-toasty/examples/toasty_full_flow.rs` | **New.** Full-stack flow: create, query, update, relationship traversal, cascade delete. |
| `CLAUDE.md` | Add yauth-toasty to workspace table, key commands, backend features table, architecture backends table. |
| `docs/backends.md` | Add Toasty section with deps, setup code, and key differences from diesel/sqlx. |
| `crates/cargo-yauth/src/generate.rs` | Update `--orm toasty` codegen to emit idiomatic 0.4 patterns (jiff, relationships, serialize(json)). |
| `crates/cargo-yauth/templates/toasty/` | Update template files for entity generation, Cargo.toml, Toasty.toml, toasty-dev binary. |
| `scripts/test-toasty-example.sh` | **New.** Integration script verifying the example app runs end-to-end. |
| `crates/yauth-toasty/Cargo.toml` | Add `[[example]]` entries for the two example binaries. Add `env_logger` as dev-dep. |

---

## Acceptance Criteria / Verification

1. **`crates/yauth-toasty/README.md` exists** and contains: quick start, backend table, migration docs, feature table.
2. **Example compiles:** `cargo build -p yauth-toasty --example toasty_backend --features full,sqlite` — succeeds.
3. **Example runs:** `cargo run -p yauth-toasty --example toasty_backend --features full,sqlite` — server starts, responds to `/auth/register`.
4. **Full-flow example compiles and runs:** `cargo run -p yauth-toasty --example toasty_full_flow --features full,sqlite` — prints success message, exits 0.
5. **CLAUDE.md updated:** grep for `yauth-toasty` in `CLAUDE.md` — appears in workspace table, key commands, and backends table.
6. **`docs/backends.md` updated:** grep for `Toasty` in `docs/backends.md` — Toasty section present with setup code.
7. **`cargo yauth generate --orm toasty` output uses jiff:** the generated entity structs use `jiff::Timestamp` (not `String`) for datetime fields.
8. **`cargo yauth generate --orm toasty` output uses relationships:** generated structs include `#[belongs_to]`/`#[has_many]`.
9. **No hand-rolled SQL in generated output:** `cargo yauth generate --orm toasty` does NOT produce `schema.sql` or per-dialect SQL files. It produces `Toasty.toml` + entity source + `toasty-dev.rs` binary.
10. **Consistency check:** the README's quick-start code matches the example app code (same API calls, same import paths).
11. **All docs reference toasty 0.4** — no stale references to 0.3.
12. **`cargo doc -p yauth-toasty --features full,sqlite --no-deps`** — generates docs without warnings. `apply_migrations` appears in the root module documentation.

---

## Out of Scope

- **Tutorial or blog post.** The README + examples are sufficient. Long-form tutorials are marketing, not engineering.
- **Video walkthrough.** Out of scope.
- **Benchmarks or performance documentation.** Toasty backend performance relative to diesel/sqlx is not documented yet — that's future work when the backend is production-ready.
- **Migration guide from diesel/sqlx to toasty.** Users don't migrate between backends; they pick one at project start.
- **API reference docs beyond rustdoc.** `cargo doc` is sufficient. No separate API docs site.
- **Updating the Vue/SolidJS TypeScript packages.** The TypeScript client is backend-agnostic — it talks to HTTP endpoints. No changes needed.
- **Updating `openapi.json` or the generated client.** The API routes are unchanged; only the backend implementation differs.

---

## Known Pitfalls

1. **Example binary deps.** The example needs `env_logger`, `axum`, and `tokio` as dev-dependencies. Ensure these are added to `[dev-dependencies]` in `Cargo.toml` with appropriate features. `axum` is already a transitive dep via `yauth` but may need to be explicit for the example binary.

2. **`all_models!()` macro path.** The README and examples use `yauth_toasty::all_models!()`. Ensure this macro is exported from `lib.rs` and works correctly when called from an external crate (not just within `yauth-toasty` itself). The macro expands `toasty::models!(...)` with all entity types — verify cross-crate expansion works.

3. **`cargo yauth generate --orm toasty` may not exist yet.** If the `cargo-yauth` CLI doesn't currently support `--orm toasty`, this milestone adds it. Check the existing CLI code to understand the template system before implementing.

4. **Example database file cleanup.** The `toasty_backend` example creates `./example.db`. Add it to `.gitignore`. The full-flow example uses `:memory:` so no cleanup needed.

5. **Documentation freshness.** After M1-M3 change the code, documentation must match the final API. Write docs after M1-M3 are complete, not before, to avoid drift. If writing docs in parallel, re-verify all code snippets compile after M3 merges.

6. **`docs/backends.md` formatting.** The existing file uses a specific section structure. Match the formatting of existing backend sections (diesel-pg, sqlx-pg, etc.) when adding the Toasty section.

7. **`CLAUDE.md` is the source of truth for AI tools.** Updates to `CLAUDE.md` must be accurate — Claude Code and other AI tools read it to understand the codebase. Double-check that command examples, feature flag names, and crate paths are correct.
