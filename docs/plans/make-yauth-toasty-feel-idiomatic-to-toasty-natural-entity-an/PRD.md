# Make yauth-toasty Idiomatic to Toasty

## Overview

Refactor the `yauth-toasty` crate so that its entity definitions, query patterns, and migration strategy align with toasty's canonical idioms. Today yauth-toasty uses raw UUID foreign-key fields, string-encoded timestamps, hand-rolled per-dialect backend modules (`pg/`, `mysql/`, `sqlite/`), and `push_schema()` for setup. This PRD replaces those patterns with:

- **Toasty relationships** (`BelongsTo`, `HasMany`, `HasOne`) instead of bare `Uuid` FK fields
- **`jiff::Timestamp`** for datetime fields (toasty's canonical time type) instead of `String`
- **Toasty's snapshot-anchored migration chain** instead of `push_schema()` in production
- **Embedded migrations** shipped inside the crate for zero-CLI consumer UX
- **Workspace membership** so the crate participates in root `cargo test` / `cargo clippy`

The crate remains `publish = false` and experimental until acceptance criteria (below) are met.

## Motivation

yauth-toasty currently works but feels like a diesel backend wearing a toasty costume. Developers choosing toasty expect:

1. Relationship fields they can traverse (`session.user().exec(&mut db)`) instead of manually joining on a UUID column.
2. Typed timestamps (`jiff::Timestamp`) instead of parsing ISO 8601 strings at every boundary.
3. Migrations generated from model definitions by `toasty-cli`, not hand-written SQL per dialect.
4. A single `apply_migrations(&db).await?` call at startup — no separate CLI for consumers.

Fixing these makes the toasty backend genuinely attractive to toasty-native projects.

## Scope

### In Scope

- Entity UX overhaul (relationships, jiff timestamps)
- Migration system aligned with toasty's `migration generate` workflow
- Embedded migration delivery for consumers
- Workspace integration
- Feature-gated model strategy
- Query patterns using toasty-generated methods and `create!` macro exclusively

### Out of Scope

- Switching any application (freshstrings, vault, etc.) to the toasty backend
- Changing yauth's primary diesel backend
- Versioning changes (knope manages versions automatically)
- DynamoDB support (yauth's schema is relational)

---

## Technical Design

### 1. Entity UX: Toasty Attributes and Relationships

#### 1.1 Derive and Key Strategy

All models use `#[derive(toasty::Model)]`. Primary keys use `#[key]` **without** `#[auto]` — yauth generates UUIDv7 client-side per project convention. The `#[auto]` attribute is reserved only for integer auto-increment keys which yauth does not use.

```rust
#[derive(Debug, toasty::Model)]
#[table = "users"]
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

    // Relationships
    #[has_many]
    pub sessions: toasty::HasMany<YauthSession>,
    #[has_many]
    pub passkeys: toasty::HasMany<YauthPasskey>,
    #[has_one]
    pub password: toasty::HasOne<Option<YauthPassword>>,
}
```

#### 1.2 Relationship Pattern

Foreign-key relationships use `BelongsTo` on the child side and `HasMany`/`HasOne` on the parent:

```rust
#[derive(Debug, toasty::Model)]
#[table = "sessions"]
pub struct YauthSession {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<YauthUser>,

    #[unique]
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: jiff::Timestamp,
    pub created_at: jiff::Timestamp,
}
```

The FK column (`user_id`) remains as the indexed `Uuid` field; the `BelongsTo` field adds traversal capability without changing the database schema. This applies uniformly:

| Child Entity | FK Field | Parent | Relationship |
|---|---|---|---|
| `YauthSession` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthPassword` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthPasskey` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthApiKey` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthOauthAccount` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthRefreshToken` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthTotpSecret` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthBackupCode` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthMagicLink` | `user_id` | `YauthUser` | `BelongsTo<YauthUser>` |
| `YauthWebhookDelivery` | `webhook_id` | `YauthWebhook` | `BelongsTo<YauthWebhook>` |
| `YauthAuthorizationCode` | `client_id_ref` | `YauthOauth2Client` | `BelongsTo<YauthOauth2Client>` |
| `YauthConsent` | `client_id_ref` | `YauthOauth2Client` | `BelongsTo<YauthOauth2Client>` |
| `YauthDeviceCode` | `client_id_ref` | `YauthOauth2Client` | `BelongsTo<YauthOauth2Client>` |

#### 1.3 Timestamp Fields: `jiff::Timestamp`

Replace all `String`-typed timestamp fields with `jiff::Timestamp`. Toasty maps `jiff::Timestamp` to the appropriate database column type per dialect (TIMESTAMPTZ on PG, DATETIME on MySQL/SQLite). This eliminates the `helpers.rs` datetime string conversion layer entirely.

The `jiff` feature is enabled on the `toasty` dependency:

```toml
toasty = { version = "0.4", default-features = false, features = ["jiff"] }
```

Domain conversion between `jiff::Timestamp` and yauth's `chrono::NaiveDateTime` uses a thin boundary layer:

```rust
fn jiff_to_chrono(ts: jiff::Timestamp) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(ts.as_second(), ts.subsec_nanosecond() as u32)
        .unwrap_or_default()
        .naive_utc()
}

fn chrono_to_jiff(dt: chrono::NaiveDateTime) -> jiff::Timestamp {
    jiff::Timestamp::from_second(dt.and_utc().timestamp())
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
}
```

This is explicit: yauth-entity uses chrono (shared across all backends), yauth-toasty bridges to jiff at the boundary. If yauth-entity ever migrates to jiff, the conversion disappears.

---

### 2. Migrations: Toasty's Snapshot-Anchored Chain

#### 2.1 Migration File Structure

Migrations live at `crates/yauth-toasty/toasty/` following toasty's canonical layout:

```
crates/yauth-toasty/
  Toasty.toml
  toasty/
    history.toml
    migrations/
      0001_initial_core.sql
      0002_email_password.sql
      0003_passkey.sql
      0004_mfa.sql
      ...
    snapshots/
      0001_snapshot.toml
      0002_snapshot.toml
      ...
```

#### 2.2 `Toasty.toml` Configuration

Located at `crates/yauth-toasty/Toasty.toml`:

```toml
[migration]
path = "toasty"
statement_breakpoints = true
prefix_style = "Sequential"
```

These match toasty's defaults for `statement_breakpoints` and `prefix_style`. The `path` is explicit for clarity.

#### 2.3 Generation Workflow (Developer-Only)

Migrations are generated by a dev-only binary inside the crate. This binary is NOT published and NOT required by consumers:

```
crates/yauth-toasty/src/bin/toasty_dev.rs
```

Developers generating migrations run:

```bash
cargo run --bin toasty-dev -- migration generate --name initial_core
```

The binary wraps `toasty-cli`'s generation logic, configured to read models from the crate and write to the `toasty/` directory. It uses the `Toasty.toml` at the crate root.

When models change (e.g., adding a new entity for a new plugin), the developer:

1. Edits/adds the model struct in `src/entities/`
2. Runs `cargo run --bin toasty-dev -- migration generate --name describe_change`
3. Commits the resulting `migrations/NNNN_*.sql` + `snapshots/NNNN_snapshot.toml` + updated `history.toml`

Toasty's diff engine handles per-dialect SQL generation from the single model definition — no separate `pg/`, `mysql/`, `sqlite/` SQL directories.

#### 2.4 Embedded Migrations for Consumers

Consumers never run a CLI. The crate ships migrations embedded via `include_str!` / `include_dir!`:

```rust
// crates/yauth-toasty/src/migrations.rs

use include_dir::{include_dir, Dir};

static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/toasty/migrations");

/// Apply all pending yauth migrations to the database.
///
/// Call this once at application startup before constructing the backend.
/// Idempotent — already-applied migrations are skipped.
///
/// ```rust
/// let db = toasty::Db::builder()
///     .connect("postgres://localhost/myapp")
///     .await?;
/// yauth_toasty::apply_migrations(&db).await?;
/// ```
pub async fn apply_migrations(db: &toasty::Db) -> Result<(), yauth::repo::RepoError> {
    // Reads history.toml embedded in the binary, applies pending .sql files
    // in sequence order, records each in the migrations tracking table.
    todo!("implement using toasty's migration apply API")
}
```

The consumer's startup becomes:

```rust
let db = toasty::Db::builder()
    .table_name_prefix("yauth_")
    .models(toasty::models!(yauth_toasty::entities::*))
    .connect(&database_url)
    .await?;

yauth_toasty::apply_migrations(&db).await?;

let backend = yauth_toasty::pg::ToastyPgBackend::from_db(db);
let yauth = YAuthBuilder::new(backend, config)
    .with_email_password(ep_config)
    .build()
    .await?;
```

This is <= 30 lines of wiring including the migration call — meeting the acceptance criterion.

#### 2.5 Remove Per-Dialect SQL Directories

The existing `src/pg/`, `src/mysql/`, `src/sqlite/` modules currently differ only in their connection URL handling and the `build_db()` method. After this change:

- **Remove** the duplicated `build_db()` + `all_models()` pattern from each dialect module
- **Consolidate** into a single `ToastyBackend` struct (or keep thin per-dialect types that differ only in their constructor for type safety), all sharing the same `common::build_repositories()` implementation
- **No per-dialect SQL files** — toasty generates dialect-appropriate DDL at migration-generation time based on which driver feature is enabled

The per-dialect modules (`pg/mod.rs`, `mysql/mod.rs`, `sqlite/mod.rs`) remain as thin type wrappers providing `new(url)` / `from_db(db)` constructors, but they no longer contain SQL or schema logic.

---

### 3. Query and Create UX: Toasty-Native Patterns

#### 3.1 No Raw SQL

All repository implementations use toasty's generated query methods exclusively:

| Operation | Pattern |
|---|---|
| Find by ID | `YauthUser::get_by_id(&mut db, &id).await` |
| Find by unique field | `YauthUser::filter_by_email(&email).first(&mut db).await` |
| Create | `toasty::create!(YauthUser { id, email, ... }).exec(&mut db).await` |
| Update | `user.update().email("new@x.com").exec(&mut db).await` |
| Delete | `user.delete().exec(&mut db).await` |
| List all | `YauthUser::all().exec(&mut db).await` |
| Filter | `YauthSession::filter(YauthSession::fields().user_id().eq(uid)).exec(&mut db).await` |
| Traverse relation | `user.sessions().exec(&mut db).await` |
| Scoped create | `toasty::create!(in user.sessions() { ... }).exec(&mut db).await` |

The existing `tokio-postgres` optional dependency for raw SQL fallback is **removed**. If toasty cannot express a query, that gap is documented (see Section 6) rather than papered over.

#### 3.2 Known Toasty Gaps

These operations may not be expressible in toasty's current (0.4.x) query API:

| Gap | Current Workaround | Proposed Resolution |
|---|---|---|
| `ILIKE` / case-insensitive search | Application-layer filter (fetch all, filter in Rust) | Accept as limitation; document. Toasty issue filed. |
| Aggregate `COUNT(*)` | Fetch all, `.len()` | Accept; bounded by yauth's typical table sizes |
| Bulk delete by filter | Loop + individual deletes | Use `Model::filter(...).delete().exec()` if supported in 0.4; else loop |
| `DELETE CASCADE` behavior | Manual deletion of children before parent | Implement in application code via relationship traversal |
| Complex `WHERE` with `OR` | Multiple queries | Accept; yauth's queries are simple enough |

Each gap is tracked as a known limitation in the crate's docs. No raw SQL is introduced — if a gap is blocking, it's escalated to the toasty project or the operation is decomposed into supported primitives.

---

### 4. Feature-Gated Models and the Migration Schema

#### 4.1 Decision: All Models Always in Schema

Feature-gated models (e.g., `YauthPasskey` behind `#[cfg(feature = "passkey")]`) present a tension with migrations: if a consumer enables `email-password` but not `passkey`, should the `yauth_webauthn_credentials` table exist?

**Decision: Yes — all tables are always created.**

Rationale:
- Migrations are static SQL files committed to the crate. Generating per-feature-combination variants is combinatorially explosive (2^11 plugin features = 2048 variants).
- Unused tables cost nothing (no indexes hot, no writes happening).
- This matches how diesel/sqlx backends work: `cargo yauth generate` always emits all tables for enabled plugins, and the recommended practice is to generate for `full`.
- Upgrading (enabling a new feature later) requires no additional migration — the table already exists.
- The code-level `#[cfg(feature = "...")]` gates remain on the entity struct definitions and repository implementations, so disabled-feature code is not compiled and the API surface stays clean.

The migration chain generates tables for ALL plugins. The Rust model structs remain feature-gated so that:
- `YauthPasskey` type and `PasskeyRepository` impl only compile with `passkey` feature
- The `yauth_webauthn_credentials` table exists in the database regardless
- A consumer enabling `passkey` later needs zero schema changes

#### 4.2 Migration Ordering

Migration files follow plugin dependency order (topological sort, matching `yauth-migration`'s existing collector):

1. `0001_initial_core.sql` — users, sessions, audit_log, challenges, rate_limits, revocations
2. `0002_email_password.sql` — passwords, email_verifications, password_resets
3. `0003_passkey.sql` — webauthn_credentials
4. `0004_mfa.sql` — totp_secrets, backup_codes
5. `0005_oauth.sql` — oauth_accounts, oauth_states
6. `0006_bearer.sql` — refresh_tokens
7. `0007_api_key.sql` — api_keys
8. `0008_magic_link.sql` — magic_links
9. `0009_oauth2_server.sql` — oauth2_clients, authorization_codes, consents, device_codes
10. `0010_account_lockout.sql` — account_locks, unlock_tokens
11. `0011_webhooks.sql` — webhooks, webhook_deliveries

All are applied by `apply_migrations()` regardless of which features the consumer has enabled.

---

### 5. Workspace Integration

#### 5.1 Add to Workspace Members

Move `crates/yauth-toasty` from `exclude` to `members` in the root `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/yauth",
    "crates/yauth-migration",
    "crates/yauth-entity",
    "crates/cargo-yauth",
    "crates/yauth-toasty",
]
# remove: exclude = ["crates/yauth-toasty"]
resolver = "2"
```

#### 5.2 Resolving the `links` Conflict

The crate was excluded because toasty's SQLite driver (`toasty-driver-sqlite`) depends on a different `libsqlite3-sys` version than sqlx's SQLite feature. Resolution:

1. **Feature-gate the SQLite driver** — the `sqlite` feature on `yauth-toasty` pulls in `toasty-driver-sqlite`. Without it, no `libsqlite3-sys` conflict.
2. **CI uses `--features postgresql,mysql` for yauth-toasty** — SQLite tests run in a separate CI job that does NOT compile sqlx's sqlite backend in the same invocation.
3. **Root workspace `cargo test`** does NOT enable `yauth-toasty/sqlite` by default. The crate's `default-features = []` ensures no conflict on a bare `cargo test`.
4. **If the conflict persists at the workspace resolver level** even without enabling the feature, use Cargo's `[patch]` or `[workspace.dependencies]` to unify `libsqlite3-sys` versions, or pin to a toasty version that aligns. Document the specific version constraint.

If none of these resolve the conflict cleanly, the fallback is: keep `exclude` but add a dedicated CI step (`cargo test -p yauth-toasty --features postgresql,full`) and document the reason in `CLAUDE.md`. This is acceptable but not preferred.

#### 5.3 Shared Workspace Version

`yauth-toasty` uses the workspace version (`workspace.package.version`) via:

```toml
[package]
name = "yauth-toasty"
version.workspace = true
```

This ensures knope manages its version alongside all other crates. `publish = false` remains until acceptance criteria are met.

---

### 6. Testing Strategy

#### 6.1 Unit / Development Tests

Use `db.push_schema().await?` for speed — no migration files needed, toasty creates tables from model definitions directly:

```rust
#[tokio::test]
async fn test_user_crud() {
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .models(toasty::models!(yauth_toasty::entities::*))
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db.push_schema().await.unwrap();
    // ... test using repos ...
}
```

#### 6.2 Integration / Conformance Tests

Use `apply_migrations(&db).await?` to verify the embedded migration chain works end-to-end. The existing conformance test suite (`tests/conformance.rs`) switches to this path:

```rust
// Integration test setup
let db = build_db(&url).await?;
yauth_toasty::apply_migrations(&db).await?;
let backend = ToastyPgBackend::from_db(db);
let repos = backend.repositories();
```

#### 6.3 `create_tables()` Deprecation

The current `create_tables()` method (which calls `push_schema()`) remains available but is deprecated in favor of `apply_migrations()` for anything beyond throwaway tests:

```rust
#[deprecated(since = "0.13.0", note = "Use yauth_toasty::apply_migrations() for production setups")]
pub async fn create_tables(&self) -> Result<(), RepoError> { ... }
```

---

### 7. `publish = false` and Acceptance Criteria

The crate stays `publish = false` until ALL of the following are demonstrated:

1. **A scaffold app can adopt yauth-toasty with <= 30 lines of wiring** including the `apply_migrations()` call, backend construction, and `YAuthBuilder` setup.
2. **All 65+ conformance tests pass** on at least PostgreSQL and SQLite toasty backends using the embedded migration path.
3. **No raw SQL** exists in any repository implementation — all queries use toasty's generated methods.
4. **Relationship traversal works** — at minimum `session.user().exec(&mut db)` and `user.sessions().exec(&mut db)` produce correct results in tests.
5. **jiff timestamps round-trip correctly** — no precision loss vs. the chrono domain types (verified by conformance tests).

Once these are met, `publish = false` can be removed and the crate enters the normal release pipeline.

---

## Milestones

### Milestone 1: Entity Overhaul

- Replace all `String` timestamp fields with `jiff::Timestamp`
- Add `BelongsTo` / `HasMany` / `HasOne` relationship fields to all entities
- Remove `helpers.rs` datetime string conversion (replace with jiff<->chrono boundary)
- Enable `jiff` feature on toasty dependency
- Verify all models compile with `cargo check`

### Milestone 2: Migration System

- Add `Toasty.toml` at crate root
- Create `src/bin/toasty_dev.rs` binary for migration generation
- Generate initial migration chain (0001-0011) from model definitions
- Implement `apply_migrations()` with `include_dir!` embedding
- Add `crates/yauth-toasty/toasty/` directory with generated files
- Remove `tokio-postgres` optional dependency

### Milestone 3: Query Patterns + Repo Refactor

- Rewrite all repository implementations to use toasty-generated methods exclusively
- Use relationship traversal where appropriate (e.g., cascade deletes via `user.sessions()`)
- Remove any raw SQL fallback code
- Document known toasty gaps as `// GAP:` comments with tracking info
- Consolidate per-dialect modules (remove duplicated logic from `pg/`, `mysql/`, `sqlite/`)

### Milestone 4: Workspace Integration + CI

- Move crate from `exclude` to `members` in root `Cargo.toml`
- Resolve `libsqlite3-sys` version conflict (feature-gate or CI split)
- Use `version.workspace = true`
- Add CI job for `yauth-toasty` (at minimum: `cargo clippy -p yauth-toasty --features postgresql,full`)
- Update `CLAUDE.md` with toasty-specific test commands

### Milestone 5: Conformance + Acceptance Verification

- Run full conformance suite via `apply_migrations()` path
- Build a minimal scaffold example (< 30 lines) demonstrating end-to-end setup
- Verify relationship traversal in integration tests
- Verify jiff timestamp precision in round-trip tests
- Document results; if all pass, mark ready for `publish = true` in a follow-up PR

---

## Success Metrics

| Metric | Target |
|---|---|
| Conformance test pass rate | 100% on PG + SQLite (MySQL stretch goal) |
| Raw SQL in repo implementations | 0 lines |
| Consumer wiring lines | <= 30 (including migration call) |
| Timestamp precision loss | 0 (second-level accuracy minimum; sub-second where toasty/jiff support it) |
| CI integration | `cargo test` at workspace root includes yauth-toasty (non-sqlite features) |

## Non-Goals

- Switching any existing application to the toasty backend
- Changing yauth's primary diesel backend or its repository trait interfaces
- Supporting toasty's DynamoDB driver (yauth is relational)
- Version number changes (knope handles automatically)
- Publishing the crate to crates.io (stays `publish = false` for now)
