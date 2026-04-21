# Make yauth-toasty Idiomatic to Toasty

## Overview

Rework the `yauth-toasty` crate so that its entity definitions, query patterns, and migration story align with toasty's native idioms — rather than looking like diesel/sqlx structs shoehorned into `#[derive(toasty::Model)]`. The goal is that a developer familiar with toasty would look at yauth-toasty code and immediately recognize it as natural toasty.

The scope is limited to the `yauth-toasty` crate itself. We are **not** switching any existing application to this backend, not touching yauth's primary diesel backends, and not manually managing version numbers (knope handles that).

## Current State

`yauth-toasty` already exists at `crates/yauth-toasty/` with:
- 27 entity structs using `#[derive(toasty::Model)]`
- 17 repository trait implementations (shared via `common/`)
- Three per-dialect backend modules (`pg/`, `mysql/`, `sqlite/`)
- A 65-test conformance suite
- `publish = false` and excluded from the root workspace (`Cargo.toml: exclude = ["crates/yauth-toasty"]`)

**What's un-idiomatic today:**

1. **No relationships.** Foreign keys are bare `Uuid` fields (`user_id: Uuid`) instead of `#[belongs_to]` + `toasty::BelongsTo<T>` wrappers. Parent models don't declare `#[has_many]` / `#[has_one]`.
2. **Timestamps are `String`.** Toasty supports `jiff::Timestamp` via its `jiff` feature. yauth-toasty stores datetimes as ISO 8601 strings and manually parses them through `helpers.rs`.
3. **No migration system.** Schema creation uses `push_schema()` everywhere (fine for tests, not production). There is no `Toasty.toml`, no `toasty/migrations/` directory, no snapshot chain.
4. **Hand-rolled per-dialect SQL dirs.** The `pg/`, `mysql/`, `sqlite/` backend modules each construct a `Db` independently, duplicating logic. Toasty's point is that one model definition covers all dialects; the per-dialect dirs exist only to pick the driver.
5. **Raw SQL fallback dependency.** `tokio-postgres` is an optional dep "for complex queries Toasty can't express" — but no code uses it. Toasty's query API now covers the needed patterns.
6. **Excluded from workspace.** `cargo test` / `cargo clippy` at the root doesn't catch regressions in yauth-toasty.

## Core Changes

### 1. Idiomatic Entity Definitions

Rewrite all 27 entity structs to use toasty's relationship and timestamp idioms.

**Relationships — use `#[belongs_to]` / `#[has_many]` / `#[has_one]`:**

Every foreign key gets both a concrete column field and a virtual relationship field:

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

And the parent declares the inverse:

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

    #[has_many]
    pub sessions: toasty::HasMany<YauthSession>,

    #[has_many]
    pub passkeys: toasty::HasMany<YauthPasskey>,
    // ... other has_many for each child entity
}
```

This unlocks toasty features like association filtering (`User::filter(User::fields().sessions().any(...))`), eager loading (`.include(User::fields().sessions())`), and cascading deletes (toasty auto-deletes children when a required FK parent is deleted).

**Primary keys — `#[key]` without `#[auto]` for UUIDs:**

yauth uses UUIDv7 generated client-side (per convention in CLAUDE.md). Entity key fields are `#[key] id: Uuid` without `#[auto]` — the caller supplies the ID. Toasty's default `#[auto]` strategy for `Uuid` is v7, which matches yauth's convention, but we omit `#[auto]` because IDs are generated in the yauth domain layer (the `New*` input structs carry an `id` field).

Exception: `YauthPassword` uses `#[key] user_id: Uuid` (the FK is the PK, 1:1 relationship). This remains as-is but gains `#[belongs_to]`.

**Timestamps — use `jiff::Timestamp`:**

Replace all `pub created_at: String` / `pub expires_at: String` fields with `jiff::Timestamp`. This eliminates `helpers.rs`'s `dt_to_str` / `str_to_dt` functions. Toasty handles jiff↔SQL conversion internally per dialect.

**Decision: yauth currently uses `chrono::NaiveDateTime` in domain types (`yauth-entity`).** The conversion layer (`user_to_domain`, etc.) will convert between `jiff::Timestamp` (toasty entity) and `chrono::NaiveDateTime` (domain) using `jiff`'s `From<chrono::NaiveDateTime>` interop. This keeps the change local to yauth-toasty; `yauth-entity` is unchanged. If jiff's chrono interop is insufficient, we'll use epoch-millis as the bridge (both libraries support this losslessly).

**JSON fields — use `#[serialize(json)]`:**

Fields currently stored as `String` with manual `serde_json::to_string` / `from_str` (e.g., `redirect_uris`, `grant_types`, `events`) should use `#[serialize(json)]` with their natural Rust types:

```rust
#[serialize(json)]
pub redirect_uris: Vec<String>,

#[serialize(json)]
pub grant_types: Vec<String>,

#[serialize(json)]
pub scopes: Option<Vec<String>>,
```

This eliminates `json_to_str` / `str_to_json` helpers.

**Unique constraints:**

`#[unique]` is already used correctly on fields like `email`, `token_hash`, `client_id`. No change needed — just verifying existing usage is correct.

**Full entity relationship map:**

| Parent Entity | Child Entity | FK Field | Relationship |
|---|---|---|---|
| `YauthUser` | `YauthSession` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthPassword` | `user_id` (PK) | `has_one` ↔ `belongs_to` |
| `YauthUser` | `YauthPasskey` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthEmailVerification` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthPasswordReset` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthTotpSecret` | `user_id` (PK) | `has_one` ↔ `belongs_to` |
| `YauthUser` | `YauthBackupCode` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthOauthAccount` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthApiKey` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthRefreshToken` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthAccountLock` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthUnlockToken` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthConsent` | `user_id` | `has_many` ↔ `belongs_to` |
| `YauthUser` | `YauthAuditLog` | `user_id` | `has_many` ↔ `belongs_to` (nullable) |
| `YauthOauth2Client` | `YauthAuthorizationCode` | `client_id` (string FK) | `has_many` ↔ `belongs_to` |
| `YauthOauth2Client` | `YauthDeviceCode` | `client_id` (string FK) | `has_many` ↔ `belongs_to` |
| `YauthOauth2Client` | `YauthConsent` | `client_id` (string FK) | `has_many` ↔ `belongs_to` |
| `YauthWebhook` | `YauthWebhookDelivery` | `webhook_id` | `has_many` ↔ `belongs_to` |

### 2. Toasty-Native Migration System

**Current state:** `push_schema()` only — no migration chain, no production path.

**Target state:** toasty's snapshot-anchored migration chain (`toasty/migrations/`, `toasty/snapshots/`, `toasty/history.toml`), generated by `toasty-cli` from the model types.

#### 2a. Toasty.toml

Add `Toasty.toml` at the `crates/yauth-toasty/` crate root:

```toml
[migration]
path = "toasty"
statement_breakpoints = true
prefix_style = "Sequential"
```

This matches toasty's defaults. `statement_breakpoints = true` adds `-- #[toasty::breakpoint]` comments so the migration applier can split multi-statement migrations.

#### 2b. Development CLI Binary

Because toasty-cli needs access to model types (via `toasty::models!(crate::*)`), create a thin dev binary at `crates/yauth-toasty/src/bin/toasty-dev.rs`:

```rust
//! Dev-only CLI for generating toasty migrations from yauth-toasty models.
//!
//! Usage:
//!   cargo run --bin toasty-dev -- migration generate --name add_passkey_fields
//!   cargo run --bin toasty-dev -- migration apply

use toasty_cli::{Config, ToastyCli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load()?;
    // Build Db with all yauth models — no connection needed for `migration generate`
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .models(toasty::models!(yauth_toasty::*))
        .build()?;
    let cli = ToastyCli::with_config(db, config);
    cli.parse_and_run().await?;
    Ok(())
}
```

Developers run `cargo run --bin toasty-dev -- migration generate --name foo` when models change. The resulting files (`toasty/migrations/NNNN_foo.sql`, `toasty/snapshots/NNNN_snapshot.toml`, `toasty/history.toml`) are committed to the crate.

#### 2c. Embedded Migrations for Consumers

yauth is a library — consumers should not need to install or run a CLI. Ship embedded migrations:

```rust
// crates/yauth-toasty/src/migrations.rs

use include_dir::{include_dir, Dir};

/// Embedded migration files from the committed toasty/ directory.
static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/toasty");

/// Apply all pending yauth-toasty migrations.
///
/// Call this once at startup:
/// ```rust
/// yauth_toasty::apply_migrations(&db).await?;
/// ```
pub async fn apply_migrations(db: &toasty::Db) -> Result<(), yauth::repo::RepoError> {
    db.apply_migrations_from(MIGRATIONS_DIR.as_ref())
        .await
        .map_err(|e| yauth::repo::RepoError::Internal(
            format!("migration error: {e}").into()
        ))
}
```

If toasty doesn't expose an `apply_migrations_from` that accepts an embedded directory, the implementation will iterate migration SQL files from the embedded dir, check the `__toasty_migrations` tracking table, and execute pending ones in order inside a transaction. This is a straightforward ~50-line function.

**Consumer wiring is minimal** (~3 lines):

```rust
let backend = ToastyPgBackend::new("postgres://...").await?;
yauth_toasty::apply_migrations(backend.db()).await?; // one call
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

#### 2d. Remove Hand-Rolled SQL Dirs

The current `pg/`, `mysql/`, `sqlite/` modules contain nearly identical `Db::builder()` setup differing only in driver URL. After this change:

- `pg/mod.rs`, `mysql/mod.rs`, `sqlite/mod.rs` remain as thin backend structs (they construct `Db` with the right driver URL and implement `DatabaseBackend`), but they no longer contain any SQL or schema-creation logic.
- There are no separate `pg/schema.sql`, `mysql/schema.sql`, `sqlite/schema.sql` files. Toasty emits driver-specific SQL at migration generation time from one set of model definitions.
- `create_tables()` on each backend remains for test convenience (delegates to `push_schema()`), clearly documented as test-only.

### 3. Idiomatic Query Patterns

Replace any raw SQL or query-builder-of-our-own patterns with toasty's generated methods and `create!` macro. The current code already largely does this — the changes are refinements.

**Patterns to use:**

| Operation | Toasty idiom |
|---|---|
| Get by PK | `User::get_by_id(&mut db, &id).await?` |
| Get by unique field | `User::get_by_email(&mut db, &email).await?` or `User::filter_by_email(&email).get(&mut db).await?` |
| Filter by indexed field | `Session::filter_by_user_id(user_id).exec(&mut db).await?` |
| Create | `toasty::create!(User { ... }).exec(&mut db).await?` |
| Update | `user.update().email("new@example.com").exec(&mut db).await?` |
| Delete | `user.delete().exec(&mut db).await?` or `User::delete_by_id(&mut db, id).await?` |
| Batch delete by FK | `Session::filter_by_user_id(user_id).delete().exec(&mut db).await?` |
| Eager load | `User::filter_by_id(id).include(User::fields().sessions()).get(&mut db).await?` |
| Pagination | `.limit(n).offset(o)` or cursor-based `.paginate(n)` |

**Known gaps in toasty (call out, don't paper over):**

- **ILIKE / case-insensitive search:** toasty doesn't support `ILIKE`. The `list()` method with search currently filters in application code. This remains acceptable for admin-panel use cases. Document as a known limitation.
- **Upsert / ON CONFLICT:** toasty doesn't support upsert. The current delete+insert-in-transaction pattern (used by `PasswordRepository::upsert`) stays. Document as a gap to revisit when toasty adds upsert support.
- **Complex filter expressions:** If any repository method can't be expressed with toasty's filter API, call it out explicitly in the code with a `// GAP:` comment rather than dropping to raw SQL silently.

**Remove `tokio-postgres` optional dependency.** No code uses it; any remaining gaps use toasty's API or application-layer workarounds.

### 4. Feature-Gated Models and the Migration Snapshot

**Decision: All models are always present in the schema (simpler, safer).**

Rationale:
- Toasty's migration snapshot is computed from `toasty::models!(crate::*)`, which sees all models compiled into the binary. If feature flags exclude models from compilation, they're excluded from the snapshot, meaning different feature combinations produce different migration chains — an unsound composition.
- A feature-off build must not leave orphaned tables or require a migration to drop them.
- Empty tables have negligible cost. The diesel/sqlx backends already create all `yauth_` tables regardless of which plugins are enabled.

**Implementation:**
- Entity structs are **always compiled** (remove `#[cfg(feature = "...")]` gates from entity module declarations in `entities/mod.rs`).
- Repository trait implementations remain feature-gated (they depend on yauth's feature-gated repository traits).
- The `build_repositories()` function continues to wire up only the repositories matching enabled features.
- The `toasty-dev` CLI binary is compiled with `--features full` so the snapshot always includes all models.
- `Toasty.toml` documents this: "All yauth tables are always created. Unused plugin tables remain empty."

This is the same approach as the memory backend (which creates all data structures regardless of features) and aligns with how most auth libraries work (e.g., NextAuth always creates all tables).

### 5. Workspace Inclusion

**Move yauth-toasty into the root workspace.**

Currently excluded because toasty's SQLite driver uses a different `libsqlite3-sys` version than sqlx, causing a Cargo `links` conflict.

**Fix:** Add yauth-toasty as a workspace member conditionally:

```toml
# Cargo.toml (root workspace)
[workspace]
members = [
    "crates/yauth",
    "crates/yauth-migration",
    "crates/yauth-entity",
    "crates/cargo-yauth",
    "crates/yauth-toasty",
]
resolver = "2"
```

The `links` conflict only triggers when both `sqlx-sqlite-backend` (which pulls `libsqlite3-sys` via sqlx) and `yauth-toasty/sqlite` (which pulls a different `libsqlite3-sys` via toasty-driver-sqlite) are compiled together. Since:

1. `yauth-toasty` doesn't depend on `yauth` with any backend features enabled (it uses `default-features = false`).
2. No feature in the workspace simultaneously enables `sqlx-sqlite-backend` and `yauth-toasty/sqlite`.
3. The `all-backends` feature (CI-only) can exclude `yauth-toasty/sqlite` just as it already excludes `diesel-libsql-backend` for the same reason.

If the conflict persists despite these guards (e.g., Cargo feature unification across workspace members), the fallback is:

- Keep yauth-toasty excluded from the default workspace.
- Add a CI job that runs `cargo test --manifest-path crates/yauth-toasty/Cargo.toml --features full,sqlite` and `cargo clippy --manifest-path crates/yauth-toasty/Cargo.toml --features full,postgresql,mysql,sqlite -- -D warnings` separately.
- Document the `links` conflict reason explicitly in `Cargo.toml` and in this PRD.

Either way, `cargo clippy` and `cargo test` must cover yauth-toasty in CI. The workspace-member approach is preferred; the separate-CI-job approach is the fallback.

### 6. Experimental Labeling

**`publish = false` stays** until all of the following acceptance criteria are met:

1. A scaffold app can adopt yauth-toasty with ≤30 lines of wiring, including the `apply_migrations` call.
2. The full conformance test suite (65+ tests) passes on at least PostgreSQL and SQLite backends.
3. The embedded migration system works end-to-end: model change → `toasty-dev migration generate` → commit → consumer calls `apply_migrations()` → schema updated.
4. A manual smoke test against a real app (e.g., a minimal Axum app with email-password + passkey) confirms the backend works outside the test harness.
5. toasty itself reaches a stable-enough state that API churn doesn't break yauth-toasty on every update.

Do not drop `publish = false` just because the UX is nicer. The flag is a signal to consumers that this backend is not yet production-ready.

## Technical Decisions

| Decision | Rationale |
|---|---|
| All models always compiled (no `#[cfg]` on entities) | Feature-gated models produce different migration snapshots per feature combination — unsound. Empty tables are cheap. |
| `jiff::Timestamp` for all datetime fields | Toasty's canonical time integration. Eliminates manual string↔datetime conversion. |
| `#[serialize(json)]` for JSON fields | Toasty's native JSON serialization. Eliminates manual `serde_json` helpers. |
| Relationships via `#[belongs_to]` / `#[has_many]` | Enables cascade deletes, eager loading, association queries — core toasty features. |
| `#[key]` without `#[auto]` for UUIDs | yauth generates UUIDv7 client-side in the domain layer. Toasty's `#[auto]` default is also v7, but we keep ID generation in the domain. |
| Embedded migrations via `include_dir!` | Library consumers shouldn't need a CLI. One function call at startup. |
| Dev CLI at `src/bin/toasty-dev.rs` | toasty-cli needs model types. Thin binary, not shipped to consumers. |
| `push_schema()` only for tests | Fast, no migration tracking overhead. Production uses `apply_migrations()`. |
| Remove `tokio-postgres` optional dep | Unused. Gaps handled by toasty API or application-layer workarounds, not raw SQL. |
| Prefer workspace member over separate CI job | Catches regressions early. Fallback to separate CI job if `links` conflict is unavoidable. |

## Milestones

### Milestone 1: Entity Rewrite + Relationship Graph

Rewrite all 27 entity structs to use toasty relationships, `jiff::Timestamp`, and `#[serialize(json)]`.

- Add `jiff` feature to `toasty` dependency.
- Add `include_dir` dependency.
- Replace all `String` timestamp fields with `jiff::Timestamp`.
- Replace all manual JSON `String` fields with `#[serialize(json)]` + real types.
- Add `#[belongs_to]` fields on every child entity.
- Add `#[has_many]` / `#[has_one]` fields on parent entities (`YauthUser`, `YauthOauth2Client`, `YauthWebhook`).
- Remove `#[cfg(feature = "...")]` gates from entity module declarations in `entities/mod.rs` (always compile all models).
- Update `helpers.rs`: remove `dt_to_str` / `str_to_dt` / `json_to_str` / `str_to_json`. Keep `toasty_err` / `toasty_conflict` error mappers. Add `jiff_to_chrono` / `chrono_to_jiff` conversion helpers.
- Remove `tokio-postgres` optional dependency from `Cargo.toml`.
- All existing conformance tests must still compile and pass (with updated conversion code in repository impls).

### Milestone 2: Repository Impl Refresh

Update all 17 repository implementations to use idiomatic toasty query patterns and the new entity shapes.

- Update `user_to_domain` / `session_to_domain` / etc. conversion functions for `jiff::Timestamp` ↔ `chrono::NaiveDateTime`.
- Remove manual JSON serialization/deserialization in repository code.
- Leverage `belongs_to` / `has_many` for cascade deletes where applicable (e.g., `user.delete()` cascading to sessions, passkeys, etc.).
- Replace any remaining raw SQL with toasty query API calls, or document gaps with `// GAP:` comments.
- Keep feature gates on repository modules (they depend on feature-gated yauth traits).
- Conformance tests pass.

### Milestone 3: Migration System

Set up toasty's migration chain and embedded migration delivery.

- Add `Toasty.toml` at crate root.
- Create `src/bin/toasty-dev.rs` with toasty-cli integration.
- Add `toasty-cli` as a dev/build dependency.
- Run `toasty-dev migration generate --name initial` with `--features full` to produce the initial migration.
- Commit `toasty/history.toml`, `toasty/migrations/0000_initial.sql`, `toasty/snapshots/0000_snapshot.toml`.
- Implement `apply_migrations()` in `src/migrations.rs` using `include_dir!`.
- Add `pub mod migrations;` to `lib.rs`.
- Update backend `create_tables()` doc comments to clarify test-only usage vs `apply_migrations()` for production.
- Integration test: create a fresh database, call `apply_migrations()`, then run conformance tests against it.

### Milestone 4: Workspace Integration + CI

Bring yauth-toasty under the root workspace and ensure CI coverage.

- Attempt workspace inclusion: remove `exclude = ["crates/yauth-toasty"]`, add to `members`.
- If `links` conflict: add separate CI job in `.github/workflows/` for yauth-toasty (clippy + test with `full,sqlite` and `full,postgresql` features).
- Ensure `cargo clippy --features full,postgresql,mysql,sqlite -- -D warnings` passes for yauth-toasty.
- Ensure `cargo test --features full,sqlite --test conformance` passes.
- Document the workspace decision in `CLAUDE.md` (workspace member or separate CI, and why).

## Out of Scope

- Switching any app (freshstrings, vault, etc.) to the toasty backend.
- Changing yauth's primary diesel backends.
- Versioning — crate versions are auto-managed by knope from conventional commits.
- DynamoDB support (yauth's schema is relational).
- Changing `yauth-entity` domain types (they stay `chrono::NaiveDateTime`).

## Success Metrics

| Metric | Target |
|---|---|
| Entity idiomatic-ness | Every entity struct uses `#[belongs_to]` / `#[has_many]` for FKs, `jiff::Timestamp` for datetimes, `#[serialize(json)]` for JSON fields |
| Conformance test pass rate | 100% of existing 65+ tests pass on all toasty backends |
| Consumer wiring simplicity | A scaffold app adopts yauth-toasty with ≤30 lines including `apply_migrations()` call |
| Zero raw SQL in yauth-toasty | No `tokio-postgres`, no hand-written SQL strings. Gaps documented with `// GAP:` comments |
| Migration round-trip | Model change → `toasty-dev migration generate` → commit → `apply_migrations()` → schema updated — works end-to-end |
| CI coverage | `cargo clippy` and `cargo test` cover yauth-toasty (either as workspace member or separate CI job) |

## Non-Goals

- yauth-toasty is not intended to replace the diesel/sqlx backends. It is an alternative for developers who prefer toasty's code-first approach.
- This PRD does not address publishing to crates.io. `publish = false` remains until acceptance criteria are met.
- No new repository trait methods are added. The existing yauth repository trait surface is unchanged.
