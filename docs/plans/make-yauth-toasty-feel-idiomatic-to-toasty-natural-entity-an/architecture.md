# Architecture

## Overview

All changes are scoped to the `crates/yauth-toasty/` crate. The crate remains a separate workspace member (or excluded with its own CI — see Workspace Integration below) because Toasty's SQLite driver conflicts with sqlx's `libsqlite3-sys` via Cargo's `links` check.

The crate's internal structure stays the same:

```
crates/yauth-toasty/
  Cargo.toml
  src/
    lib.rs              # pub mod entities, pub(crate) mod helpers, pub(crate) mod common, per-dialect backends
    entities/
      mod.rs            # ALL models always compiled (no #[cfg] gates)
      users.rs          # YauthUser with #[has_many] relationships
      sessions.rs       # YauthSession with #[belongs_to(User)]
      ...               # 25 more entity files
    helpers.rs          # jiff↔chrono conversion + error mapping (slimmed down)
    common/
      mod.rs            # build_repositories() + shared repo impls
      user_repo.rs      # ToastyUserRepo using idiomatic Toasty queries
      ...               # 16 more repo files (feature-gated)
    pg/mod.rs           # ToastyPgBackend
    mysql/mod.rs        # ToastyMysqlBackend
    sqlite/mod.rs       # ToastySqliteBackend
  tests/
    conformance.rs      # 65+ cross-backend conformance tests
```

## Data Model

### Entity Layer (Toasty models)

Entities live in `src/entities/` and use Toasty's derive macros. They are the Toasty-native representation of yauth's database tables.

**Key design decisions:**

1. **Always compiled.** Entity structs are NOT `#[cfg(feature = "...")]`-gated. All 27 models are compiled regardless of which plugin features are enabled. This ensures `toasty::models!(crate::*)` produces a consistent model set, which is critical for Toasty's migration snapshot system.

2. **`YauthUser` naming retained.** The PRD considered renaming `YauthUser` → `User` etc., but the `Yauth` prefix avoids collision when consumers use `toasty::models!(crate::*, yauth_toasty::*)` in their own `Db::builder()` — their app likely has its own `User` model. The `#[table = "users"]` attribute plus `table_name_prefix("yauth_")` handles the database-side naming.

3. **Relationships.** Every FK gets both a concrete column field and a virtual relationship field:

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
       pub expires_at: jiff::Timestamp,
       pub created_at: jiff::Timestamp,
       // ...
   }
   ```

   Parent entities declare the inverse:

   ```rust
   #[derive(Debug, toasty::Model)]
   #[table = "users"]
   pub struct YauthUser {
       // ... scalar fields ...

       #[has_many]
       pub sessions: toasty::HasMany<YauthSession>,
       #[has_one]
       pub password: toasty::HasOne<YauthPassword>,
       // ... other relationships
   }
   ```

4. **`jiff::Timestamp` for all datetime fields.** Toasty's `jiff` feature handles the SQL encoding per dialect (TIMESTAMPTZ on PG, DATETIME on MySQL, TEXT on SQLite). The `helpers.rs` conversion layer bridges between `jiff::Timestamp` (entity) and `chrono::NaiveDateTime` (domain) using epoch-millis or jiff's chrono interop.

5. **`#[serialize(json)]` for JSON fields.** Fields like `redirect_uris`, `grant_types`, `scopes`, `events` use their natural Rust types (`Vec<String>`, `Option<Vec<String>>`, etc.) with Toasty's JSON serialization attribute.

### Relationship Map

| Parent | Child | FK | Type | Notes |
|--------|-------|-----|------|-------|
| `YauthUser` | `YauthSession` | `user_id` | `has_many` ↔ `belongs_to` | Cascade delete |
| `YauthUser` | `YauthPassword` | `user_id` (PK) | `has_one` ↔ `belongs_to` | 1:1, FK is PK |
| `YauthUser` | `YauthPasskey` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthEmailVerification` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthPasswordReset` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthTotpSecret` | `user_id` | `has_one` ↔ `belongs_to` | 1:1 per user |
| `YauthUser` | `YauthBackupCode` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthOauthAccount` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthApiKey` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthRefreshToken` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthAccountLock` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthUnlockToken` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthConsent` | `user_id` | `has_many` ↔ `belongs_to` | |
| `YauthUser` | `YauthAuditLog` | `user_id` | `has_many` ↔ `belongs_to` | Nullable FK |
| `YauthOauth2Client` | `YauthAuthorizationCode` | `client_id` | `has_many` ↔ `belongs_to` | String FK |
| `YauthOauth2Client` | `YauthDeviceCode` | `client_id` | `has_many` ↔ `belongs_to` | String FK |
| `YauthOauth2Client` | `YauthConsent` | `client_id` | `has_many` ↔ `belongs_to` | String FK |
| `YauthWebhook` | `YauthWebhookDelivery` | `webhook_id` | `has_many` ↔ `belongs_to` | |

### Domain Layer (unchanged)

`yauth-entity` types (`domain::User`, `domain::Session`, etc.) use `chrono::NaiveDateTime` and `serde_json::Value`. These are **not changed** — the conversion layer in `helpers.rs` and the `*_to_domain()` functions bridge between the two representations.

## Contracts

### DatabaseBackend Trait (unchanged)

```rust
pub trait DatabaseBackend: Send + Sync {
    fn repositories(&self) -> Repositories;
}
```

Each per-dialect backend (`ToastyPgBackend`, `ToastyMysqlBackend`, `ToastySqliteBackend`) implements this trait by delegating to `common::build_repositories(&self.db)`. This contract is **not changed** — the refactoring is internal to yauth-toasty.

### Repository Traits (unchanged)

All repository traits (`UserRepository`, `SessionRepository`, `PasswordRepository`, etc.) remain exactly as defined in `yauth::repo::*`. The trait signatures, return types, and behavioral contracts are unchanged. Only the internal implementation behind the trait changes.

### Conversion Contract

Every Toasty entity has a `fn into_domain(self) -> domain::T` conversion and every domain input type has a `fn from_domain(input) -> Self` conversion. These live alongside the repository implementations in `common/*_repo.rs`.

The conversion layer is the **only place** where `jiff::Timestamp` ↔ `chrono::NaiveDateTime` bridging occurs. No jiff types leak into the public API.

## Patterns

### Query Patterns (idiomatic Toasty)

| Operation | Before (anti-pattern) | After (idiomatic) |
|-----------|----------------------|-------------------|
| Get by PK | `YauthUser::get_by_id(&mut db, &id).await` | Same (already correct) |
| Get by unique field | `YauthUser::filter_by_email(&email).get(&mut db).await` | `YauthUser::get_by_email(&mut db, &email).await` |
| Filter by indexed field | Manual iteration | `YauthSession::filter_by_user_id(user_id).exec(&mut db).await` |
| Create | `toasty::create!(YauthUser { ... }).exec(&mut db).await` | Same (already correct) |
| Update | Fetch → `user.update().field(val).exec()` → re-fetch | Same pattern, but with `jiff::Timestamp` fields |
| Delete | Manual per-table deletion | `user.delete().exec(&mut db).await` (cascading via relationships) |
| Paginate | Fetch all → `.skip(offset).take(limit)` in memory | `Model::all().limit(limit).offset(offset).exec(&mut db).await` |
| Search (ILIKE) | Fetch all → filter in Rust | Same — Toasty lacks ILIKE. Documented as known limitation. |

### Error Mapping Pattern

```rust
// toasty::Error → RepoError
fn toasty_err(e: toasty::Error) -> RepoError {
    RepoError::Internal(format!("{e}").into())
}

fn toasty_conflict(e: toasty::Error) -> RepoError {
    let msg = format!("{e}");
    if msg.contains("duplicate key") || msg.contains("unique constraint")
        || msg.contains("UNIQUE constraint failed") || msg.contains("Duplicate entry")
    {
        return RepoError::Conflict(msg);
    }
    RepoError::Internal(msg.into())
}
```

These stay in `helpers.rs` (unchanged).

### Timestamp Conversion Pattern

```rust
// helpers.rs — replaces dt_to_str/str_to_dt

use jiff::Timestamp as JiffTimestamp;
use chrono::NaiveDateTime;

/// Convert jiff::Timestamp to chrono::NaiveDateTime for domain types.
pub(crate) fn jiff_to_chrono(ts: JiffTimestamp) -> NaiveDateTime {
    let epoch_secs = ts.as_second();
    let nanos = ts.subsec_nanosecond();
    NaiveDateTime::from_timestamp_opt(epoch_secs, nanos as u32)
        .unwrap_or(NaiveDateTime::MIN)
}

/// Convert chrono::NaiveDateTime to jiff::Timestamp for Toasty entities.
pub(crate) fn chrono_to_jiff(dt: NaiveDateTime) -> JiffTimestamp {
    let epoch_secs = dt.and_utc().timestamp();
    let nanos = dt.and_utc().timestamp_subsec_nanos();
    JiffTimestamp::from_second(epoch_secs)
        .expect("valid timestamp")
        .with_subsec_nanosecond(nanos as i32)
        .expect("valid nanos")
}

// Option wrappers
pub(crate) fn opt_jiff_to_chrono(ts: Option<JiffTimestamp>) -> Option<NaiveDateTime> { ... }
pub(crate) fn opt_chrono_to_jiff(dt: Option<NaiveDateTime>) -> Option<JiffTimestamp> { ... }
```

If jiff provides direct `From<NaiveDateTime>` / `Into<NaiveDateTime>` interop, use that instead of manual epoch conversion.

### Db Handle Pattern

Each repo holds a cloned `Db` handle:

```rust
pub(crate) struct ToastyUserRepo {
    db: Db,
}
```

Toasty's `Db` is `Clone` and internally reference-counted. Cloning is cheap. Each method clones to get a `&mut db`:

```rust
fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
    Box::pin(async move {
        let mut db = self.db.clone();
        // ... use &mut db ...
    })
}
```

This pattern is **unchanged** from the current implementation and is the correct way to use Toasty from behind an `Arc<dyn Trait>` interface.

## Invariants

1. **Entity compilation is unconditional.** All 27 entity structs compile regardless of feature flags. Only repository trait implementations are `#[cfg]`-gated.

2. **No jiff types in public API.** The `DatabaseBackend` trait, `Repositories` struct, and repository trait methods use `chrono::NaiveDateTime` and `serde_json::Value` (via `yauth-entity`). jiff is an internal implementation detail of yauth-toasty.

3. **Conformance test parity.** Every change must keep the existing 65+ conformance tests passing. The conformance suite is the canonical correctness check.

4. **No behavioral changes.** Case-insensitive email lookup, expiration-on-read, cascade delete, fail-open rate limiting, timing-safe patterns — all behavioral contracts documented in yauth's conformance test suite are preserved.

5. **`push_schema()` for tests, migrations for production.** Test setup continues to use `backend.create_tables()` → `db.push_schema()`. Production schema setup will use the migration system (M2 scope).

6. **Toasty table prefix.** All backends configure `Db::builder().table_name_prefix("yauth_")`. Entity `#[table = "users"]` maps to `yauth_users` at runtime. This is unchanged.

## Workspace Integration Decision

The `yauth-toasty` crate is currently excluded from the root workspace (`Cargo.toml: exclude = ["crates/yauth-toasty"]`) due to `libsqlite3-sys` version conflicts between Toasty's SQLite driver and sqlx.

**Preferred approach:** Add `yauth-toasty` as a workspace member. The `links` conflict only triggers when both `sqlx-sqlite-backend` and `yauth-toasty/sqlite` are compiled together. Since no feature combination enables both simultaneously, this should work.

**Fallback approach:** Keep excluded, add a separate CI job that runs `cargo test --manifest-path crates/yauth-toasty/Cargo.toml --features full,sqlite` and clippy separately.

This decision is deferred to M3 (Workspace Integration + CI) to avoid blocking M1.

## Files Changed (M1 Scope)

| File | Change |
|------|--------|
| `crates/yauth-toasty/Cargo.toml` | Add `jiff` dep, enable `toasty/jiff` feature, remove `tokio-postgres` optional dep |
| `crates/yauth-toasty/src/entities/mod.rs` | Remove all `#[cfg(feature = "...")]` gates on entity modules |
| `crates/yauth-toasty/src/entities/*.rs` (27 files) | Add `#[belongs_to]`/`#[has_many]`/`#[has_one]`, replace `String` datetimes with `jiff::Timestamp`, replace `String` JSON with `#[serialize(json)]` + real types |
| `crates/yauth-toasty/src/helpers.rs` | Remove `dt_to_str`/`str_to_dt`/`json_to_str`/`str_to_json`, add `jiff_to_chrono`/`chrono_to_jiff` |
| `crates/yauth-toasty/src/common/*_repo.rs` (17 files) | Update `*_to_domain()` conversions for jiff↔chrono, update JSON handling, use Toasty's generated accessors where applicable, use `.limit()/.offset()` for pagination |
| `crates/yauth-toasty/tests/conformance.rs` | Minimal changes — ensure tests still pass with updated entity types |
