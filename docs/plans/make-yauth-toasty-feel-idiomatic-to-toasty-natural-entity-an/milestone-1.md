# Milestone 1: Entity Rewrite + Relationship Graph + Repo Refresh

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone delivers the core idiomaticity improvement: rewriting all 27 Toasty entity structs to use relationships, native timestamps, and native JSON serialization, then updating all 17 repository implementations to use the new entity shapes and idiomatic Toasty query patterns.

After this milestone, a Toasty developer opening `crates/yauth-toasty/` sees code that uses Toasty's relationship system, `jiff::Timestamp` for time, `#[serialize(json)]` for structured data, and Toasty's generated query accessors — not diesel patterns wearing a Toasty hat.

---

## What must work

### Part A: Dependency Changes (`Cargo.toml`)

1. Add `jiff` dependency: `jiff = { version = "0.2", features = ["serde"] }`
2. Enable the `jiff` feature on `toasty`: change `toasty = { version = "0.3" }` to `toasty = { version = "0.3", features = ["jiff"] }`
3. Remove `tokio-postgres` from `[dependencies]` (it's unused — no code references it)
4. All existing feature flags remain unchanged

### Part B: Entity Rewrites (`src/entities/`)

5. **Remove `#[cfg]` gates from `entities/mod.rs`.** Every `mod foo;` and `pub use foo::*;` line in `entities/mod.rs` must be unconditional — no `#[cfg(feature = "...")]`. All 27 entity modules are always compiled.

6. **Add relationships to all entity structs.** Every foreign key field gains a `#[belongs_to]` virtual field. Every parent entity gains `#[has_many]` or `#[has_one]` virtual fields. See the relationship map in `architecture.md` for the full list.

   Example — `users.rs`:
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
       #[has_one]
       pub password: toasty::HasOne<YauthPassword>,
       #[has_many]
       pub passkeys: toasty::HasMany<YauthPasskey>,
       #[has_many]
       pub email_verifications: toasty::HasMany<YauthEmailVerification>,
       #[has_many]
       pub password_resets: toasty::HasMany<YauthPasswordReset>,
       #[has_one]
       pub totp_secret: toasty::HasOne<YauthTotpSecret>,
       #[has_many]
       pub backup_codes: toasty::HasMany<YauthBackupCode>,
       #[has_many]
       pub oauth_accounts: toasty::HasMany<YauthOauthAccount>,
       #[has_many]
       pub api_keys: toasty::HasMany<YauthApiKey>,
       #[has_many]
       pub refresh_tokens: toasty::HasMany<YauthRefreshToken>,
       #[has_many]
       pub account_locks: toasty::HasMany<YauthAccountLock>,
       #[has_many]
       pub unlock_tokens: toasty::HasMany<YauthUnlockToken>,
       #[has_many]
       pub consents: toasty::HasMany<YauthConsent>,
       #[has_many]
       pub audit_logs: toasty::HasMany<YauthAuditLog>,
   }
   ```

   Example — `sessions.rs`:
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

7. **Replace all `String`-encoded datetimes with `jiff::Timestamp`.** Every field currently typed `String` that stores a datetime (identified by the name pattern `*_at` and by `helpers.rs` `dt_to_str`/`str_to_dt` calls in the repo code) becomes `jiff::Timestamp` or `Option<jiff::Timestamp>`.

   Fields affected (complete list):
   - `YauthUser`: `banned_until`, `created_at`, `updated_at`
   - `YauthSession`: `expires_at`, `created_at`
   - `YauthAuditLog`: `created_at`
   - `YauthChallenge`: `expires_at`
   - `YauthRateLimit`: `window_start`
   - `YauthRevocation`: `expires_at`
   - `YauthEmailVerification`: `expires_at`, `created_at`
   - `YauthPasswordReset`: `expires_at`, `used_at`, `created_at`
   - `YauthPasskey`: `created_at`, `last_used_at`
   - `YauthTotpSecret`: `created_at`
   - `YauthBackupCode`: `created_at`
   - `YauthOauthAccount`: `expires_at`, `created_at`, `updated_at`
   - `YauthOauthState`: `expires_at`, `created_at`
   - `YauthApiKey`: `last_used_at`, `expires_at`, `created_at`
   - `YauthRefreshToken`: `expires_at`, `created_at`
   - `YauthMagicLink`: `expires_at`, `created_at`
   - `YauthOauth2Client`: `banned_at`, `created_at`
   - `YauthAuthorizationCode`: `expires_at`, `created_at`
   - `YauthConsent`: `created_at`, `updated_at`
   - `YauthDeviceCode`: `expires_at`, `last_polled_at`, `created_at`
   - `YauthAccountLock`: `locked_until`, `created_at`, `updated_at`
   - `YauthUnlockToken`: `expires_at`, `created_at`
   - `YauthWebhook`: `created_at`, `updated_at`
   - `YauthWebhookDelivery`: `created_at`

8. **Replace `String`-encoded JSON with `#[serialize(json)]` + natural types.** Fields currently storing JSON as `String` with manual `json_to_str`/`str_to_json` in repo code gain `#[serialize(json)]` and their natural Rust type.

   Fields affected:
   - `YauthOauth2Client`: `redirect_uris` → `Vec<String>`, `grant_types` → `Vec<String>`, `scopes` → `Option<serde_json::Value>`
   - `YauthAuthorizationCode`: `scopes` → `Option<serde_json::Value>`
   - `YauthConsent`: `scopes` → `Option<serde_json::Value>`
   - `YauthDeviceCode`: `scopes` → `Option<serde_json::Value>`
   - `YauthApiKey`: `scopes` → `Option<serde_json::Value>`
   - `YauthWebhook`: `events` → `Vec<String>`
   - `YauthWebhookDelivery`: `payload` → `serde_json::Value`
   - `YauthAuditLog`: `metadata` → `Option<serde_json::Value>`
   - `YauthPasskey`: `credential` → `serde_json::Value`

   Note: If `#[serialize(json)]` is not stable in Toasty 0.3 for these types, fall back to `String` with a `// GAP: awaiting Toasty #[serialize(json)] stability` comment. Verify by compiling.

### Part C: Helpers Update (`src/helpers.rs`)

9. **Remove old conversion functions:** `dt_to_str`, `str_to_dt`, `opt_dt_to_str`, `opt_str_to_dt`, `json_to_str`, `str_to_json`, `opt_json_to_str`, `opt_str_to_json`.

10. **Add jiff↔chrono conversion functions:** `jiff_to_chrono(jiff::Timestamp) -> NaiveDateTime`, `chrono_to_jiff(NaiveDateTime) -> jiff::Timestamp`, and their `Option` wrappers. If jiff provides `From<NaiveDateTime>` interop, use that. Otherwise, use epoch-second + subsec-nanosecond conversion (both libraries support this losslessly).

11. **Keep error mappers:** `toasty_err` and `toasty_conflict` remain unchanged.

### Part D: Repository Refresh (`src/common/*_repo.rs`)

12. **Update all `*_to_domain()` conversion functions.** Replace `str_to_dt(m.created_at)` with `jiff_to_chrono(m.created_at)`. Replace `str_to_json(&m.metadata)` with direct `m.metadata` (since it's already the right type). Apply this to all 27 entity → domain conversion functions.

13. **Update all domain → entity conversions in `create` methods.** Replace `dt_to_str(input.created_at)` with `chrono_to_jiff(input.created_at)`. Replace `json_to_str(&input.scopes)` with direct `input.scopes`. Apply this in all `toasty::create!(...)` macro invocations.

14. **Use Toasty's generated accessors for unique-field lookups.** Where Toasty generates `get_by_{field}()` for `#[unique]` fields, use it instead of manual filter queries. Example: `YauthUser::get_by_email(&mut db, &email)` instead of `YauthUser::filter_by_email(&email).get(&mut db)`. Apply where the generated accessor exists and is semantically equivalent.

15. **Use DB-level pagination.** Replace the pattern:
    ```rust
    let all: Vec<T> = T::all().exec(&mut db).await?;
    let total = all.len() as i64;
    let paged = all.into_iter().skip(offset).take(limit).collect();
    ```
    with:
    ```rust
    // Count separately if needed (or fetch all IDs for count)
    let total = T::all().count().exec(&mut db).await? as i64;
    let paged: Vec<T> = T::all()
        .limit(limit as usize)
        .offset(offset as usize)
        .exec(&mut db)
        .await?;
    ```
    If Toasty doesn't support `.count()`, keep the full-fetch pattern for total count but still use `.limit()/.offset()` for the result page. Document the gap.

16. **Use relationship-aware deletes where applicable.** For `UserRepository::delete()`, check if Toasty cascades deletes through `#[has_many]`/`#[has_one]` relationships automatically. If yes, simplify the delete implementation to just `user.delete().exec(&mut db).await`. If not, keep the explicit cascade delete but add a comment noting the desired behavior.

17. **Preserve all behavioral contracts.** These must not change:
    - Case-insensitive email lookup (lowercase before query)
    - Expiration-on-read (check `expires_at` after fetch, return `None` if expired)
    - `used_at` check on password resets (return `None` if already used)
    - Fail-open rate limiting (return `allowed: true` on error)
    - Upsert via delete+insert in transaction (until Toasty adds ON CONFLICT)

### Part E: Remove Unused Dependency

18. **Remove `tokio-postgres` from `Cargo.toml`.** It's listed as an optional dependency but no code imports or uses it. Grep for `tokio_postgres` and `tokio-postgres` to confirm zero usage.

---

## After building, prove it works

1. `cargo build -p yauth-toasty --features full,sqlite` — compiles with all features and SQLite backend. No errors.
2. `cargo build -p yauth-toasty --features full,postgresql` — compiles with PostgreSQL backend. No errors.
3. `cargo build -p yauth-toasty --features full,mysql` — compiles with MySQL backend. No errors.
4. `cargo build -p yauth-toasty --features sqlite` — compiles with minimal features (no plugins). All 27 entity modules still compile because they are not `#[cfg]`-gated.
5. `cargo clippy -p yauth-toasty --features full,sqlite -- -D warnings` — zero warnings.
6. `cargo fmt --check` — no formatting issues.
7. `cargo test -p yauth-toasty --features full,sqlite --test conformance` — all 65+ conformance tests pass for SQLite.
8. With `DATABASE_URL` set: `cargo test -p yauth-toasty --features full,postgresql --test conformance` — all tests pass for PostgreSQL.
9. With `MYSQL_DATABASE_URL` set: `cargo test -p yauth-toasty --features full,mysql --test conformance` — all tests pass for MySQL.
10. Grep for `dt_to_str\|str_to_dt\|json_to_str\|str_to_json` in `crates/yauth-toasty/src/` — zero matches (old helpers fully removed).
11. Grep for `tokio.postgres\|tokio_postgres` in `crates/yauth-toasty/` — zero matches.
12. Grep for `pub created_at: String` in `crates/yauth-toasty/src/entities/` — zero matches (all datetime fields use `jiff::Timestamp`).
13. Grep for `#\[cfg\(feature` in `crates/yauth-toasty/src/entities/mod.rs` — zero matches (no feature gates on entity modules).
14. Grep for `belongs_to` in `crates/yauth-toasty/src/entities/` — at least 17 matches (one per child entity with a FK).

---

## Test strategy

- The existing conformance test suite (`tests/conformance.rs`) is the primary validation. It tests every repository trait method across all three backends.
- No new tests are needed — the conformance suite already covers all behavioral contracts.
- If any test fails due to a conversion bug (e.g., jiff timestamp precision differs from chrono), fix the conversion in `helpers.rs` until the test passes.
- Run conformance tests with `--test-threads=1` for MySQL/PostgreSQL (shared database state). SQLite in-memory can run parallel.
- Verify compilation with minimal features (`--features sqlite` only) to confirm entities compile without plugin feature gates.

---

## Known pitfalls

1. **jiff::Timestamp precision vs chrono::NaiveDateTime.** jiff uses nanosecond precision; chrono uses up to nanosecond but some database drivers truncate to microsecond. The conversion must not introduce precision loss that fails conformance tests. Use epoch-seconds + subsec-nanoseconds as the bridge, not string formatting. If conformance tests assert exact datetime equality, verify the round-trip is lossless.

2. **Toasty's `#[has_many]`/`#[belongs_to]` may require specific attribute syntax.** Toasty 0.3's exact attribute format for relationships may differ from examples. Check `docs.rs/toasty/0.3.0` and the toasty repo's examples. The key parameters are `key` (FK column on the child) and `references` (PK column on the parent). If the syntax is different, adapt accordingly.

3. **`#[serialize(json)]` may not be stable in Toasty 0.3.** If the attribute doesn't work for certain types or isn't available, fall back to `String` storage with explicit serde calls. Mark each fallback with `// GAP: #[serialize(json)]` so it's easy to revisit.

4. **Forward references in entity modules.** Adding `#[has_many] pub sessions: HasMany<YauthSession>` to `YauthUser` requires `YauthSession` to be in scope. Since entities are in separate modules, ensure the `use` imports in each file resolve correctly. Toasty's proc macro may handle cross-module references via the model registry; verify by compiling.

5. **Circular relationship declarations.** `YauthUser` has `#[has_many] sessions` and `YauthSession` has `#[belongs_to] user`. This is a circular type reference. Toasty handles this through its model registry (the proc macro generates separate metadata structs, not direct type references). Verify this works by compiling — if it doesn't, declare relationships only on the child side (`#[belongs_to]` only) and omit `#[has_many]` from the parent.

6. **Entity module ordering in `mod.rs`.** With all modules unconditionally compiled and circular references, the module declaration order in `entities/mod.rs` matters for Toasty's macro expansion. Declare parent entities before children (users before sessions, etc.) to match the dependency order. If Toasty's proc macro doesn't care about declaration order, any order works.

7. **`Option<jiff::Timestamp>` column type.** Toasty must map `Option<jiff::Timestamp>` to a nullable datetime column. Verify this works for each dialect (PG: `TIMESTAMPTZ NULL`, MySQL: `DATETIME NULL`, SQLite: `TEXT NULL`). If Toasty can't handle nullable jiff timestamps, fall back to `Option<String>` for those specific fields.

8. **Cascade delete behavior.** Toasty may or may not cascade deletes through `#[has_many]` relationships automatically. If it doesn't, the explicit cascade delete code in `UserRepository::delete()` must remain. Check Toasty's docs or test empirically: create a user + session, delete the user, verify the session is also deleted.

9. **`YauthConsent` has TWO parent FKs.** `YauthConsent` belongs to both `YauthUser` (via `user_id`) and `YauthOauth2Client` (via `client_id`). Toasty should handle multiple `#[belongs_to]` on one model. Verify by compiling.

10. **The `toasty::models!(crate::*)` call in backend constructors.** With all entities unconditionally compiled, `toasty::models!(crate::*)` in each backend's `build_db()` / `all_models()` should pick up all 27 models. Verify the macro expands correctly after the changes.

11. **String FK fields on OAuth2 entities.** `YauthAuthorizationCode`, `YauthDeviceCode`, and `YauthConsent` use `client_id: String` as a FK to `YauthOauth2Client.client_id: String`. The `#[belongs_to]` attribute must reference the correct parent field (`references = client_id`), not the parent's PK (`id`). Verify Toasty supports non-PK FK references; if not, keep the FK as a bare `String` field without `#[belongs_to]`.
