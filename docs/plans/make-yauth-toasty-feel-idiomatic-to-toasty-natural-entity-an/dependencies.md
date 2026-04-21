# Dependencies

## Existing (unchanged)

- **toasty** `0.4.x` — Toasty ORM. Already a dependency of `yauth-toasty` (upgraded from 0.3 → 0.4 in M1). https://crates.io/crates/toasty
- **yauth** (path dep) — yauth core. `default-features = false`. Provides `DatabaseBackend`, repository traits, `RepoError`, domain types.
- **yauth-entity** (path dep) — Domain types (`User`, `Session`, `Password`, etc.). Uses `chrono::NaiveDateTime`.
- **uuid** `1.x` — UUID generation/parsing. Already in workspace.
- **chrono** `0.4.x` — Datetime types. Already in workspace, used by `yauth-entity`.
- **serde_json** `1.x` — JSON serialization. Already in workspace.
- **tokio** `1.x` (features: `full`) — Async runtime. Already in workspace.
- **log** `0.4.x` — Logging facade. Already in workspace.

## To Add

- **jiff** `0.2.x` (latest: 0.2) — Toasty's canonical datetime library. Required to replace `String`-encoded timestamps with `jiff::Timestamp` in entity definitions. Toasty's `jiff` feature enables native jiff↔SQL column mapping, eliminating manual string conversion. https://crates.io/crates/jiff
  - Version justification: `0.2` matches the version Toasty 0.4.x depends on internally. Using the same version avoids version splits.
  - Also enable the `jiff` feature on the `toasty` dependency: `toasty = { version = "0.4", features = ["jiff"] }`.
  - Add `jiff = { version = "0.2", features = ["serde"] }` to the `yauth-toasty` Cargo.toml for direct use in conversion code.

- **include_dir** `0.7.x` — Compile-time directory embedding. Used in M2 to embed the `toasty/` migration directory into the binary so library consumers get schema management from a single function call without needing migration files on disk at runtime. https://crates.io/crates/include_dir
  - Version justification: `0.7` is the latest stable release with proc-macro `include_dir!()` support.

- **toasty-cli** `0.4.x` (optional, dev-only) — Toasty's migration CLI library. Used by the `toasty-dev` binary (M2) to generate migration diffs from model types. NOT shipped to consumers — gated behind the `dev-cli` feature flag. https://crates.io/crates/toasty-cli
  - Version justification: must match the toasty version (0.4) for snapshot compatibility.

- **anyhow** `1.x` (optional, dev-only) — Error handling for the `toasty-dev` binary. Standard Rust error convenience crate. Already widely used in the ecosystem. Gated behind the `dev-cli` feature. https://crates.io/crates/anyhow

## To Remove

- **tokio-postgres** (optional) — Listed as an optional dependency "for complex queries Toasty can't express" but no code uses it. Toasty's query API covers the needed patterns. Removing it cleans up the dependency tree and signals that yauth-toasty is fully Toasty-native.

## Feature Flag Changes

No new feature flags are added or removed. The existing feature flags on `yauth-toasty` remain:

| Feature | Purpose |
|---------|---------|
| `postgresql` | PostgreSQL backend via `toasty-driver-postgresql` |
| `mysql` | MySQL backend via `toasty-driver-mysql` |
| `sqlite` | SQLite backend via `toasty-driver-sqlite` |
| `email-password` | Email/password plugin repos |
| `passkey` | WebAuthn plugin repos |
| `mfa` | TOTP + backup codes plugin repos |
| `oauth` | OAuth linking plugin repos |
| `bearer` | JWT refresh token plugin repos |
| `api-key` | API key plugin repos |
| `magic-link` | Magic link plugin repos |
| `admin` | Admin plugin repos |
| `oauth2-server` | OAuth2 server plugin repos |
| `account-lockout` | Account lockout plugin repos |
| `webhooks` | Webhook plugin repos |
| `full` | All of the above |

**Entity compilation change:** Entity structs are always compiled regardless of feature flags (the `#[cfg(feature = "...")]` gates are removed from `entities/mod.rs`). Only the repository implementations remain feature-gated. This ensures a consistent migration snapshot across all feature combinations.

## Environment Variables

No new environment variables required.

Existing test environment variables remain unchanged:
- `DATABASE_URL` — PostgreSQL connection string (for PG conformance tests)
- `MYSQL_DATABASE_URL` — MySQL connection string (for MySQL conformance tests)
- SQLite tests use in-memory databases and require no env var.

## Rust Toolchain

- Minimum: Rust 1.94 (Toasty's MSRV). The current toolchain is ≥1.94, so no upgrade needed.
