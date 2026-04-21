# Dependencies

## Existing (unchanged)

- **toasty** `0.3.0` — Toasty ORM. Already a dependency of `yauth-toasty`. https://crates.io/crates/toasty
- **yauth** (path dep) — yauth core. `default-features = false`. Provides `DatabaseBackend`, repository traits, `RepoError`, domain types.
- **yauth-entity** (path dep) — Domain types (`User`, `Session`, `Password`, etc.). Uses `chrono::NaiveDateTime`.
- **uuid** `1.x` — UUID generation/parsing. Already in workspace.
- **chrono** `0.4.x` — Datetime types. Already in workspace, used by `yauth-entity`.
- **serde_json** `1.x` — JSON serialization. Already in workspace.
- **tokio** `1.x` (features: `full`) — Async runtime. Already in workspace.
- **log** `0.4.x` — Logging facade. Already in workspace.

## To Add

- **jiff** `0.2.x` (latest: 0.2) — Toasty's canonical datetime library. Required to replace `String`-encoded timestamps with `jiff::Timestamp` in entity definitions. Toasty's `jiff` feature enables native jiff↔SQL column mapping, eliminating manual string conversion. https://crates.io/crates/jiff
  - Version justification: `0.2` matches the version Toasty 0.3.0 depends on internally. Using the same version avoids version splits.
  - Also enable the `jiff` feature on the `toasty` dependency: `toasty = { version = "0.3", features = ["jiff"] }`.
  - Add `jiff = { version = "0.2", features = ["serde"] }` to the `yauth-toasty` Cargo.toml for direct use in conversion code.

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
