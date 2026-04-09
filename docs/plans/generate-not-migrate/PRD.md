# Generate, Don't Migrate

## Overview

Remove yauth's runtime migration system entirely. `cargo yauth generate` becomes the only CLI surface — it produces **only the artifacts each ORM natively consumes**: Diesel gets migration SQL, sqlx gets migration SQL + query files, SeaORM gets entity models, Toasty gets model files. Users run their own ORM tooling to apply migrations. yauth becomes pure auth logic that assumes tables exist.

This positions yauth as the defacto auth library for Rust. For pros, it feels like home — native Diesel migrations, native sqlx queries, native SeaORM entities. For beginners who know nothing about auth, it guides them: the CLI explains what it's doing, generated files are self-documenting, and every step points to the next one. We own complexity so users don't.

## Core Features

1. **ORM-native artifact generation**: `cargo yauth generate` dispatches per ORM and produces only what that ORM expects:
   - **Diesel**: `migrations/<timestamp>_yauth_init/up.sql` + `down.sql` — standard Diesel migration format. User runs `diesel migration run`.
   - **sqlx**: `migrations/<number>_yauth_init.sql` — standard sqlx migration format. User runs `sqlx migrate run`. Additionally generates typed `.sql` query files for use with `sqlx::query_file!()`.
   - **SeaORM**: Entity model files (`entities/yauth/*.rs`) — `Model`, `ActiveModel`, `Entity`, `Relation` structs. No migrations — user writes their own or uses `sea-orm-cli migrate generate`.
   - **Toasty**: Model files (`models/yauth/*.rs`) — `#[derive(toasty::Model)]` structs. No migrations — Toasty handles schema its own way.

2. **Backend accepts user's pool**: Backend constructors take an existing connection pool instead of a URL string. yauth never creates, configures, or manages the pool. Teams keep their existing pool configuration, connection limits, and middleware.

3. **No runtime migration**: The `DatabaseBackend` trait loses its `migrate()` method. Backends assume tables exist. If they don't, the ORM's own error surfaces (e.g., "relation yauth_users does not exist") — clear, familiar, not wrapped in yauth abstractions.

4. **yauth-migration becomes build-time only**: The migration crate's schema types (`TableDef`, `ColumnDef`, etc.), plugin schemas, dialect-specific DDL generators, and diff engine remain — but only as dependencies of `cargo-yauth`. The `yauth` library crate has zero dependency on `yauth-migration` at runtime.

5. **sqlx query file generation**: For sqlx users, generate `.sql` files covering every yauth repository operation (find user by email, create session, validate session, etc.) that users can use with `sqlx::query_file!()` in their own projects — a significant DX win that no other auth library offers.

6. **Incremental generation**: `cargo yauth add-plugin mfa` still works — it generates only the incremental migration (new tables) for Diesel/sqlx, or adds new entity/model files for SeaORM/Toasty. `cargo yauth remove-plugin` generates the teardown.

7. **Guided CLI output**: `cargo yauth init` and `cargo yauth generate` print clear next-step instructions after running — what files were created, what command to run next, and why. A beginner who has never used Diesel should be able to follow the CLI output alone to get auth working.

8. **Self-documenting generated files**: Every generated SQL migration, query file, entity, and model includes comments explaining what the table/query does in auth terms (e.g., "-- Sessions table: tracks active login sessions. Each row is one browser/device."). Pros skip the comments. Beginners learn from them.

9. **Guided skill onboarding**: When the yauth skill triggers in a project with no yauth setup (no `yauth` in Cargo.toml, no `yauth.toml`), it offers three paths: (a) guided walkthrough — uses AskUserQuestion to recommend ORM, dialect, plugins based on what's already in the project, (b) describe — user says what they want and the skill configures it, (c) defaults — sensible defaults applied immediately. The walkthrough asks short, direct questions ("Your project uses diesel — use diesel-pg-backend?" not "Would you like me to help you choose a backend?").

10. **Wiring documentation**: Each ORM gets a concrete guide showing the full path from `cargo yauth init` to a working Axum app. The guide covers: generate artifacts, apply with ORM tooling, construct pool, pass pool to backend, build yauth, merge router.

## Technical Decisions

- **Backends accept pools, not URLs**: `DieselPgBackend::from_pool(pool)` instead of `DieselPgBackend::new("postgres://...")`. This is critical for adoption — teams already have pool configuration and yauth shouldn't fight it.
- **No tracking table**: yauth currently maintains a `yauth_schema_migrations` table with schema hashes. This goes away. The ORM's own migration tracking (diesel's `__diesel_schema_migrations`, sqlx's `_sqlx_migrations`) is sufficient.
- **`generate --check` stays**: CI can still verify generated artifacts are fresh. This is a build-time check, not a runtime one.
- **Schema-first ORMs get migrations**: Diesel and sqlx are schema-first — SQL is the source of truth, so yauth generates SQL.
- **Code-first ORMs get models only**: SeaORM and Toasty are code-first — code is the source of truth, so yauth generates Rust model files. Migration is the user's responsibility.
- **sqlx query files are the differentiator**: No other Rust auth library generates compile-time-checked query files. This makes yauth + sqlx feel native rather than bolted on.
- **Memory backend unchanged**: `InMemoryBackend` has no migration story and doesn't need one. It continues to work as-is for tests and prototyping.
- **Tone: clear, never condescending**: All user-facing text (CLI output, generated file comments, docs, error messages) is factual and direct. State what something is and what to do next. No hedging ("you might want to"), no lecturing ("as you probably know"), no filler. A beginner gets clarity. A pro gets brevity. Same words serve both.

## Milestones

### Milestone 1: Remove migrate() and accept pools
Strip `migrate()` from `DatabaseBackend`. Change all backend constructors to accept pools via `from_pool()`. Update all integration tests to set up schema via ORM-native tooling (raw SQL or ORM CLI) before constructing backends. This is the breaking change — ship it clean.

### Milestone 2: Decouple yauth-migration from yauth runtime
Remove `yauth-migration` from `yauth`'s `Cargo.toml` dependencies. Remove the `yauth::schema` module entirely. Delete the `diesel_migrations/` directory. Ensure `cargo-yauth` is the sole consumer of `yauth-migration`. The `yauth` crate should compile with zero knowledge of schema definitions.

### Milestone 3: sqlx query file generation
Add query file generation to `cargo yauth generate --orm sqlx`. Generate `.sql` files for every repository operation that users can use with `query_file!()` in their own projects. This is the headline feature for sqlx users.

### Milestone 4: Docs, skill, example, and external repo updates
Update README, CLAUDE.md, the yauth skill (`~/fj/skills`), and the toasty example (`~/fj/yauth-toasty-example`) to reflect the generate-not-migrate architecture. Write per-ORM wiring guides showing the complete path from init to working Axum app.

## Success Metrics

| Metric | Target |
|--------|--------|
| Runtime migration code | 0 lines — no migration logic in the `yauth` crate |
| `yauth-migration` runtime coupling | `yauth` crate compiles with no dependency on `yauth-migration` |
| Backend constructor API | All backends accept user-provided pools, none accept URL strings |
| ORM artifact correctness | Generated Diesel migrations run via `diesel migration run` with no manual edits |
| ORM artifact correctness | Generated sqlx migrations run via `sqlx migrate run` with no manual edits |
| ORM artifact correctness | Generated SeaORM entities compile and pass type checks with no manual edits |
| ORM artifact correctness | Generated Toasty models compile and pass type checks with no manual edits |
| sqlx query coverage | Every repository trait method has a corresponding generated `.sql` query file |
| Conformance tests | All 65 repo conformance tests pass with schema set up via ORM-native tooling |
| Guided CLI output | Every `cargo yauth` command that generates files prints what was created and what to run next |
| Self-documenting output | Every generated SQL file has comments explaining tables/queries in auth terms |
| Skill onboarding | In a project with no yauth, the skill detects this and offers guided setup in 3-4 questions max |

## Non-Goals

- **Runtime schema validation**: yauth will not check at startup whether tables exist or match expected schema. If they don't, the ORM error is clear enough.
- **Migration execution**: yauth will never run DDL. That's your ORM's job.
- **Pool configuration**: yauth will not create, configure, or tune connection pools. Bring your own.
- **ORM-agnostic query abstraction**: Each backend still has its own repo implementations using its ORM's native query API. The adapter pattern from the previous PRD is abandoned.
- **Backwards compatibility with `migrate()`**: This is a clean break. The next major version removes `migrate()` with no deprecation shim.

## Open Questions

None — all resolved above.
