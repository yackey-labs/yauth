# Code-First ORM Backends (SeaORM + Toasty)

## Overview

Add SeaORM and Toasty backends to yauth, enabling users who prefer code-first ORMs to use yauth with their ORM's native patterns. Unlike the existing Diesel/sqlx backends where yauth owns the migration story, these backends export native ORM entity definitions and let users manage migrations with the ORM's own tooling.

## Core Features

1. **SeaORM Backends (PG, MySQL, SQLite)**: Three separate backends — `seaorm-pg-backend`, `seaorm-mysql-backend`, `seaorm-sqlite-backend` — each implementing all yauth repository traits using SeaORM's query API. Users get native `DeriveEntityModel` entity definitions they can use directly in their own SeaORM code alongside yauth.

2. **Toasty Backends**: Backends for each SQL database Toasty supports (PG, MySQL, SQLite), implementing all yauth repository traits using Toasty's generated query types. Users get `#[derive(toasty::Model)]` struct definitions they can use alongside their own Toasty models. DynamoDB is out of scope (yauth's schema is relational).

3. **Native Entity Exports**: Each backend's ORM-annotated entity types are publicly exported so users can join, query, and extend yauth tables using the ORM they already know. This is the key differentiator from Diesel/sqlx backends where internal models are private.

4. **User-Owned Migrations**: `DatabaseBackend::migrate()` performs schema validation only (checking that expected tables/columns exist) rather than running DDL. Users run migrations with `sea-orm-cli migrate` or Toasty's schema tooling. yauth provides the entity/schema definitions; users are responsible for applying them.

5. **Migration Asset Generation**: `cargo yauth generate` learns two new output modes:
   - `--orm seaorm` — emits SeaORM entity files (`entity/*.rs` with `DeriveEntityModel`) and optionally a `sea-orm-migration` migration crate skeleton
   - `--orm toasty` — emits Toasty model files with `#[derive(toasty::Model)]` structs defining all yauth tables
   
   These are generated from the same `TableDef` source of truth in `yauth-migration`, ensuring schema consistency across all backends.

6. **Conformance Testing**: All new backends pass the existing repo conformance test suite (currently 65+ tests). Added to `test_backends()` with the same skip-if-no-URL pattern.

## Technical Decisions

- **Separate backends per database, not one unified backend** — matches the existing pattern (`diesel-pg-backend`, `diesel-mysql-backend`, etc.) and avoids runtime database-type detection. Each backend pulls in only the deps it needs.
- **Public entity exports** — SeaORM and Toasty users expect to use ORM entity types directly. Unlike Diesel backends where `models.rs` is private, these backends export their entity modules publicly (e.g., `yauth::backends::seaorm_pg::entities`). Domain conversion still happens internally via `into_domain()` / `from_domain()`.
- **`migrate()` validates, doesn't mutate** — for code-first backends, `migrate()` queries `information_schema` (or equivalent) to verify all expected yauth tables and columns exist, returning a clear error if something is missing. This catches "forgot to run migrations" without taking ownership of the migration process.
- **Separate entity modules per backend, not cfg_attr on `yauth-entity`** — SeaORM's `DeriveEntityModel` generates an entire module of companion types per entity: a unit `Entity` struct, `Column` enum, `PrimaryKey` enum, `ActiveModel` (wrapping each field in `ActiveValue<T>`), `Relation` enum with `RelationTrait` impl, and `ActiveModelBehavior` impl. The struct must be named `Model` inside a module containing all these siblings, and relations reference other entity modules (`super::session::Entity`). None of this can be cfg_attr'd onto a shared domain struct. This is the universal pattern — Loco (the largest SeaORM framework) uses a dedicated `_entities/` directory with one file per table. yauth follows the same approach: SeaORM entities live in a shared `backends/seaorm_common/entities/` module (re-exported by each per-dialect backend), Toasty models in a shared `backends/toasty_common/models/` module, with `into_domain()` / `from_domain()` conversions to `yauth-entity` types (identical to how Diesel backends already use private `models.rs`). `yauth-entity` remains ORM-agnostic.
- **Toasty is experimental** — Toasty is pre-1.0 and its API may change. The Toasty backends carry an `#[doc = "experimental"]` warning and are excluded from stability guarantees until Toasty reaches 1.0. They are included in `all-backends` for CI but documented as unstable.
- **`yauth_` table prefix preserved** — all entity definitions use the same `yauth_` table prefix as other backends, ensuring users can mix-and-match or migrate between backends without schema changes.

## Milestones

### Milestone 1: SeaORM PostgreSQL Backend
The first code-first backend, establishing the pattern. Includes:
- `seaorm-pg-backend` feature flag and `backends::seaorm_pg` module
- SeaORM entity definitions for all yauth tables (core + all plugin tables)
- All repository trait implementations using SeaORM queries
- `migrate()` as schema validator
- `cargo yauth generate --orm seaorm` for entity file generation
- Full conformance test suite passing

### Milestone 2: SeaORM MySQL + SQLite Backends
Extend SeaORM support to remaining databases:
- `seaorm-mysql-backend` and `seaorm-sqlite-backend` feature flags
- Shared entity definitions (SeaORM entities are database-agnostic) with per-dialect query adjustments where needed
- Conformance tests for both

### Milestone 3: Toasty Backends
Add Toasty support once the SeaORM pattern is proven:
- Toasty backends for each supported database
- Toasty model generation via `cargo yauth generate --orm toasty`
- Conformance tests
- Experimental stability label

### Milestone 4: Update yauth Skill
Update the yauth integration skill in `~/fj/skills/plugins/yauth/skills/yauth/SKILL.md` to document the new backends:
- Add SeaORM backends (PG, MySQL, SQLite) to the backend selection guide with quick-start examples
- Add Toasty backends with experimental label
- Document the user-owned migration workflow (how it differs from Diesel/sqlx)
- Add `cargo yauth generate --orm seaorm` and `--orm toasty` to the CLI reference
- Update feature flag tables with new backend features
- Add SeaORM entity export usage examples (importing entities for custom queries)
- Update the `references/plugin-configs.md` if backend config patterns differ

## Success Metrics

| Metric | Target |
|--------|--------|
| Conformance test pass rate | 100% of existing tests pass on every new backend |
| Entity export usability | User can import yauth SeaORM entities and use them in their own SeaORM queries without wrapper code |
| Migration validation accuracy | `migrate()` detects missing tables/columns with zero false positives on a correctly migrated database |
| Schema consistency | Generated SeaORM entities and Toasty schemas produce identical table structures to Diesel/sqlx backends (verified by cross-backend conformance tests) |

## Non-Goals

- **yauth does not run migrations for code-first backends** — users use `sea-orm-cli migrate`, Toasty CLI, or their own migration pipeline
- **No SeaORM/Toasty integration in the plugin system itself** — plugins continue to work through repository traits; the ORM is an implementation detail of the backend
- **No runtime backend switching** — you pick one backend at compile time via feature flags, same as today
- **No Toasty stability guarantees** — until Toasty reaches 1.0, breaking changes in Toasty may require breaking changes in the yauth Toasty backend
- **No `sea-orm-migration` auto-execution** — `cargo yauth generate --orm seaorm` can scaffold migration files, but yauth never runs `sea-orm-cli` for you

## Open Questions

None — all resolved above.
