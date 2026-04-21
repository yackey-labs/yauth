# Plan: Make yauth-toasty Idiomatic to Toasty

## Problem

`yauth-toasty` works (65+ conformance tests pass across PG/MySQL/SQLite) but doesn't feel like Toasty code. The entities are flat structs with no `#[belongs_to]`/`#[has_many]` relationships, datetimes are manually encoded as `String` with 40+ conversion callsites through `helpers.rs`, JSON fields are serialized to `String` by hand, and queries fetch entire tables then filter in memory. A Toasty developer would look at the code and see diesel/sqlx patterns shoehorned into `#[derive(toasty::Model)]`.

## Fix

Refactor the `yauth-toasty` crate (at `crates/yauth-toasty/`) so its entity definitions, query patterns, and migration story use Toasty's native idioms:

1. **Relationship graph** — add `#[belongs_to]`/`#[has_many]`/`#[has_one]` to all 27 entity structs, enabling cascade deletes and eager loading.
2. **Native timestamps** — replace `String`-encoded datetimes with `jiff::Timestamp` (Toasty's canonical time type via its `jiff` feature), eliminating `dt_to_str`/`str_to_dt` helpers.
3. **Native JSON** — replace `String`-encoded JSON with `#[serialize(json)]` + real Rust types, eliminating `json_to_str`/`str_to_json` helpers.
4. **DB-level queries** — replace in-memory filtering/pagination with Toasty's `.filter()`, `.limit()`, `.offset()`.
5. **Migration chain** — add Toasty's snapshot-anchored migration system with embedded migrations for library consumers.
6. **Workspace integration** — bring yauth-toasty under CI coverage (workspace member or separate CI job).

Scope is limited to the `yauth-toasty` crate. No changes to yauth core, diesel backends, sqlx backends, SeaORM backends, or `yauth-entity` domain types.

## Milestones

### Milestone 1: Entity Rewrite + Relationship Graph + Repo Refresh

Rewrite all 27 entity structs to use Toasty relationships, `jiff::Timestamp`, and `#[serialize(json)]`. Update all 17 repository implementations to use the new entity shapes and idiomatic Toasty query patterns. Remove `#[cfg]` gates from entity modules (all models always compiled). Remove `tokio-postgres` optional dependency. All 65+ conformance tests pass.

This is the core deliverable. It addresses problems 1-4 from the PRD and produces the most visible idiomaticity improvement.

### Milestone 2: Migration System (future)

Set up Toasty's migration chain: `Toasty.toml`, dev CLI binary, embedded migrations via `include_dir!`, `apply_migrations()` public API. Addresses problem 5 from the PRD.

### Milestone 3: Workspace Integration + CI (future)

Bring yauth-toasty under CI coverage. Attempt workspace inclusion; fall back to separate CI job if `links` conflict is unavoidable. Addresses problem 6 from the PRD.

### Milestone 4: Documentation + Examples (future)

Update `CLAUDE.md`, `README.md`, the yauth skill, and any examples to reflect the idiomatic Toasty backend. Update `cargo yauth generate --orm toasty` output to match the new entity patterns.
