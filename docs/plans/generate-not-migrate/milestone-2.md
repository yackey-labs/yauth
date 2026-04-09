# Milestone 2: Decouple yauth-migration from yauth runtime

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

After this milestone, the `yauth` crate compiles with zero dependency on `yauth-migration`. Schema types, DDL generators, and plugin schema definitions live only in `cargo-yauth`.

### What must work:

1. `yauth-migration` is not listed in `crates/yauth/Cargo.toml` `[dependencies]` (it can remain in `[dev-dependencies]` for test helpers)
2. `crates/yauth/src/schema/` module is removed entirely
3. The `YAuthPlugin` trait's `fn schema(&self) -> Vec<TableDef>` method is removed — plugins no longer carry schema metadata
4. `YAuth::schema()` and `YAuth::generate_ddl()` convenience methods on the builder output are removed
5. `diesel_migrations/` directory deleted from `crates/yauth/` — these pre-written SQL files are redundant now that M1 removed the runtime migration code that consumed them via `include_str!()`
6. `cargo test --features full,all-backends` passes — all tests still work
7. `cargo build --features full,diesel-pg-backend` compiles without yauth-migration in the dep tree

### After building, prove it works:

- `cargo tree -p yauth --features full,diesel-pg-backend | grep yauth-migration` — no output (yauth-migration not in dep tree)
- `cargo test --features full,all-backends --test repo_conformance` — all 65 tests pass
- `cargo test --features full,all-backends --test pentest` — passes
- `cargo clippy --features full,all-backends -- -D warnings` — clean
- `cargo build -p cargo-yauth` — CLI still builds and works (it keeps yauth-migration dep)
- `cargo yauth generate --check -f yauth.toml` (in a test project) — still works

### Test strategy:

Test helpers can use `yauth-migration` as a dev-dependency to generate schema SQL. This is fine — test code is not shipped.

Verify the dep tree is clean: `cargo tree` must show yauth-migration only under cargo-yauth, not under yauth.

### Known pitfalls:

1. **`pub use yauth_migration::*` in schema/mod.rs is a public API**: Removing it is a breaking change. Any downstream code using `yauth::schema::TableDef` breaks. This is expected — it's a major version bump. But check if any of the example apps or the toasty example import these types.

2. **Plugin `fn schema()` is used by the builder**: Check if `YAuthBuilder::build()` calls `plugin.schema()` for anything other than migration. If it collects schemas for validation or event routing, that logic must be removed or refactored.

3. **`diesel_migrations/` directory is deleted entirely**: cargo-yauth generates SQL from `TableDef` via yauth-migration's DDL generators. The pre-written SQL files were only needed for `include_str!()` in runtime migration, which M1 already removed. Delete the directory — don't move it.

4. **workspace Cargo.toml**: After removing `yauth-migration` from the `yauth` crate, check if the workspace `[dependencies]` section still makes sense. The workspace dep for `yauth-migration` should remain since cargo-yauth still uses it.

5. **`Dialect` enum re-exported from yauth**: If any public API on `YAuth` or `YAuthBuilder` accepts `Dialect`, that signature must change. Check `generate_ddl(dialect: Dialect)` specifically.
