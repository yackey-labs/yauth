# Milestone 4: Update README + yauth Skill

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone has two parts: first update the yauth repo's own `README.md`, then update the yauth integration skill in the separate skills repo.

**Part A — README.md** (in this repo, `/home/steve/fj/yauth/README.md`):
- Add SeaORM backends (PG, MySQL, SQLite) and Toasty backends (PG, MySQL, SQLite) to the backend feature flag table
- Update the `all-backends` description to include the new backends
- Add `"seaorm"` and `"toasty"` to the `orm = "diesel" | "sqlx"` config example in the `yauth.toml` section
- Add a SeaORM quick-start example alongside the existing memory-backend quick-start (show `SeaOrmPgBackend::new(url)`)
- Note that SeaORM/Toasty backends use user-owned migrations — `migrate()` validates only, users run their ORM's migration tool
- Mark Toasty backends as experimental

**Part B — yauth skill** (in the `yackey-labs/skills` repo at `git@github.com:yackey-labs/skills.git`, locally at `~/fj/skills`). The skill files are at `plugins/yauth/skills/yauth/SKILL.md` and `plugins/yauth/skills/yauth/references/plugin-configs.md`.

### What must work:
1. **README.md** backend feature table includes all new backends with accurate descriptions
2. **README.md** `yauth.toml` example shows `orm = "diesel" | "sqlx" | "seaorm" | "toasty"`
3. **README.md** has a SeaORM quick-start example showing `SeaOrmPgBackend::new(url)` usage
4. The skill's backend selection guide includes SeaORM (PG, MySQL, SQLite) and Toasty (PG, MySQL, SQLite) alongside existing Diesel/sqlx/memory backends
5. Quick-start examples show how to add each new backend to Cargo.toml, construct the backend, and build `YAuth`
6. The user-owned migration workflow is documented — how it differs from Diesel/sqlx (no `backend.migrate()` DDL, user runs `sea-orm-cli migrate` or `toasty-cli migration apply`)
7. `cargo yauth generate --orm seaorm` and `--orm toasty` are in the CLI reference section
8. Feature flag tables include all new backend features
9. SeaORM entity export usage examples show how to import entities for custom queries
10. Toasty backends are clearly marked experimental

### After building, prove it works:
- Read README.md end-to-end. The feature flag table must list exactly 14 backends (4 diesel + 3 sqlx + 3 seaorm + 3 toasty + memory). Every code snippet must be syntactically valid Rust/TOML.
- Read the updated SKILL.md end-to-end. Every code snippet must be syntactically valid Rust/TOML.
- Verify both feature flag tables (README + SKILL) match what's actually in `crates/yauth/Cargo.toml` after milestones 1-3.
- Verify the backend selection guide covers all backends: diesel-pg, diesel-mysql, diesel-sqlite, diesel-libsql, sqlx-pg, sqlx-mysql, sqlx-sqlite, seaorm-pg, seaorm-mysql, seaorm-sqlite, toasty-pg, toasty-mysql, toasty-sqlite, memory.
- Verify the quick-start example for SeaORM PG compiles conceptually (correct imports, correct method names, correct feature flags).
- Check that `references/plugin-configs.md` includes any new config patterns for SeaORM/Toasty backends (e.g., `SeaOrmPgBackend::new(url)` vs `DieselPgBackend::new(url)`).

### Test strategy:
- Manual review — this is documentation, not code
- Cross-reference against actual Cargo.toml feature definitions and backend struct APIs from milestones 1-3

### Known pitfalls:
1. **Skill version**: Update the `metadata.version` in SKILL.md frontmatter to match the new yauth release version.
2. **Don't duplicate CLAUDE.md**: The skill should reference CLAUDE.md conventions, not restate them. Focus on user-facing integration guidance.
3. **Migration workflow is the key differentiator**: The most important new content is explaining that SeaORM/Toasty backends don't run migrations — users manage schema with their ORM's native tools. This is a paradigm shift from existing backends and must be prominently documented.
4. **Toasty experimental warning**: Add a visible callout (not just inline text) marking Toasty backends as experimental with a note about pre-1.0 instability.
