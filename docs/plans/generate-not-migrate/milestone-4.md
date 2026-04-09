# Milestone 4: Docs, skill, example, and README updates

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

After this milestone, all documentation, the yauth skill, the toasty example, and the README reflect the generate-not-migrate architecture. A beginner who knows nothing about auth can follow the README to a working app. A pro who's used Diesel for years sees native patterns and zero friction. Both paths start from the same README but diverge naturally — quick-start for beginners, per-ORM deep dives for pros.

### What must work:

1. **README.md** (`~/fj/yauth/README.md`):
   - Quick-start shows `from_pool()` pattern, not `new(url)`
   - No mention of `backend.migrate()` — replaced with "run your ORM's migration CLI"
   - Per-ORM setup sections: Diesel, sqlx, SeaORM, Toasty — each showing the native workflow
   - `cargo yauth generate` section updated to describe per-ORM outputs (migrations, query files, entities, models)
   - Feature flags table updated if any flags changed
   - Backend table reflects pool-first constructors

2. **CLAUDE.md** (`~/fj/yauth/CLAUDE.md`):
   - Architecture section updated: no migration system, backends accept pools
   - `DatabaseBackend` trait shown without `migrate()`
   - Builder pattern example updated (no migrate step)
   - Key commands section updated (remove any migrate references)
   - Conformance test section notes raw-SQL schema setup pattern

3. **Skill** (`~/fj/skills/plugins/yauth/skills/yauth/SKILL.md`):
   - Updated to reflect generate-not-migrate architecture
   - Backend selection guide shows pool-first constructors
   - Migration CLI section rewritten: generate-only, no runtime migration
   - Per-ORM wiring examples updated
   - Version bumped in frontmatter metadata
   - **New: guided onboarding flow** — when the skill triggers in a project with no yauth setup (no `yauth` in Cargo.toml, no `yauth.toml`), the skill detects this and offers three paths:
     - **Walk through**: Use AskUserQuestion to guide the user step by step. Inspect the project first (check Cargo.toml for existing ORM deps, check for existing migrations dir, check database env vars) and make recommendations based on what's already there. Questions are short and direct: "You have sqlx in Cargo.toml. Use sqlx-pg-backend?" / "Which auth features? Email+password is typical for most apps." / "Enable passkey login? Adds WebAuthn — good for passwordless."
     - **Describe**: User describes what they want in plain language ("I need email login with MFA for a postgres app") and the skill translates to the right `cargo yauth init` invocation.
     - **Defaults**: Apply sensible defaults immediately (email-password + session auth, matching whatever ORM/DB is already in the project) and show what was chosen so the user can adjust.
   - The onboarding flow ends with the skill running `cargo yauth init` and printing what to do next — no dead ends.

4. **Toasty example** (`~/fj/yauth-toasty-example/`):
   - `backend/src/main.rs` — no `migrate()` call (it already uses `push_schema()` for Toasty, so mainly verify no yauth migrate call exists)
   - `backend/Cargo.toml` — verify deps are current
   - `README.md` — updated to reflect the generate-not-migrate workflow, pool-first pattern

5. **Per-ORM wiring guides** — either in README sections or separate docs. Each guide should be followable by someone who knows their ORM but has never done auth. Define auth concepts where they first appear — one sentence, factual, no preamble (e.g., "Sessions track which users are currently logged in." not "As you may already know, session management is a critical part of any authentication system."):
   - **Diesel**: `cargo yauth init --orm diesel` → `diesel migration run` → `DieselPgBackend::from_pool(pool)` → build
   - **sqlx**: `cargo yauth init --orm sqlx` → `sqlx migrate run` → `SqlxPgBackend::from_pool(pool)` → build
   - **SeaORM**: `cargo yauth generate --orm seaorm` → copy entities → `SeaOrmPgBackend::from_connection(db)` → build
   - **Toasty**: `cargo yauth generate --orm toasty` → compile models → `ToastySqliteBackend::from_db(db)` → build

### After building, prove it works:

- Read the README from top to bottom as a new user. Every code example should compile conceptually (no references to removed APIs).
- `cargo yauth --help` output matches what the README describes.
- Search all updated files for `migrate(` — zero hits except in historical context (changelog, migration guide).
- Search all updated files for `new(url` or `new("postgres` — zero hits in quick-start or setup sections.
- The toasty example builds: `cd ~/fj/yauth-toasty-example/backend && cargo check`

### Test strategy:

No automated tests — this is documentation. Manual review for accuracy and completeness.

### Known pitfalls:

1. **README.md is 1064 lines**: Don't rewrite from scratch. Surgically update the sections that reference migration or URL-based constructors. Use search-and-replace for common patterns like `backend.migrate(` and `.new("postgres`.

2. **SKILL.md is 1335 lines**: Same approach — surgical updates. The skill is used by Claude Code agents, so accuracy matters. Wrong examples in the skill will propagate to generated code.

3. **The toasty example already doesn't call migrate()**: It uses `db.push_schema()` which is Toasty's own schema sync. Verify this is still the right pattern and that the README explains it clearly.

4. **Version numbers in skill metadata**: Bump the version in `SKILL.md` frontmatter and `plugin.json` to match the new yauth release version.

5. **Cross-repo consistency**: The skill, README, CLAUDE.md, and toasty example must all show the same API. If one says `from_pool()` and another says `new()`, agents will get confused. Do a final grep across all four for constructor names.

6. **Don't remove historical docs**: `docs/migrating-to-diesel.md` is historical. Leave it. The CHANGELOG.md documents past versions. Don't rewrite history.

7. **Skill onboarding must detect, not assume**: The skill should check for `yauth` in Cargo.toml and `yauth.toml` existence before triggering the onboarding flow. If yauth is already set up, skip straight to the normal skill behavior. Don't ask "want to set up yauth?" in a project that already has it.

8. **AskUserQuestion has latency**: Each question round-trips to the user. Keep the walkthrough to 3-4 questions max. Don't ask what you can infer from the project (if Cargo.toml has `sqlx` with `postgres` feature, don't ask which ORM or dialect).
