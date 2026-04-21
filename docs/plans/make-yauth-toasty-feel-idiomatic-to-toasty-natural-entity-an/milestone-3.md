# Milestone 3: Workspace Integration + CI

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone brings `yauth-toasty` under the root workspace and CI coverage. After this milestone, `cargo test --workspace` and `cargo clippy --workspace` catch regressions in yauth-toasty without developers needing to remember a separate `--manifest-path` invocation.

**Toasty version: 0.4** (consistent with M1 and M2).

---

## Goal

Un-exclude `crates/yauth-toasty` from the root `Cargo.toml` workspace, resolve the `libsqlite3-sys` `links` conflict, and add CI matrix coverage for yauth-toasty across PostgreSQL, MySQL, and SQLite.

---

## Deliverables

### 1. Root Workspace `Cargo.toml` Edit

**Change:**

```toml
# Before:
[workspace]
members = ["crates/yauth", "crates/yauth-migration", "crates/yauth-entity", "crates/cargo-yauth"]
exclude = ["crates/yauth-toasty"]
resolver = "2"

# After:
[workspace]
members = [
    "crates/yauth",
    "crates/yauth-migration",
    "crates/yauth-entity",
    "crates/cargo-yauth",
    "crates/yauth-toasty",
]
resolver = "2"
# No more `exclude`
```

### 2. Resolving the `libsqlite3-sys` `links` Conflict

**The problem:** Toasty's SQLite driver (`toasty-driver-sqlite`) depends on a `libsqlite3-sys` version that conflicts with sqlx's `libsqlite3-sys` via Cargo's `links` field. Both declare `links = "sqlite3"`, and Cargo forbids two crates with the same `links` value in one build graph.

**The solution — feature isolation:**

The conflict only manifests when *both* `sqlx-sqlite-backend` (from `yauth`) and `yauth-toasty/sqlite` are compiled in the same invocation. Since:

1. `yauth-toasty` depends on `yauth` with `default-features = false` — it doesn't pull in any backend features.
2. No workspace feature unifies `sqlx-sqlite-backend` and `yauth-toasty/sqlite` simultaneously.
3. The `all-backends` feature on `yauth` (CI-only) does NOT depend on `yauth-toasty`.

This means adding `yauth-toasty` as a workspace member is safe **as long as no single `cargo` invocation enables both sqlite features**. Cargo resolves features per-package, not globally, so `cargo build -p yauth --features sqlx-sqlite-backend` and `cargo build -p yauth-toasty --features sqlite` can coexist in the workspace — they're separate resolution units.

**Verification step:** After adding to workspace, run:

```bash
# This must NOT trigger links conflict:
cargo check --workspace --all-targets
cargo check -p yauth --features full,all-backends
cargo check -p yauth-toasty --features full,sqlite
```

**If the conflict persists despite feature isolation** (Cargo does unify features across workspace members for dev-dependencies or if a shared dependency triggers it):

**Fallback plan — separate CI job (keep excluded):**

If workspace inclusion fails, keep `exclude = ["crates/yauth-toasty"]` and add a dedicated CI job. Document the reason:

```toml
# Cargo.toml
# yauth-toasty is excluded because toasty-driver-sqlite and sqlx both declare
# `links = "sqlite3"`. Cargo's links check prevents them from coexisting in one
# build graph even when they're never compiled together. CI covers yauth-toasty
# via a separate job (see .github/workflows/toasty.yml).
exclude = ["crates/yauth-toasty"]
```

### 3. Dependency Resolution Check

After workspace inclusion, verify the full dependency tree resolves:

```bash
# Must succeed without errors:
cargo metadata --format-version 1 > /dev/null

# Check for version conflicts:
cargo tree -p yauth-toasty --features full,sqlite -d 2>&1 | grep -i conflict

# Verify toasty 0.4 features resolve correctly:
cargo tree -p yauth-toasty --features full,sqlite -i toasty
```

**Toasty 0.4 feature flags used by yauth-toasty:**
- `toasty/sqlite` — SQLite driver
- `toasty/postgresql` — PostgreSQL driver
- `toasty/mysql` — MySQL driver
- `toasty/jiff` — jiff::Timestamp support (added in M1)

**Potential dep conflicts to watch:**
- `uuid` — yauth workspace uses `uuid = "1"`, toasty 0.4 should also use `uuid = "1"`. If toasty uses a different version, add a workspace-level version pin.
- `chrono` — yauth uses `chrono = "0.4"`. Toasty uses `jiff` instead. No conflict expected.
- `tokio` — both use `tokio = "1"`. No conflict.
- `serde` / `serde_json` — both use `1.x`. No conflict.

### 4. Root `cargo test` / `cargo clippy` Behavior

After workspace inclusion:

```bash
# Runs tests for ALL workspace members including yauth-toasty:
cargo test --workspace

# BUT: yauth-toasty's conformance tests require --features full:
# So `cargo test --workspace` skips them (required-features gate).
# They only run with explicit feature activation:
cargo test -p yauth-toasty --features full,sqlite --test conformance
```

**`cargo clippy` behavior:**

```bash
# Checks all workspace members with default features:
cargo clippy --workspace --all-targets -- -D warnings

# yauth-toasty's default features are empty — clippy checks only the
# unconditionally-compiled entity modules and lib.rs. This is useful
# for catching basic errors but doesn't cover feature-gated repo code.

# Full coverage requires explicit features:
cargo clippy -p yauth-toasty --features full,sqlite --all-targets -- -D warnings
```

### 5. CI Matrix Updates

**Primary approach (workspace member):**

Update `.github/workflows/ci.yml`:

```yaml
jobs:
  # Existing job — unchanged (covers yauth core + migrations + entity)
  rust:
    # ...existing config...
    steps:
      - uses: actions/checkout@v4
      - name: Clippy (workspace)
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Test (workspace, default features)
        run: cargo test --workspace
      # ...existing backend-specific test steps...

  # NEW JOB: yauth-toasty CI
  toasty:
    name: yauth-toasty (${{ matrix.backend }})
    runs-on: ubuntu-latest
    strategy:
      matrix:
        backend:
          - { name: sqlite, features: "full,sqlite", services: [] }
          - { name: postgresql, features: "full,postgresql", services: [postgres], env: { DATABASE_URL: "postgres://yauth:yauth@localhost:5432/yauth_test" } }
          - { name: mysql, features: "full,mysql", services: [mysql], env: { MYSQL_DATABASE_URL: "mysql://yauth:yauth@localhost:3306/yauth_test" } }

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: yauth
          POSTGRES_PASSWORD: yauth
          POSTGRES_DB: yauth_test
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready
          --health-interval 5s
          --health-timeout 5s
          --health-retries 5

      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: root
          MYSQL_DATABASE: yauth_test
          MYSQL_USER: yauth
          MYSQL_PASSWORD: yauth
        ports: ["3306:3306"]
        options: >-
          --health-cmd "mysqladmin ping"
          --health-interval 5s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Clippy
        run: cargo clippy -p yauth-toasty --features ${{ matrix.backend.features }} --all-targets -- -D warnings

      - name: Test (conformance)
        run: cargo test -p yauth-toasty --features ${{ matrix.backend.features }} --test conformance
        env: ${{ matrix.backend.env || '{}' }}

      - name: Test (migrations)
        run: cargo test -p yauth-toasty --features ${{ matrix.backend.features }} --test migrations
        env: ${{ matrix.backend.env || '{}' }}

      - name: Format check
        run: cargo fmt -p yauth-toasty --check
```

**Fallback approach (separate CI job, workspace excluded):**

If workspace inclusion fails, the CI job uses `--manifest-path`:

```yaml
  toasty:
    name: yauth-toasty (${{ matrix.backend }})
    # ...same matrix and services as above...
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Clippy
        run: cargo clippy --manifest-path crates/yauth-toasty/Cargo.toml --features ${{ matrix.backend.features }} --all-targets -- -D warnings

      - name: Test (conformance)
        run: cargo test --manifest-path crates/yauth-toasty/Cargo.toml --features ${{ matrix.backend.features }} --test conformance
        env: ${{ matrix.backend.env || '{}' }}

      - name: Test (migrations)
        run: cargo test --manifest-path crates/yauth-toasty/Cargo.toml --features ${{ matrix.backend.features }} --test migrations
        env: ${{ matrix.backend.env || '{}' }}
```

### 6. Service Requirements

The CI job uses GitHub Actions service containers (not testcontainers). This matches how the existing yauth CI runs (`docker compose up -d` locally, service containers in CI).

**Required services:**
- **PostgreSQL 16** — for `--features full,postgresql` tests
- **MySQL 8.0** — for `--features full,mysql` tests
- **SQLite** — no service needed (in-memory or file-based)

**No testcontainers dependency.** The existing yauth test infrastructure doesn't use testcontainers (it uses `docker compose` locally and CI service containers remotely). yauth-toasty follows the same pattern for consistency.

**Database setup in tests:** Conformance tests call `backend.create_tables()` (which delegates to `push_schema()`). Migration tests call `apply_migrations()`. Neither requires manual SQL setup scripts in CI.

---

## File-by-File Changes

| File | Change |
|------|--------|
| `Cargo.toml` (root) | Add `"crates/yauth-toasty"` to `members`, remove `exclude` line. |
| `.github/workflows/ci.yml` | Add `toasty` job with 3-backend matrix (sqlite, postgresql, mysql). |
| `crates/yauth-toasty/Cargo.toml` | Add `workspace = true` to `[package]` for shared workspace metadata (version, edition, license, repository). Keep `publish = false`. |
| `CLAUDE.md` | Add yauth-toasty to the workspace structure table. Document the CI approach (workspace member or separate job). Add `cargo test -p yauth-toasty --features full,sqlite --test conformance` to the key commands section. |

**If fallback approach is needed (workspace exclusion stays):**

| File | Change |
|------|--------|
| `Cargo.toml` (root) | Keep `exclude = ["crates/yauth-toasty"]` with explanatory comment. |
| `.github/workflows/toasty.yml` | **New.** Dedicated workflow for yauth-toasty CI (uses `--manifest-path`). |
| `CLAUDE.md` | Document that yauth-toasty is excluded from workspace due to `links` conflict, with separate CI coverage. |

---

## Acceptance Criteria / Verification

### If workspace inclusion succeeds:

1. **`cargo check --workspace --all-targets`** — passes without `links` conflict or resolution errors.
2. **`cargo clippy --workspace --all-targets -- -D warnings`** — passes (yauth-toasty checked with default features).
3. **`cargo clippy -p yauth-toasty --features full,sqlite --all-targets -- -D warnings`** — zero warnings.
4. **`cargo clippy -p yauth-toasty --features full,postgresql --all-targets -- -D warnings`** — zero warnings.
5. **`cargo clippy -p yauth-toasty --features full,mysql --all-targets -- -D warnings`** — zero warnings.
6. **`cargo test --workspace`** — passes (yauth-toasty unit tests run; conformance skipped due to `required-features` gate).
7. **`cargo test -p yauth-toasty --features full,sqlite --test conformance`** — all 65+ tests pass.
8. **`cargo test -p yauth-toasty --features full,sqlite --test migrations`** — migration tests pass.
9. **With `DATABASE_URL` set:** `cargo test -p yauth-toasty --features full,postgresql --test conformance` — passes.
10. **With `MYSQL_DATABASE_URL` set:** `cargo test -p yauth-toasty --features full,mysql --test conformance` — passes.
11. **`cargo metadata --format-version 1 | jq '.workspace_members[]' | grep yauth-toasty`** — yauth-toasty appears in workspace members.
12. **CI workflow passes** on a PR (all three backends green).
13. **Existing yauth CI jobs unaffected** — `cargo test --features full,all-backends` still passes for the core yauth crate.

### If fallback approach is used:

1. **`Cargo.toml` has explanatory comment** on the `exclude` line.
2. **`.github/workflows/toasty.yml` exists** with matrix across sqlite/pg/mysql.
3. **`cargo clippy --manifest-path crates/yauth-toasty/Cargo.toml --features full,sqlite --all-targets -- -D warnings`** — passes.
4. **`cargo test --manifest-path crates/yauth-toasty/Cargo.toml --features full,sqlite --test conformance`** — passes.
5. **CI workflow passes** on a PR.
6. **CLAUDE.md documents** the separate CI approach.

---

## Out of Scope

- **Merging yauth-toasty into the `yauth` crate.** It remains a separate crate. The workspace inclusion is just about CI coverage and developer ergonomics.
- **Adding yauth-toasty to `all-backends` feature flag.** The `all-backends` feature already excludes `diesel-libsql-backend` for similar `links` reasons. yauth-toasty follows the same pattern — it's tested separately.
- **Testcontainers integration.** The project uses docker compose locally and CI service containers. No testcontainers are introduced.
- **Publishing yauth-toasty.** `publish = false` remains. Publishing is gated on acceptance criteria in the PRD.
- **Cross-crate integration tests.** Tests that exercise yauth + yauth-toasty together (e.g., running the pentest suite against the Toasty backend) are future work.
- **Workspace-level feature unification.** We do NOT add `yauth-toasty` features to the root workspace's `[workspace.dependencies]` or try to unify features across crates. Each crate manages its own feature flags independently.

---

## Known Pitfalls

1. **Cargo feature unification in dev-dependencies.** Even if `yauth-toasty` uses `yauth` with `default-features = false`, Cargo may unify features when both crates are workspace members and share dev-dependencies. Run `cargo tree --workspace -e features` to verify no unexpected feature activation. If `sqlx-sqlite-backend` gets activated on `yauth-toasty`'s dependency on `yauth`, the `links` conflict triggers.

2. **CI matrix services are conditional.** GitHub Actions service containers run for all matrix entries. The sqlite entry doesn't need postgres/mysql services but they start anyway. This is harmless (services are unused) but slightly wasteful. Use `if: matrix.backend.name != 'sqlite'` on service steps if GHA supports it, or accept the minor waste.

3. **`cargo test --workspace` runtime.** Adding yauth-toasty to the workspace means `cargo test --workspace` now compiles an additional crate. With default features (no plugins), this is a trivial compile (~2s). With `--features full,sqlite`, it adds significant compile time (~30s). The CI job tests yauth-toasty separately to avoid inflating the main CI time.

4. **Lockfile churn.** Adding yauth-toasty as a workspace member pulls toasty's dependencies into the root `Cargo.lock`. This is a large diff (~50-100 new entries). It's correct behavior but produces a noisy PR. Commit the lockfile change in a dedicated commit with a clear message.

5. **Version field in `Cargo.toml`.** If `yauth-toasty` uses `version.workspace = true`, it inherits the workspace version (currently `0.12.0`). But yauth-toasty is at `0.8.9`. **Decision:** Keep `version = "0.8.9"` in yauth-toasty's `Cargo.toml` (do NOT inherit workspace version). yauth-toasty has `publish = false` so version number is informational only. When it's eventually published, knope will manage it.

6. **`cargo fmt` scope.** `cargo fmt --check` at the workspace root already checks all workspace members. After inclusion, yauth-toasty code is covered by the existing fmt check. Ensure the code passes `cargo fmt --check` before adding to workspace.

7. **Rust edition alignment.** The workspace uses `edition = "2024"` and yauth-toasty already uses `edition = "2024"`. No change needed. If they differed, workspace members can specify their own edition.
