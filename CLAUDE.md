# CLAUDE.md — yauth

## What This Is

`yauth` is a modular, plugin-based authentication library for Rust (Axum) with TypeScript client + SolidJS UI packages. It provides email/password, passkey (WebAuthn), MFA (TOTP + backup codes), OAuth, bearer tokens (JWT), API keys, and admin endpoints — all behind feature flags.

**Repo:** `github.com/yackey-labs/yauth`

## Workspace Structure

### Rust Crates (`crates/`)

| Crate | Purpose |
|---|---|
| `yauth` | Main library — plugins, middleware, builder, auth logic, backends, repository traits, declarative schema |

Key internal modules in `yauth`:
- `backends/diesel_pg/` — PostgreSQL backend (`DieselBackend`)
- `backends/diesel_libsql/` — SQLite/Turso backend (`DieselLibsqlBackend`)
- `backends/memory/` — In-memory backend (`InMemoryBackend`)
- `backends/redis/` — Redis caching decorators
- `repo/` — `DatabaseBackend` trait, repository traits, `Repositories` struct, `RepoError`
- `domain/` — ORM-agnostic domain types (always compiled, no backend deps)
- `schema/` — Declarative schema definitions, DDL generation per dialect (Postgres, SQLite, MySQL)

### TypeScript Packages (`packages/`)

| Package | Purpose |
|---|---|
| `@yackey-labs/yauth-shared` | Shared types (`AuthUser`, `AuthSession`, AAGUID map) |
| `@yackey-labs/yauth-client` | HTTP client for all auth endpoints |
| `@yackey-labs/yauth-ui-vue` | Vue 3 components + composables (LoginForm, useAuth, etc.) |
| `@yackey-labs/yauth-ui-solidjs` | SolidJS components (LoginForm, RegisterForm, etc.) |

### Pentest Suite (`pentest/`)

`pentest-yauth.sh` — comprehensive OWASP security test suite (255+ cases).

## Key Commands

```bash
# Rust
cargo test --features full          # Run all unit tests
cargo fmt --check                    # Format check
cargo clippy --features full -- -D warnings  # Lint

# TypeScript
bun install                          # Install dependencies
bun run build                        # Build all TS packages
bun run lint                         # Biome lint check
bun run lint:fix                     # Biome lint + fix
bun run typecheck                    # TypeScript type check
bun validate                         # lint:fix + typecheck + build
bun validate:ci                      # lint + typecheck + build + generate:check (strict)

# Client generation
bun generate                         # Regenerate TS client from Rust types + routes
bun generate:check                   # Fail if generated client is out of date (CI)

# Integration / Pentest
docker compose up -d                 # Start PostgreSQL + Mailpit
bash pentest/pentest-yauth.sh        # Run full pentest suite (255+ cases, 0 FAIL expected)
```

## Feature Flags

### Backend Features

| Feature | What It Enables | Default |
|---|---|---|
| `diesel-pg-backend` | PostgreSQL backend via diesel-async + deadpool | Yes |
| `diesel-libsql-backend` | SQLite/Turso backend via `diesel-libsql` crate | No |
| `memory-backend` | Fully in-memory backend (no database required) | No |

### Plugin Features

| Feature | What It Enables | Default |
|---|---|---|
| `email-password` | Registration, login, verification, forgot/reset/change password | Yes |
| `passkey` | WebAuthn registration + login | No |
| `mfa` | TOTP setup/verify + backup codes | No |
| `oauth` | OAuth2 provider linking | No |
| `bearer` | JWT access/refresh tokens | No |
| `api-key` | API key generation + validation | No |
| `admin` | User management, ban/unban, impersonation | No |
| `telemetry` | Native OpenTelemetry SDK instrumentation (spans, span events, context propagation) | No |
| `openapi` | utoipa OpenAPI spec generation (for client codegen) | No |
| `redis` | Redis caching decorator — wraps repository traits for sub-ms session/rate-limit lookups | No |
| `full` | All of the above (all backends + all plugins) | No |

Feature flags gate code across all Rust crates in the workspace.

## Architecture

### Plugin System

Plugins implement the `YAuthPlugin` trait:
- `public_routes()` — unauthenticated routes (login, register, etc.)
- `protected_routes()` — routes behind auth middleware (change password, passkey management, etc.)
- `on_event()` — react to auth events (MFA intercepts login, etc.)

### Database Backends

yauth uses a `DatabaseBackend` trait with three implementations:

| Backend | Type | Use case |
|---|---|---|
| `DieselBackend` | `backends::diesel_pg` | Production PostgreSQL (default) |
| `DieselLibsqlBackend` | `backends::diesel_libsql` | Local SQLite files or remote Turso databases |
| `InMemoryBackend` | `backends::memory` | Tests, prototyping, CI — no database required |

Redis (`with_redis()`) is a **caching decorator** that wraps repository traits for sub-millisecond session/rate-limit lookups. The database remains the source of truth. Redis is not a separate store backend.

### Builder Pattern

`build()` is **async** and returns `Result<YAuth, RepoError>`. Migrations are explicit — call `backend.migrate()` before building.

```rust
use yauth::backends::diesel_pg::DieselBackend;
use yauth::repo::{DatabaseBackend, EnabledFeatures};

let backend = DieselBackend::new("postgres://user:pass@localhost/mydb")?;
backend.migrate(&EnabledFeatures::from_compile_flags()).await?;

let yauth = YAuthBuilder::new(backend, config)
    .with_email_password(ep_config)
    .with_passkey(pk_config)
    .with_bearer(bearer_config)
    .with_mfa(mfa_config)
    .build()
    .await?;

let router = yauth.router();        // Axum Router<YAuthState>
let state = yauth.state().clone();   // For app-level state sharing
```

### Tri-Mode Auth Middleware

The auth middleware checks credentials in order:
1. **Session cookie** — `CookieJar` → `validate_session()`
2. **Bearer token** — `Authorization: Bearer <jwt>` → JWT validation (feature-gated)
3. **API key** — `X-Api-Key: <key>` → key hash lookup (feature-gated)

Authenticated user is injected as `Extension<AuthUser>` on the request.

### Core Routes (always available)

- `GET /session` — returns authenticated user info
- `POST /logout` — invalidates session cookie

## Generated TypeScript Client

This project uses `utoipa` (OpenAPI 3.1 spec generation) + `orval` (TypeScript client generation from OpenAPI) to auto-generate `@yackey-labs/yauth-client`.

**Pipeline:** Rust types derive `ToSchema` → `routes_meta.rs` builds OpenAPI spec programmatically → `openapi.json` → orval generates `packages/client/src/generated.ts` → `packages/client/src/index.ts` wraps generated functions into backward-compatible `createYAuthClient()` factory.

**Key files:**
- `crates/yauth/src/routes_meta.rs` — OpenAPI spec builder (paths + schemas per feature flag)
- `openapi.json` — generated OpenAPI 3.1 spec (committed)
- `orval.config.ts` — orval configuration
- `packages/client/src/mutator.ts` — custom fetch wrapper (credentials, error handling, bearer tokens)
- `packages/client/src/generated.ts` — orval-generated functions (committed, do not edit manually)
- `packages/client/src/index.ts` — `createYAuthClient()` wrapper providing grouped API

**When modifying any API endpoint or request/response type:**
1. Update the route metadata in `crates/yauth/src/routes_meta.rs`
2. Ensure request/response types have `#[derive(TS)] #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))] #[ts(export)]`
3. Run `bun generate` to regenerate `openapi.json` and the TypeScript client
4. Commit the regenerated `openapi.json` and `packages/client/src/generated.ts` alongside Rust changes

**CI check:** `bun generate:check` (part of `bun validate:ci`) fails if the OpenAPI spec is out of date.

## Versioning

Releases are fully automated via [knope](https://knope.tech) + GitHub CI. The only manual step is writing conventional commits — everything else happens automatically.

### Happy path
1. Write conventional commits (`feat:`, `fix:`, `feat!:`, etc.)
2. PR is merged to `main`
3. CI runs `.github/workflows/release.yml` which calls `knope release`
4. knope bumps versions in `Cargo.toml`, `Cargo.lock`, all `package.json` files, and writes `CHANGELOG.md`
5. knope commits `chore: prepare release N`, publishes to crates.io + npm, pushes the commit + tag, creates a GitHub release
6. The `chore: prepare release` commit triggers CI again but is skipped by the `if: !startsWith(...)` guard

### Rules
- **NEVER manually edit version numbers** — knope manages `Cargo.toml`, `Cargo.lock`, and all `package.json` files
- **NEVER run `knope release` locally** — use `knope release --dry-run` to preview
- All Rust crates and npm packages share a **single unified version** via `knope.toml`
- `feat:` → minor bump, `fix:` → patch bump, `feat!:` / `fix!:` / `BREAKING CHANGE:` → major bump

### Partial release recovery
If CI publishes to crates.io/npm but fails before pushing the version commit and tag (e.g., "crate already exists" on a re-run):
1. Manually bump all version files to N
2. Commit as `chore: prepare release N`
3. Open a PR, merge it
4. Push the tag: `git tag vN <squash-sha> && git push origin vN`
5. Open a `fix:` PR to trigger the next version

## Conventions

- **Always use Bun** — `bun install`, `bun run`, etc. Never use npm or yarn for running scripts
- **npm publish uses npm CLI** — the release workflow uses `npm publish --provenance` (not `bun publish`) because only the npm CLI supports OIDC trusted publishing; no NPM_TOKEN is required
- **Conventional commits** for all commit messages — this directly drives automated versioning
- **Biome** for TypeScript linting/formatting (not ESLint)
- **`cargo fmt` + `cargo clippy`** for Rust
- **`yauth_` table prefix** on all database tables
- **Configurable PG schema** — use `DieselBackend::with_schema(url, "auth")` to isolate yauth tables in a separate PostgreSQL schema (default `"public"`).
- **Timing-safe patterns** — dummy password hash on failed lookups to prevent timing attacks
- **HIBP k-anonymity** — password breach checking via HaveIBeenPwned API (configurable)
- **Rate limiting** — per-operation rate limits (login, register, forgot-password, etc.)
- **Event system** — `AuthEvent` enum emitted on all auth operations for plugin interception

## Telemetry

Uses native OpenTelemetry SDK (no `tracing` crate). Key points:
- `opentelemetry` + `opentelemetry_sdk` + `opentelemetry-otlp` for Rust spans (direct SDK, no tracing bridge)
- Errors/warnings in request handlers are OTel **span events** (not disconnected logs) — visible in Honeycomb trace waterfall
- `crate::otel` helper module provides `record_error()`, `add_event()`, `set_attribute()`, `with_span()` — all compile to no-ops when `telemetry` feature is disabled
- `telemetry::init()` registers `TraceContextPropagator` for W3C traceparent/tracestate propagation
- `telemetry::layer::trace_middleware` creates native OTel server spans with context attached via `cx.attach()` and stored in request extensions
- Operational logging uses `log` crate (not `tracing`) — library does NOT init a log subscriber
- `@opentelemetry/sdk-trace-web` for frontend
- CORS must include `traceparent` and `tracestate` headers
- Health checks excluded from tracing
