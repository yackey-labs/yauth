# CLAUDE.md — yauth

## What This Is

`yauth` is a modular, plugin-based authentication library for Rust (Axum) with TypeScript client + SolidJS UI packages. It provides email/password, passkey (WebAuthn), MFA (TOTP + backup codes), OAuth, bearer tokens (JWT), API keys, and admin endpoints — all behind feature flags.

**Repo:** `github.com/yackey-labs/yauth`

## Workspace Structure

### Rust Crates (`crates/`)

| Crate | Purpose |
|---|---|
| `yauth` | Main library — plugins, middleware, builder, auth logic |
| `yauth-entity` | Diesel entities (all tables prefixed `yauth_`) |
| `yauth-migration` | Diesel migrations (feature-gated per plugin) |

### TypeScript Packages (`packages/`)

| Package | Purpose |
|---|---|
| `@yackey-labs/yauth-shared` | Shared types (`AuthUser`, `AuthSession`, AAGUID map) |
| `@yackey-labs/yauth-client` | HTTP client for all auth endpoints |
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

| Feature | What It Enables | Default |
|---|---|---|
| `diesel-async` | Diesel-async database backend (deadpool) | Yes |
| `email-password` | Registration, login, verification, forgot/reset/change password | Yes |
| `passkey` | WebAuthn registration + login | No |
| `mfa` | TOTP setup/verify + backup codes | No |
| `oauth` | OAuth2 provider linking | No |
| `bearer` | JWT access/refresh tokens | No |
| `api-key` | API key generation + validation | No |
| `admin` | User management, ban/unban, impersonation | No |
| `telemetry` | OpenTelemetry tracing bridge | No |
| `full` | All of the above | No |

Feature flags gate code in all three Rust crates (entity, migration, yauth) simultaneously.

## Architecture

### Plugin System

Plugins implement the `YAuthPlugin` trait:
- `public_routes()` — unauthenticated routes (login, register, etc.)
- `protected_routes()` — routes behind auth middleware (change password, passkey management, etc.)
- `on_event()` — react to auth events (MFA intercepts login, etc.)

### Builder Pattern

```rust
let yauth = YAuthBuilder::new(pool, config)
    .with_email_password(ep_config)
    .with_passkey(pk_config)
    .with_bearer(bearer_config)
    .with_mfa(mfa_config)
    .build();

let router = yauth.router();        // Axum Router<YAuthState>
let state = yauth.into_state();     // For app-level state sharing
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

This project uses `axfetchum` to auto-generate `@yackey-labs/yauth-client` from Rust types + route metadata.

**When modifying any API endpoint or request/response type:**
1. Update the route metadata in `crates/yauth/src/routes_meta.rs`
2. Ensure request/response types have `#[derive(TS)] #[ts(export)]`
3. Run `bun generate` to regenerate the TypeScript client
4. Commit the regenerated `packages/client/src/generated.ts` alongside Rust changes

**CI check:** `bun generate:check` (part of `bun validate:ci`) fails if the generated client is out of date.

## Versioning

- **Semantic versioning** is automated via [knope](https://knope.tech) + GitHub CI
- **NEVER manually edit version numbers** in `Cargo.toml`, `Cargo.lock`, or `package.json` — knope manages all of them from conventional commits
- **NEVER run `knope release` locally** — releases are triggered exclusively by pushing to `main` via CI (`.github/workflows/release.yml`)
- All Rust crates and npm packages share a **single unified version** managed by `knope.toml`
- `feat:` → minor bump, `fix:` → patch bump, `feat!:` / `fix!:` / `BREAKING CHANGE:` → major bump
- Pushing to `main` triggers: `knope release` → version bump + changelog + GitHub release + publish (Cargo + npm)
- The `chore: prepare release` commit pushed by the release job is skipped by the `if: !startsWith(...)` guard
- To preview what knope will do: `knope release --dry-run` (dry-run only, never run the real thing locally)

## Conventions

- **Always use Bun** — `bun install`, `bun publish`, `bun run`, etc. Never use npm or yarn
- **Conventional commits** for all commit messages — this directly drives automated versioning
- **Biome** for TypeScript linting/formatting (not ESLint)
- **`cargo fmt` + `cargo clippy`** for Rust
- **`yauth_` table prefix** on all database tables
- **Timing-safe patterns** — dummy password hash on failed lookups to prevent timing attacks
- **HIBP k-anonymity** — password breach checking via HaveIBeenPwned API (configurable)
- **Rate limiting** — per-operation rate limits (login, register, forgot-password, etc.)
- **Event system** — `AuthEvent` enum emitted on all auth operations for plugin interception

## Telemetry

Uses the honeycomb plugin for OTel instrumentation guidance. Key points:
- `tracing` + `tracing-opentelemetry` for Rust spans
- `@opentelemetry/sdk-trace-web` for frontend
- CORS must include `traceparent` and `tracestate` headers
- Health checks excluded from tracing
