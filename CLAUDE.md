# CLAUDE.md — yauth

## What This Is

`yauth` is a modular, plugin-based authentication library for Rust (Axum) with TypeScript client + SolidJS UI packages. It provides email/password, passkey (WebAuthn), MFA (TOTP + backup codes), OAuth, bearer tokens (JWT), API keys, and admin endpoints — all behind feature flags.

**Repo:** `forgejo.yackey.cloud/yauth/yauth`

## Workspace Structure

### Rust Crates (`crates/`)

| Crate | Purpose |
|---|---|
| `yauth` | Main library — plugins, middleware, builder, auth logic |
| `yauth-entity` | SeaORM entities (all tables prefixed `yauth_`) |
| `yauth-migration` | SeaORM migrations (feature-gated per plugin) |

### TypeScript Packages (`packages/`)

| Package | Purpose |
|---|---|
| `@yauth/shared` | Shared types (`AuthUser`, `AuthSession`, AAGUID map) |
| `@yauth/client` | HTTP client for all auth endpoints |
| `@yauth/ui-solidjs` | SolidJS components (LoginForm, RegisterForm, etc.) |

### Pentest Suite (`pentest/`)

`pentest-yauth.sh` — comprehensive OWASP security test suite (172+ cases).

## Key Commands

```bash
# Rust
cargo test --features full          # Run all unit tests (53)
cargo fmt --check                    # Format check
cargo clippy --features full -- -D warnings  # Lint

# TypeScript
bun install                          # Install dependencies
bun run build                        # Build all TS packages
bun run lint                         # Biome lint check
bun run lint:fix                     # Biome lint + fix
bun run typecheck                    # TypeScript type check
bun validate                         # lint:fix + typecheck + build
bun validate:ci                      # lint + typecheck + build (strict)

# Integration / Pentest
docker compose up -d                 # Start PostgreSQL + Mailpit
bash pentest/pentest-yauth.sh        # Run full pentest suite (172+ cases, 0 FAIL expected)
```

## Feature Flags

| Feature | What It Enables | Default |
|---|---|---|
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
let yauth = YAuthBuilder::new(db, config)
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

## Conventions

- **Conventional commits** for all commit messages
- **Biome** for TypeScript linting/formatting (not ESLint)
- **`cargo fmt` + `cargo clippy`** for Rust
- **`yauth_` table prefix** on all database tables
- **Timing-safe patterns** — dummy password hash on failed lookups to prevent timing attacks
- **HIBP k-anonymity** — password breach checking via HaveIBeenPwned API (configurable)
- **Rate limiting** — per-operation rate limits (login, register, forgot-password, etc.)
- **Event system** — `AuthEvent` enum emitted on all auth operations for plugin interception

## Telemetry

See `OTel_Rules.md` for full instrumentation conventions. Key points:
- `tracing` + `tracing-opentelemetry` for Rust spans
- `@opentelemetry/sdk-trace-web` for frontend
- CORS must include `traceparent` and `tracestate` headers
- Health checks excluded from tracing
