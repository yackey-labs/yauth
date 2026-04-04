# yauth

Modular, plugin-based authentication library for Rust (Axum) with a generated TypeScript client and SolidJS UI components.

Every feature is behind a **feature flag** — enable only what you need.

## Features

| Feature | Description | When to use |
|---------|-------------|-------------|
| `email-password` | Registration, login, email verification, forgot/reset/change password, HIBP breach checking, configurable password policy | Default auth for most apps |
| `passkey` | WebAuthn registration and passwordless login | When you want passwordless/biometric login |
| `mfa` | TOTP setup/verify with backup codes; intercepts login flow via event system | When you need 2FA for sensitive accounts |
| `oauth` | OAuth2 client — multi-provider linking (Google, GitHub, etc.) | When users should sign in with external providers |
| `bearer` | JWT access/refresh tokens with token family tracking (reuse detection) | When API clients need stateless auth tokens |
| `api-key` | Scoped API key generation with optional expiration | When third-party integrations or scripts need long-lived credentials |
| `magic-link` | Passwordless email login with optional signup | When you want frictionless email-based auth |
| `admin` | User management, ban/unban, session management, impersonation | When you need a back-office admin panel |
| `status` | Protected endpoint listing enabled plugins | When you want a settings/admin page to show active auth features |
| `oauth2-server` | Full OAuth2 authorization server (authorization code + PKCE, device flow, client credentials, dynamic registration, token introspection + revocation) | When yauth is the identity provider for other apps |
| `account-lockout` | Brute-force protection with exponential backoff, unlock via email or admin | When you need per-account lockout beyond IP rate limiting |
| `webhooks` | HMAC-signed HTTP callbacks on auth events with retry + delivery history | When external systems need real-time auth event notifications |
| `oidc` | OpenID Connect Provider — id_token issuance, OIDC discovery, JWKS, /userinfo | When downstream apps need OIDC-compliant SSO |
| `telemetry` | Native OpenTelemetry SDK instrumentation | When you need distributed tracing |
| `openapi` | utoipa OpenAPI spec generation for client codegen | When you need to generate or update the TypeScript client |
| `redis` | Redis caching decorator — wraps repository traits for sub-ms lookups | Multi-replica deployments, high-traffic apps |
| `diesel-pg-backend` | PostgreSQL backend via diesel-async + deadpool | Production Postgres deployments (default) |
| `diesel-libsql-backend` | SQLite/Turso backend via diesel-libsql | Local dev, embedded apps, Turso edge databases |
| `memory-backend` | Fully in-memory backend (no database) | Unit tests, prototyping, CI |
| `full` | All of the above | Development/testing |

`email-password` is enabled by default.

## Try It in 30 Seconds

No database needed. Copy, paste, run:

```rust
use yauth::prelude::*;
use yauth::backends::memory::InMemoryBackend;

#[tokio::main]
async fn main() {
    let yauth = YAuthBuilder::new(InMemoryBackend::new(), YAuthConfig::default())
        .with_email_password(EmailPasswordConfig {
            require_email_verification: false,
            ..Default::default()
        })
        .build()
        .await
        .unwrap();

    let app = axum::Router::new()
        .nest("/auth", yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

```bash
# Register
curl -X POST http://localhost:3000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"MyPassword123!"}'

# Login
curl -X POST http://localhost:3000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"MyPassword123!"}'
```

## Quick Start

### 1. Backend (Rust/Axum)

```bash
cargo add yauth --features email-password
cargo add tokio --features full
cargo add axum
```

```rust
use yauth::prelude::*;
use yauth::repo::{DatabaseBackend, EnabledFeatures};
use yauth::backends::diesel_pg::DieselBackend;
use axum::Router;

#[tokio::main]
async fn main() {
    let backend = DieselBackend::new("postgres://user:pass@localhost/mydb")
        .expect("Failed to create backend");

    // Run migrations (creates yauth_* tables)
    backend.migrate(&EnabledFeatures::from_compile_flags()).await.unwrap();

    let config = YAuthConfig {
        base_url: "http://localhost:3000".into(),
        ..Default::default()
    };

    let yauth = YAuthBuilder::new(backend, config)
        .with_email_password(EmailPasswordConfig::default())
        .build()
        .await
        .expect("Failed to build YAuth");

    let app = Router::new()
        .nest("/api/auth", yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### 2. Frontend (TypeScript)

```bash
bun add @yackey-labs/yauth-client
```

```typescript
import { createYAuthClient } from "@yackey-labs/yauth-client";

const auth = createYAuthClient({ baseUrl: "/api/auth" });

// Register
await auth.emailPassword.register({ email: "user@example.com", password: "s3cure!Pass" });

// Login
await auth.emailPassword.login({ email: "user@example.com", password: "s3cure!Pass" });

// Check session
const user = await auth.getSession();
console.log(user.email); // "user@example.com"

// Logout
await auth.logout();
```

### 3. Pre-built UI (optional)

#### Vue 3

```bash
bun add @yackey-labs/yauth-ui-vue
```

**Install the plugin** in your app entry (`main.ts`):

```typescript
import { createApp } from "vue";
import { YAuthPlugin } from "@yackey-labs/yauth-ui-vue";
import App from "./App.vue";

createApp(App)
  .use(YAuthPlugin, { baseUrl: "/api/auth" })
  .mount("#app");
```

**Login page** — the `LoginForm` component handles email/password and emits `@success` when login succeeds:

```vue
<script setup lang="ts">
import { LoginForm } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const router = useRouter();
</script>

<template>
  <LoginForm @success="router.push('/dashboard')" />
</template>
```

**Dashboard page** — use the `useSession()` composable to access the current user:

```vue
<script setup lang="ts">
import { useSession, useAuth } from "@yackey-labs/yauth-ui-vue";

const { user, isAuthenticated, loading } = useSession();
const { logout } = useAuth();
</script>

<template>
  <div v-if="loading">Loading...</div>
  <div v-else-if="isAuthenticated">
    <p>Logged in as {{ user?.email }}</p>
    <button @click="logout">Logout</button>
  </div>
  <div v-else>Not logged in</div>
</template>
```

**Composables reference:**

| Composable | Returns | Use for |
|------------|---------|---------|
| `useYAuth()` | `{ client, user, loading, refetch }` | Direct client access |
| `useAuth()` | `{ user, loading, error, submitting, login, register, logout, forgotPassword, resetPassword, changePassword }` | Auth actions with error/loading state |
| `useSession()` | `{ user, loading, isAuthenticated, isEmailVerified, logout }` | Reactive session state checks |

**Component props and events:**

| Component | Props | Events |
|-----------|-------|--------|
| `LoginForm` | `showPasskey?: boolean` | `@success`, `@mfa-required(pendingSessionId)` |
| `RegisterForm` | — | `@success(message)` |
| `ForgotPasswordForm` | — | `@success(message)` |
| `ResetPasswordForm` | `token: string` | `@success(message)` |
| `ChangePasswordForm` | — | `@success(message)` |
| `VerifyEmail` | `token: string` | `@success(message)` |
| `MfaChallenge` | `pendingSessionId: string` | `@success` |
| `MfaSetup` | — | `@complete` |
| `PasskeyButton` | `mode: "login" \| "register"`, `email?: string` | `@success` |
| `OAuthButtons` | `providers: string[]` | — |
| `MagicLinkForm` | — | `@success(message)` |
| `ProfileSettings` | — | — |

**`AuthUser` type** (returned by `getSession()` and available in composables):

```typescript
interface AuthUser {
  id: string;
  email: string;
  display_name: string | null;
  email_verified: boolean;
  role: string;
  auth_method: "Session" | "Bearer" | "ApiKey";
}
```

#### SolidJS

```bash
bun add @yackey-labs/yauth-ui-solidjs
```

```tsx
import { YAuthProvider, LoginForm } from "@yackey-labs/yauth-ui-solidjs";

function App() {
  return (
    <YAuthProvider baseUrl="/api/auth">
      <LoginForm onSuccess={() => navigate("/dashboard")} />
    </YAuthProvider>
  );
}
```

Access the session in any child component:

```tsx
import { useYAuth } from "@yackey-labs/yauth-ui-solidjs";

function Dashboard() {
  const { user, refetch } = useYAuth();
  return <p>Logged in as {user()?.email}</p>;
}
```

### Adding more features

Enable additional plugins with feature flags:

```bash
cargo add yauth --features email-password,passkey,mfa,oauth
```

```rust
let yauth = YAuthBuilder::new(backend, config)
    .with_email_password(EmailPasswordConfig::default())
    .with_passkey(PasskeyConfig {
        rp_id: "myapp.example.com".into(),
        rp_origin: "https://myapp.example.com".into(),
        rp_name: "My App".into(),
    })
    .with_mfa(MfaConfig::default())
    .with_oauth(OAuthConfig {
        providers: vec![/* Google, GitHub, etc. */],
    })
    .build()
    .await?;
```

All new endpoints are automatically available on the client — no regeneration needed if you use the pre-built `@yackey-labs/yauth-client` package.

### Choose Your Backend

#### PostgreSQL (default)

```rust
use yauth::backends::diesel_pg::DieselBackend;

let backend = DieselBackend::new("postgres://user:pass@localhost/mydb")?;
// Or with a custom PostgreSQL schema:
let backend = DieselBackend::with_schema("postgres://user:pass@localhost/mydb", "auth")?;

let yauth = YAuthBuilder::new(backend, config).build().await?;
```

#### SQLite / Turso (diesel-libsql)

```bash
cargo add yauth --features email-password,diesel-libsql-backend --no-default-features
```

```rust
use yauth::backends::diesel_libsql::DieselLibsqlBackend;

// Local SQLite file
let backend = DieselLibsqlBackend::new("file:yauth.db")?;
// In-memory SQLite
let backend = DieselLibsqlBackend::new(":memory:")?;
// Remote Turso (set LIBSQL_AUTH_TOKEN env var)
let backend = DieselLibsqlBackend::new("libsql://your-db.turso.io")?;

let yauth = YAuthBuilder::new(backend, config).build().await?;
```

#### In-Memory (no database)

```bash
cargo add yauth --features email-password,memory-backend --no-default-features
```

```rust
use yauth::backends::memory::InMemoryBackend;

let backend = InMemoryBackend::new();
let yauth = YAuthBuilder::new(backend, config).build().await?;
```

### Redis Caching

Redis wraps repository traits as a caching decorator. The database remains the source of truth.

```bash
cargo add yauth --features email-password,redis
```

```rust
let redis_client = redis::Client::open("redis://127.0.0.1:6379")?;
let redis_conn = redis_client.get_connection_manager().await?;

let yauth = YAuthBuilder::new(backend, config)
    .with_redis(redis_conn)  // caches sessions, rate limits, challenges, revocation
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

## Architecture

### Plugin System

Plugins implement the `YAuthPlugin` trait:

- `public_routes()` — unauthenticated endpoints (login, register, etc.)
- `protected_routes()` — endpoints behind auth middleware
- `on_event()` — react to auth events (e.g., MFA intercepts login, account lockout blocks login)

Custom plugins can be added via `builder.with_plugin(Box::new(MyPlugin))`.

### Tri-Mode Auth Middleware

Every protected route checks credentials in order:

1. **Session cookie** — `CookieJar` → `validate_session()`
2. **Bearer token** — `Authorization: Bearer <jwt>` → JWT validation (requires `bearer` feature)
3. **API key** — `X-Api-Key: <key>` → key hash lookup (requires `api-key` feature)

The authenticated user is injected as `Extension<AuthUser>` with fields: `id`, `email`, `display_name`, `email_verified`, `role`, `banned`, `auth_method`, and `scopes`.

### Event System

All auth operations emit an `AuthEvent`:

- `UserRegistered`, `LoginSucceeded`, `LoginFailed`, `SessionCreated`, `Logout`
- `PasswordChanged`, `EmailVerified`
- `MfaEnabled`, `MfaDisabled`
- `UserBanned`, `UserUnbanned`
- `MagicLinkSent`, `MagicLinkVerified`
- `AccountLocked`, `AccountUnlocked`
- `WebhookDelivered`

Plugins respond with `Continue`, `RequireMfa { pending_session_id }`, or `Block { status, message }`.

## Configuration Guide

### Session Binding

Detects session hijacking by binding sessions to client IP and/or User-Agent. Configure in `YAuthConfig`:

- `bind_ip: true` — track client IP at session creation
- `bind_user_agent: true` — track User-Agent at session creation
- `BindingAction::Warn` — log mismatch but allow access
- `BindingAction::Invalidate` — destroy session on mismatch (forces re-auth)

**When to use:** Enable `Warn` by default; use `Invalidate` for high-security applications. Note that `bind_ip` may cause issues with mobile users or VPN changes.

### Remember Me

Set `remember_me_ttl` on `YAuthConfig` to enable longer sessions when users opt in. The login request accepts a `remember_me: true` field.

**When to use:** When you want short default sessions (e.g., 24h) with opt-in long sessions (e.g., 30d) via a "keep me logged in" checkbox.

### Password Policy

Configure `PasswordPolicyConfig` on `EmailPasswordConfig`:

- `require_uppercase`, `require_lowercase`, `require_digit`, `require_special` — character class requirements
- `max_length` — maximum password length (default: 128)
- `disallow_common_passwords` — reject top common passwords
- `password_history_count` — prevent reuse of last N passwords (0 = disabled)

**When to use:** When regulatory compliance or security policy requires specific password complexity rules beyond minimum length + HIBP checking.

### Account Lockout

Configure `AccountLockoutConfig`:

- `max_failed_attempts` — threshold before lockout (default: 5)
- `lockout_duration` — base lockout time (default: 5 minutes)
- `exponential_backoff` — double duration on each lockout
- `max_lockout_duration` — cap for backoff (default: 24 hours)
- `auto_unlock` — auto-unlock after duration expires

**When to use:** When you need per-account brute-force protection that works across IPs. Rate limiting is per-IP; account lockout is per-account. Use both together for defense in depth.

### Webhooks

Configure `WebhookConfig`:

- `max_retries` — retry failed deliveries (default: 3)
- `retry_delay` — delay between retries (default: 30s)
- `timeout` — HTTP timeout per delivery (default: 10s)
- `max_webhooks` — limit per user (default: 10)

Payloads are signed with HMAC-SHA256 via the `X-Webhook-Signature` header. Admin routes at `/webhooks` manage webhook CRUD.

**When to use:** When external systems (Slack bots, CRMs, analytics) need real-time notifications of auth events without polling.

### OIDC

Configure `OidcConfig`:

- `issuer` — OIDC issuer URL (must match `iss` claim)
- `id_token_ttl` — id_token expiry (default: 1 hour)
- `claims_supported` — advertised claims (default: sub, email, email_verified, name)

**When to use:** When yauth is the identity provider and downstream apps need OIDC-compliant SSO. Automatically enables `bearer` + `oauth2-server`.

## API Routes

### Core (always available)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/session` | Yes | Get authenticated user info |
| POST | `/logout` | Yes | Invalidate session |
| PATCH | `/me` | Yes | Update display name |

### Email/Password

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | No | Register with email + password |
| POST | `/login` | No | Authenticate (supports `remember_me` flag) |
| POST | `/verify-email` | No | Verify email token |
| POST | `/resend-verification` | No | Resend verification email |
| POST | `/forgot-password` | No | Request password reset |
| POST | `/reset-password` | No | Reset password with token |
| POST | `/change-password` | Yes | Change password |

### Passkey (WebAuthn)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/passkey/login/begin` | No | Start WebAuthn login challenge |
| POST | `/passkey/login/finish` | No | Complete WebAuthn login |
| POST | `/passkeys/register/begin` | Yes | Start passkey registration |
| POST | `/passkeys/register/finish` | Yes | Complete passkey registration |
| GET | `/passkeys` | Yes | List passkeys |
| DELETE | `/passkeys/{id}` | Yes | Delete passkey |

### MFA (TOTP + Backup Codes)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/mfa/verify` | No | Verify MFA code during login |
| POST | `/mfa/totp/setup` | Yes | Generate TOTP secret + backup codes |
| POST | `/mfa/totp/confirm` | Yes | Confirm TOTP setup |
| DELETE | `/mfa/totp` | Yes | Disable TOTP |
| GET | `/mfa/backup-codes` | Yes | Get backup code count |
| POST | `/mfa/backup-codes/regenerate` | Yes | Regenerate backup codes |

### OAuth (Client)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/oauth/{provider}/authorize` | No | Start OAuth flow |
| GET/POST | `/oauth/{provider}/callback` | No | OAuth callback |
| GET | `/oauth/accounts` | Yes | List connected accounts |
| DELETE | `/oauth/{provider}` | Yes | Unlink provider |
| POST | `/oauth/{provider}/link` | Yes | Link account to provider |

### Bearer Tokens (JWT)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/token` | No | Get access + refresh tokens |
| POST | `/token/refresh` | No | Refresh access token |
| POST | `/token/revoke` | Yes | Revoke refresh token |

### API Keys

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api-keys` | Yes | List API keys |
| POST | `/api-keys` | Yes | Create API key (optional scopes, expiry) |
| DELETE | `/api-keys/{id}` | Yes | Delete API key |

### Magic Link

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/magic-link/send` | No | Send magic link email |
| POST | `/magic-link/verify` | No | Verify magic link token |

### Status

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/status` | Yes | List enabled plugin names |

### Admin

All admin routes require `role = "admin"`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users` | List users (paginated, searchable) |
| GET | `/admin/users/{id}` | Get user details |
| PUT | `/admin/users/{id}` | Update user |
| DELETE | `/admin/users/{id}` | Delete user |
| POST | `/admin/users/{id}/ban` | Ban user |
| POST | `/admin/users/{id}/unban` | Unban user |
| POST | `/admin/users/{id}/impersonate` | Create session as user |
| GET | `/admin/sessions` | List sessions |
| DELETE | `/admin/sessions/{id}` | Terminate session |

### OAuth2 Server

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| GET | `/oauth/authorize` | Authorization endpoint (JSON or redirect to consent UI) |
| POST | `/oauth/authorize` | Consent submission (JSON or form-urlencoded) |
| POST | `/oauth/token` | Token endpoint — authorization_code, refresh_token, client_credentials (RFC 6749) |
| POST | `/oauth/introspect` | Token introspection (RFC 7662) |
| POST | `/oauth/revoke` | Token revocation (RFC 7009) |
| POST | `/oauth/register` | Dynamic client registration (RFC 7591) |
| POST | `/oauth/device/code` | Device authorization request (RFC 8628) |
| GET/POST | `/oauth/device` | Device verification |

Supported grant types: `authorization_code` (with PKCE S256), `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:device_code`.

### Account Lockout

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/account/request-unlock` | No | Request unlock email |
| POST | `/account/unlock` | No | Unlock account with token |
| POST | `/admin/users/{id}/unlock` | Yes (admin) | Admin force-unlock |

### Webhooks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/webhooks` | Yes | Create webhook |
| GET | `/webhooks` | Yes | List webhooks |
| GET | `/webhooks/{id}` | Yes | Get webhook with delivery history |
| PUT | `/webhooks/{id}` | Yes | Update webhook |
| DELETE | `/webhooks/{id}` | Yes | Delete webhook |
| POST | `/webhooks/{id}/test` | Yes | Send test delivery |

### OIDC

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/openid-configuration` | No | OIDC discovery document |
| GET | `/.well-known/jwks.json` | No | JSON Web Key Set |
| GET/POST | `/userinfo` | Yes | OIDC UserInfo endpoint |

## TypeScript Packages

### @yackey-labs/yauth-client

HTTP client auto-generated from the OpenAPI spec via `utoipa` + `orval`.

```typescript
import { createYAuthClient } from "@yackey-labs/yauth-client";

const auth = createYAuthClient({ baseUrl: "https://myapp.example.com/auth" });

// Email/password
await auth.emailPassword.register({ email, password });
await auth.emailPassword.login({ email, password, remember_me: true });

// Session
const user = await auth.getSession();
await auth.logout();

// Webhooks, account lockout, OIDC, OAuth2 server, passkey, MFA, etc.
// — all available as namespaced methods on the client
```

### @yackey-labs/yauth-shared

Shared TypeScript types (`AuthUser`, `AuthSession`, etc.) and an AAGUID authenticator map.

### @yackey-labs/yauth-ui-vue

Pre-built Vue 3 components and composables:

- `YAuthPlugin` / `useYAuth()` — Vue plugin (accepts `client` or `baseUrl`)
- `useAuth()` — composable for auth actions (login, register, logout, etc.)
- `useSession()` — composable for reactive session state (`user`, `isAuthenticated`, `loading`)
- `LoginForm`, `RegisterForm`, `ForgotPasswordForm`, `ResetPasswordForm`
- `ChangePasswordForm`, `VerifyEmail`, `ProfileSettings`
- `PasskeyButton`, `OAuthButtons`
- `MfaSetup`, `MfaChallenge`
- `MagicLinkForm`

Components check for feature availability — if a feature group isn't present on the client, the component gracefully renders nothing.

### @yackey-labs/yauth-ui-solidjs

Pre-built SolidJS components:

- `YAuthProvider` / `useYAuth()` — context provider (accepts `client` or `baseUrl`)
- Same component set as Vue: `LoginForm`, `RegisterForm`, `ProfileSettings`, etc.
- `ConsentScreen` — OAuth2 authorization consent UI

## Security

- **Argon2id** password hashing with timing-safe dummy hash on failed lookups
- **HaveIBeenPwned** k-anonymity password breach checking (fail-open)
- **Password policy** — configurable complexity, common password rejection, history tracking
- **Rate limiting** per operation (login, register, forgot-password, magic-link)
- **Account lockout** — per-account brute-force protection with exponential backoff
- **Session binding** — optional IP + User-Agent binding for hijacking detection
- **Session tokens** stored as SHA-256 hashes
- **JWT refresh token family tracking** — automatic revocation on reuse detection
- **CSRF protection** — HttpOnly + SameSite=Lax cookies; bearer/API key via headers
- **Email enumeration prevention** — consistent responses for non-existent accounts
- **Audit logging** — all auth events written to `yauth_audit_log` table
- **WebAuthn challenge TTL** — 5-minute expiry with credential exclusion
- **Webhook signing** — HMAC-SHA256 signatures for payload integrity
- **PKCE S256** — required for all OAuth2 authorization code flows

## Database Backends

yauth uses a `DatabaseBackend` trait with pluggable implementations. All persistent data (users, passwords, sessions, API keys, etc.) is accessed through repository traits, making the auth logic fully database-agnostic.

| Backend | Feature Flag | Connection | Use case |
|---|---|---|---|
| `DieselBackend` | `diesel-pg-backend` (default) | PostgreSQL via diesel-async 0.8 + deadpool | Production |
| `DieselLibsqlBackend` | `diesel-libsql-backend` | Local SQLite / remote Turso via diesel-libsql 0.1.4 | Embedded, edge, local dev |
| `InMemoryBackend` | `memory-backend` | None (all data in HashMaps) | Tests, prototyping |

Migrations are explicit — call `backend.migrate()` before `build()`. Plugins declare tables as Rust data, and DDL is generated per dialect (Postgres, SQLite, MySQL) via the declarative schema system.

### Configurable PostgreSQL Schema

By default, yauth tables live in the `public` schema. Use `DieselBackend::with_schema()` to isolate them:

```rust
let backend = DieselBackend::with_schema(&database_url, "auth")?;
```

### Redis Caching

Enable the `redis` feature for Redis-backed caching of sessions, rate limits, challenges, and JTI revocation:

```bash
cargo add yauth --features email-password,redis
```

```rust
let redis_client = redis::Client::open("redis://127.0.0.1:6379")?;
let redis_conn = redis_client.get_connection_manager().await?;

let yauth = YAuthBuilder::new(backend, config)
    .with_redis(redis_conn)  // wraps repo traits with Redis caching
    .with_email_password(EmailPasswordConfig::default())
    .build()
    .await?;
```

`.with_redis()` adds a caching layer around repository operations for sessions, rate limits, challenges, and token revocation. The database backend remains the source of truth.

**When to use Redis:** multi-replica deployments (shared sessions), high-traffic apps (sub-millisecond session lookups), or when you need instant JWT revocation across all nodes.

See [docs/migrating-to-diesel.md](docs/migrating-to-diesel.md) for a migration guide if upgrading from yauth v0.1.x (which supported SeaORM).

## Database Schema

All tables are prefixed with `yauth_`. Migrations are feature-gated — only tables for enabled features are created.

Migrations are explicit — call `backend.migrate()` when and where you want:

```rust
// At app startup
let backend = DieselPgBackend::new(&database_url)?;
backend.migrate(&EnabledFeatures::from_compile_flags()).await?;
```

```rust
// Or in CI / init container / CLI tool — same call, different context
let backend = DieselPgBackend::new(&database_url)?;
backend.migrate(&EnabledFeatures::from_compile_flags()).await?;
// No need to build YAuth — just run migrations and exit
```

```rust
// Or export DDL for your own migration tool (Flyway, Liquibase, sqlx, etc.)
let ddl = yauth.generate_ddl(Dialect::Postgres)?;
```

### Schema by Plugin

Only the tables for your enabled features are created. Core tables are always present.

#### Core (always)

| Table | Description |
|-------|-------------|
| `yauth_users` | `id` (uuid), `email`, `display_name`, `email_verified`, `role`, `banned`, `banned_reason`, `banned_until`, `created_at`, `updated_at` |
| `yauth_sessions` | `id` (uuid), `user_id` → users, `token_hash`, `ip_address`, `user_agent`, `expires_at`, `created_at` |
| `yauth_audit_log` | `id` (uuid), `user_id` → users, `event_type`, `metadata` (json), `ip_address`, `created_at` |

#### email-password

| Table | Description |
|-------|-------------|
| `yauth_passwords` | `user_id` → users (pk), `password_hash` |
| `yauth_email_verifications` | `id`, `user_id` → users, `token_hash`, `expires_at`, `created_at` |
| `yauth_password_resets` | `id`, `user_id` → users, `token_hash`, `expires_at`, `used_at`, `created_at` |

#### passkey

| Table | Description |
|-------|-------------|
| `yauth_webauthn_credentials` | `id`, `user_id` → users, `name`, `aaguid`, `device_name`, `credential` (json), `created_at`, `last_used_at` |

#### mfa

| Table | Description |
|-------|-------------|
| `yauth_totp_secrets` | `id`, `user_id` → users (unique), `encrypted_secret`, `verified`, `created_at` |
| `yauth_backup_codes` | `id`, `user_id` → users, `code_hash`, `used`, `created_at` |

#### oauth

| Table | Description |
|-------|-------------|
| `yauth_oauth_accounts` | `id`, `user_id` → users, `provider`, `provider_user_id`, `access_token_enc`, `refresh_token_enc`, `expires_at`, `updated_at`, `created_at` |
| `yauth_oauth_states` | `state` (pk), `provider`, `redirect_url`, `expires_at`, `created_at` |

#### bearer

| Table | Description |
|-------|-------------|
| `yauth_refresh_tokens` | `id`, `user_id` → users, `token_hash`, `family_id` (token rotation), `expires_at`, `revoked`, `created_at` |

#### api-key

| Table | Description |
|-------|-------------|
| `yauth_api_keys` | `id`, `user_id` → users, `key_prefix`, `key_hash`, `name`, `scopes` (json), `last_used_at`, `expires_at`, `created_at` |

#### magic-link

| Table | Description |
|-------|-------------|
| `yauth_magic_links` | `id`, `email`, `token_hash`, `expires_at`, `used`, `created_at` |

#### oauth2-server

| Table | Description |
|-------|-------------|
| `yauth_oauth2_clients` | `id`, `client_id`, `client_secret_hash`, `redirect_uris` (json), `client_name`, `grant_types` (json), `scopes` (json), `is_public`, `created_at` |
| `yauth_authorization_codes` | `id`, `code_hash`, `client_id`, `user_id` → users, `scopes` (json), `redirect_uri`, `code_challenge`, `code_challenge_method`, `nonce`, `expires_at`, `used`, `created_at` |
| `yauth_consents` | `id`, `user_id` → users, `client_id`, `scopes` (json), `created_at` — unique (user_id, client_id) |
| `yauth_device_codes` | `id`, `device_code_hash`, `user_code`, `client_id`, `scopes` (json), `user_id` → users, `status`, `interval`, `expires_at`, `last_polled_at`, `created_at` |

#### account-lockout

| Table | Description |
|-------|-------------|
| `yauth_account_locks` | `id`, `user_id` → users (unique), `failed_count`, `locked_until`, `lock_count`, `locked_reason`, `created_at`, `updated_at` |
| `yauth_unlock_tokens` | `id`, `user_id` → users, `token_hash`, `expires_at`, `created_at` |

#### webhooks

| Table | Description |
|-------|-------------|
| `yauth_webhooks` | `id`, `url`, `secret`, `events` (json), `active`, `created_at`, `updated_at` |
| `yauth_webhook_deliveries` | `id`, `webhook_id` → webhooks, `event_type`, `payload` (json), `status_code`, `response_body`, `success`, `attempt`, `created_at` |

#### oidc

| Table | Description |
|-------|-------------|
| `yauth_oidc_nonces` | `id`, `nonce_hash`, `authorization_code_id`, `created_at` |

Also adds a `nonce` column to `yauth_authorization_codes`.

Plugins without tables: `admin`, `status`, `telemetry`.

## Development

```bash
# Rust
cargo test --features full
cargo clippy --features full -- -D warnings
cargo fmt --check

# TypeScript
bun install
bun validate          # lint:fix + typecheck + build
bun generate          # regenerate TS client from Rust types
bun generate:check    # CI: fail if client is out of date

# Integration testing
docker compose up -d                 # PostgreSQL + Mailpit
bash pentest/pentest-yauth.sh        # 172+ OWASP security test cases
```

## Versioning

Automated via [knope](https://knope.tech) from conventional commits. Never manually edit version numbers. All Rust crates and npm packages share a single unified version.

## License

MIT
