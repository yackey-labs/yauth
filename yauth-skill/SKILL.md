---
name: yauth
description: >
  Guide for integrating the yauth authentication library into Rust/Axum applications
  with SolidJS or Vue frontends. Covers Cargo setup with feature flags, YAuthBuilder
  configuration, database pool creation and migrations, auth middleware for protecting
  routes, and frontend UI components (YAuthProvider, LoginForm, RegisterForm, etc.).
  Use this skill whenever the user asks about yauth setup, yauth configuration,
  adding authentication to an Axum app with yauth, configuring yauth plugins
  (email-password, passkey, MFA, OAuth, bearer tokens, API keys, magic links,
  account lockout, webhooks, OAuth2 server, OIDC), using yauth frontend components
  in SolidJS or Vue, or troubleshooting yauth integration. Also trigger when you see
  yauth in Cargo.toml dependencies, imports like `use yauth::prelude::*`, or
  `@yackey-labs/yauth-client` / `@yackey-labs/yauth-ui-solidjs` / `@yackey-labs/yauth-ui-vue`
  in package.json.
metadata:
  version: "0.3.1"
---

# yauth Integration Guide

yauth is a modular, plugin-based authentication library for Rust (Axum) with TypeScript client and UI packages for SolidJS and Vue. Everything is behind feature flags — you only compile and run what you need.

**Packages:**
- **Rust:** `yauth` (crates.io) — core library with plugins, middleware, builder
- **TypeScript:** `@yackey-labs/yauth-client` (npm) — HTTP client for all auth endpoints
- **SolidJS:** `@yackey-labs/yauth-ui-solidjs` (npm) — pre-built auth components
- **Vue:** `@yackey-labs/yauth-ui-vue` (npm) — pre-built auth components

## Quick Start

The fastest path to a working auth system:

### 1. Add yauth to Cargo.toml

```toml
[dependencies]
yauth = { version = "0.3", features = ["email-password"] }
```

Pick the features you need — see the [Feature Flags](#feature-flags) section.

**Important:** There are no separate `yauth-entity` or `yauth-migration` crates. Those were discontinued and yanked — entity and migration modules are built into the `yauth` crate itself.

### 2. Set up the database pool and run migrations

```rust
use yauth::prelude::*;

let config = yauth::AsyncDieselConnectionManager::<yauth::AsyncPgConnection>::new(&database_url);
let pool = yauth::DieselPool::builder(config).build()?;

// Runs only the migrations for your enabled features — all idempotent
yauth::migration::diesel_migrations::run_migrations(&pool).await?;
```

For a custom PostgreSQL schema (e.g., isolating yauth tables under `auth`):

```rust
let yauth_config = yauth::config::YAuthConfig {
    db_schema: "auth".into(),
    ..Default::default()
};
let pool = yauth::create_pool(&database_url, &yauth_config)?;
yauth::migration::diesel_migrations::run_migrations_with_schema(&pool, "auth").await?;
```

### 3. Build the YAuth instance

```rust
let auth = YAuthBuilder::new(pool, yauth::config::YAuthConfig {
    base_url: "https://myapp.example.com".into(),
    session_cookie_name: "session".into(),
    session_ttl: Duration::from_secs(7 * 24 * 3600),
    secure_cookies: true,
    trusted_origins: vec!["https://myapp.example.com".into()],
    smtp: Some(yauth::config::SmtpConfig {
        host: "smtp.example.com".into(),
        port: 587,
        from: "noreply@example.com".into(),
    }),
    auto_admin_first_user: true,
    allow_signups: true,
    ..Default::default()
})
.with_email_password(yauth::config::EmailPasswordConfig::default())
.build();
```

### 4. Mount routes in your Axum app

```rust
let auth_state = auth.state().clone();

// Your own protected routes — AuthUser injected via Extension
let app_protected = Router::new()
    .route("/api/me", get(me_handler))
    .layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        yauth::middleware::auth_middleware,
    ));

let app = Router::new()
    .route("/api/health", get(health_handler))
    .merge(app_protected)
    .nest("/api/auth", auth.router())  // All yauth routes under /api/auth
    .with_state(auth_state);
```

### 5. Access the authenticated user in handlers

```rust
use yauth::middleware::AuthUser;

async fn me_handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    Json(json!({
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "auth_method": format!("{:?}", user.auth_method),
    }))
}
```

The auth middleware tries credentials in order: session cookie, then `Authorization: Bearer <jwt>`, then `X-Api-Key` header. The first valid credential wins.

### 6. Add frontend packages

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-solidjs
# or for Vue:
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-vue
```

See [Frontend Integration](#frontend-integration) for component usage.

---

## Feature Flags

Enable features in `Cargo.toml`. Each feature gates its own database tables, routes, and configuration.

| Feature | What It Enables | Needs Config? |
|---|---|---|
| `email-password` (default) | Registration, login, email verification, forgot/reset/change password | Yes: `EmailPasswordConfig` |
| `passkey` | WebAuthn registration + login | Yes: `PasskeyConfig` |
| `mfa` | TOTP setup/verify + backup codes | Yes: `MfaConfig` |
| `oauth` | OAuth2 provider linking (Google, GitHub, etc.) | Yes: `OAuthConfig` |
| `bearer` | JWT access/refresh tokens | Yes: `BearerConfig` |
| `api-key` | API key generation + validation via `X-Api-Key` header | No |
| `magic-link` | Passwordless email login | Yes: `MagicLinkConfig` |
| `admin` | User management, ban/unban, impersonation | No |
| `account-lockout` | Brute-force protection with exponential backoff | Yes: `AccountLockoutConfig` |
| `webhooks` | HTTP callbacks on auth events | Yes: `WebhookConfig` |
| `oauth2-server` | OAuth2 Authorization Server (auth codes, device flow) | Yes: `OAuth2ServerConfig` |
| `oidc` | OpenID Connect Provider (requires `bearer` + `oauth2-server`) | Yes: `OidcConfig` |
| `status` | Health check endpoint | No |
| `telemetry` | OpenTelemetry tracing bridge | No |
| `redis` | Redis store backend for sessions, rate limits, challenges | No (runtime config) |
| `full` | All of the above | — |

**Common combinations:**

```toml
# Web app with passwords + passkeys + MFA
yauth = { version = "0.3", features = ["email-password", "passkey", "mfa"] }

# API service with bearer tokens + API keys
yauth = { version = "0.3", features = ["email-password", "bearer", "api-key"] }

# Full-featured auth server
yauth = { version = "0.3", features = ["full"] }
```

---

## Plugin Configuration Reference

For detailed configuration structs and all their fields/defaults, read `references/plugin-configs.md`.

The reference covers every plugin's config struct, all fields, types, and default values. Consult it when you need to customize a specific plugin beyond the defaults.

### Builder Pattern Summary

Each plugin that needs configuration has a `with_*` method on `YAuthBuilder`:

```rust
let auth = YAuthBuilder::new(pool, config)
    .with_email_password(EmailPasswordConfig { ... })
    .with_passkey(PasskeyConfig { ... })
    .with_mfa(MfaConfig { ... })
    .with_bearer(BearerConfig { ... })
    .with_oauth(OAuthConfig { ... })
    .with_magic_link(MagicLinkConfig { ... })
    .with_oauth2_server(OAuth2ServerConfig { ... })
    .with_account_lockout(AccountLockoutConfig { ... })
    .with_webhooks(WebhookConfig { ... })
    .with_oidc(OidcConfig { ... })
    // Stateless plugins — no config needed
    .with_api_key()
    .with_admin()
    .with_status()
    // Store backend
    .with_redis(redis_conn)  // or .with_redis_prefixed(conn, "myapp:")
    .build();
```

Only call the `with_*` methods for plugins you've enabled via feature flags.

---

## YAuthConfig (Core Configuration)

```rust
yauth::config::YAuthConfig {
    base_url: String,                    // Public-facing URL of your app
    session_cookie_name: String,         // Cookie name (default: "session")
    session_ttl: Duration,               // Session lifetime (default: 7 days)
    cookie_domain: CookieDomainPolicy,   // Auto (default) or Explicit("example.com")
    secure_cookies: bool,                // Require HTTPS (default: false)
    trusted_origins: Vec<String>,        // CORS/CSRF origins
    smtp: Option<SmtpConfig>,            // Email sending (None = disabled)
    auto_admin_first_user: bool,         // First registered user gets admin role
    allow_signups: bool,                 // Global signup kill-switch (default: true)
    remember_me_ttl: Option<Duration>,   // Extended session for "remember me"
    session_binding: SessionBindingConfig, // IP/UA binding for session security
    db_schema: String,                   // PostgreSQL schema (default: "public")
}
```

**Important notes:**
- Set `secure_cookies: true` in production (HTTPS required)
- `trusted_origins` must include your frontend's origin for CSRF protection
- `cookie_domain: CookieDomainPolicy::Explicit("example.com".into())` enables cross-subdomain cookie sharing
- `smtp` is required for email verification, forgot password, and magic links to actually send emails
- `db_schema` lets you isolate yauth tables (e.g., `"auth"`) — use `yauth::create_pool()` to get a pool with the correct `search_path`

---

## Store Backends

yauth uses pluggable stores for four categories of ephemeral data. The store backend you choose applies to all four:

| Store | What It Holds | Lifetime |
|---|---|---|
| **Sessions** | Session tokens, user bindings, expiry | Hours to days |
| **Rate limits** | Per-operation counters (login, register, etc.) | Seconds to minutes |
| **Challenges** | CSRF tokens, WebAuthn challenges, MFA state | Seconds to minutes |
| **Revocations** | Revoked JWT token IDs (JTI blocklist) | Until token expiry |

### Three backend options

**Memory** (default) — in-process `HashMap`s, no persistence. Data is lost on restart. Fine for single-instance development, but not suitable for production or multi-instance deployments.

```rust
// Memory is the default — no extra config needed
let auth = YAuthBuilder::new(pool, config)
    .build();
```

**Postgres** — uses the same database pool. Sessions go in the regular `yauth_sessions` table. Rate limits, challenges, and revocations use **`UNLOGGED` tables** (`yauth_rate_limits`, `yauth_challenges`, `yauth_revocations`) — these are faster than regular tables because they skip WAL, but data is lost on a Postgres crash (which is fine for ephemeral data). Tables are created automatically on first use.

```rust
let auth = YAuthBuilder::new(pool, config)
    .with_store_backend(StoreBackend::Postgres)
    .build();
```

**Redis** — requires the `redis` feature flag. All ephemeral data stored in Redis with TTL-based expiry. Best for multi-instance production deployments where you need shared state without database load. Supports a key prefix for multi-tenant isolation.

```rust
// In Cargo.toml: yauth = { version = "0.3", features = ["email-password", "redis"] }

let client = redis::Client::open("redis://127.0.0.1/")?;
let conn = client.get_connection_manager().await?;

let auth = YAuthBuilder::new(pool, config)
    .with_redis(conn)
    // Or with a key prefix for multi-tenant deployments:
    // .with_redis_prefixed(conn, "myapp:")
    .build();
```

### Which to use

- **Dev / single instance:** Memory (default) or Postgres
- **Production without Redis:** Postgres — zero extra infra, unlogged tables keep it fast
- **Production with Redis available:** Redis — shared state across processes, minimal latency, and works for both single- and multi-instance deployments

---

## Frontend Integration

Both Vue and SolidJS UI packages share the same component set. They all use `@yackey-labs/yauth-client` under the hood.

**Available components** (same in both frameworks):

| Component | Purpose | Key Props |
|---|---|---|
| `LoginForm` | Email/password login | `onSuccess`, `onMfaRequired`, `onError`, `showPasskey` |
| `RegisterForm` | User registration | `onSuccess`, `onError` |
| `ForgotPasswordForm` | Request password reset | `onSuccess` |
| `ResetPasswordForm` | Reset with token | `token`, `onSuccess` |
| `ChangePasswordForm` | Change current password | `onSuccess`, `onError` |
| `VerifyEmail` | Auto-verify on mount | `token`, `onSuccess`, `onError` |
| `MfaChallenge` | TOTP code input during login | `pendingSessionId`, `onSuccess`, `onError` |
| `MfaSetup` | 3-step MFA enrollment | `onComplete` (receives backup codes) |
| `PasskeyButton` | WebAuthn login/register | `mode`, `email`, `onSuccess`, `onError` |
| `OAuthButtons` | OAuth provider buttons | `providers` (e.g., `["google", "github"]`) |
| `MagicLinkForm` | Passwordless email login | `onSuccess` |
| `ProfileSettings` | Full profile management | *(no props — self-contained)* |
| `ConsentScreen` | OAuth2 consent UI | `clientId`, `scopes`, `redirectUri`, ... |

### Vue 3

Install the plugin and use components:

```typescript
import { createApp } from 'vue'
import { YAuthPlugin } from '@yackey-labs/yauth-ui-vue'

createApp(App)
  .use(YAuthPlugin, { baseUrl: '/api/auth' })
  .mount('#app')
```

**Composables:**

```typescript
import { useAuth, useSession, useYAuth } from '@yackey-labs/yauth-ui-vue'

// useYAuth — raw client + reactive user
const { client, user, loading, refetch } = useYAuth()

// useAuth — high-level actions with built-in error/submitting state
const { login, register, logout, forgotPassword, resetPassword, changePassword, error, submitting } = useAuth()

// useSession — reactive computed properties for templates
const { isAuthenticated, isEmailVerified, userEmail, userRole, displayName } = useSession()
```

**Example pages:**

```vue
<!-- LoginPage.vue -->
<script setup>
import { ref } from 'vue'
import { LoginForm, MfaChallenge } from '@yackey-labs/yauth-ui-vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const mfaPending = ref<string | null>(null)
</script>

<template>
  <MfaChallenge v-if="mfaPending" :pendingSessionId="mfaPending"
    @success="router.push('/dashboard')" />
  <LoginForm v-else
    @success="router.push('/dashboard')"
    @mfa-required="(id) => mfaPending = id" />
</template>
```

```vue
<!-- DashboardPage.vue -->
<script setup>
import { useSession } from '@yackey-labs/yauth-ui-vue'
const { isAuthenticated, displayName, userRole, logout } = useSession()
</script>

<template>
  <div v-if="isAuthenticated">
    <p>Welcome, {{ displayName }} ({{ userRole }})</p>
    <button @click="logout">Logout</button>
  </div>
  <router-link v-else to="/login">Log in</router-link>
</template>
```

### SolidJS

Wrap your app in `YAuthProvider`:

```tsx
import { YAuthProvider } from "@yackey-labs/yauth-ui-solidjs";

function App() {
  return (
    <YAuthProvider baseUrl="/api/auth">
      <Router>
        <Route path="/login" component={LoginPage} />
        <Route path="/register" component={RegisterPage} />
        <Route path="/dashboard" component={DashboardPage} />
      </Router>
    </YAuthProvider>
  );
}
```

**Using the auth context:**

```tsx
import { useYAuth } from "@yackey-labs/yauth-ui-solidjs";

function DashboardPage() {
  const { client, user, loading } = useYAuth();

  return (
    <Show when={!loading()} fallback={<div>Loading...</div>}>
      <Show when={user()}>
        {(u) => <p>Logged in as {u().email}</p>}
      </Show>
    </Show>
  );
}
```

**MFA flow pattern:**

```tsx
function LoginPage() {
  const [mfaPending, setMfaPending] = createSignal<string | null>(null);

  return (
    <Show when={mfaPending()} fallback={
      <LoginForm
        onSuccess={(user) => navigate("/dashboard")}
        onMfaRequired={(sessionId) => setMfaPending(sessionId)}
      />
    }>
      {(sessionId) => (
        <MfaChallenge
          pendingSessionId={sessionId()}
          onSuccess={() => navigate("/dashboard")}
        />
      )}
    </Show>
  );
}
```

### Using the Client Directly

If you need lower-level control or a custom UI:

```typescript
import { createYAuthClient } from "@yackey-labs/yauth-client";

const client = createYAuthClient({
  baseUrl: "/api/auth",
  credentials: "include",  // Send session cookies
  // For bearer token auth:
  // getToken: async () => localStorage.getItem("token"),
  onError: (err) => console.error(err.status, err.message),
});

// All methods are grouped by feature:
await client.emailPassword.login({ email, password });
await client.emailPassword.register({ email, password });
await client.getSession();
await client.logout();
await client.passkey.loginBegin({ email });
await client.mfa.setup();
await client.apiKeys.create({ name: "My Key" });
await client.admin.listUsers({ page: 1, per_page: 20 });
```

### Styling

All UI components use **shadcn/ui-compatible** Tailwind CSS classes with CSS custom property theme tokens (`bg-primary`, `text-primary-foreground`, `bg-destructive`, `border-input`, `bg-muted`, `bg-accent`, `bg-background`, etc.). If your project already uses shadcn/ui (or any shadcn-based theme like shadcn-vue or shadcn-solid), the yauth components will inherit your theme automatically — no extra styling needed. If your project doesn't define these tokens, add them to your CSS or use a shadcn theme as a starting point.

---

## Auth Routes Reference

When yauth is mounted at `/api/auth`, these routes are available (depending on enabled features):

**Core (always):**
- `GET /config` — public auth configuration
- `GET /session` — current user (requires auth)
- `POST /logout` — destroy session (requires auth)
- `PATCH /me` — update profile (requires auth)

**Email-Password:**
- `POST /register`, `POST /login`, `POST /verify-email`, `POST /resend-verification`
- `POST /forgot-password`, `POST /reset-password`, `POST /change-password` (auth)

**Passkey:**
- `POST /passkey/login/begin`, `POST /passkey/login/finish`
- `POST /passkeys/register/begin` (auth), `POST /passkeys/register/finish` (auth)
- `GET /passkeys` (auth), `DELETE /passkeys/{id}` (auth)

**Bearer:** `POST /token`, `POST /token/refresh`, `POST /token/revoke` (auth)

**API Key:** `POST /api-keys` (auth), `GET /api-keys` (auth), `DELETE /api-keys/{id}` (auth)

**MFA:** `POST /mfa/setup` (auth), `POST /mfa/verify`, `POST /mfa/confirm` (auth), `POST /mfa/disable` (auth), backup code endpoints

**Magic Link:** `POST /magic-link/send`, `POST /magic-link/verify`

**OAuth:** `GET /oauth/authorize/{provider}`, `GET /oauth/callback/{provider}`, `GET /oauth/accounts` (auth), `DELETE /oauth/accounts/{provider}` (auth)

**Admin (admin role only):** `GET/PUT/DELETE /admin/users/{id}`, `POST /admin/users/{id}/ban`, `POST /admin/users/{id}/impersonate`, session management

**OAuth2 Server:** Authorization, token, introspect, revoke, device flow, client registration endpoints

**OIDC:** `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET/POST /userinfo`

---

## Development Setup

For local development, use docker compose to start PostgreSQL, Redis, and Mailpit (SMTP testing):

```bash
docker compose up -d
# Starts: postgres:17 (port 5433), redis:7 (port 6379), mailpit (SMTP 1026, UI 8026)

DATABASE_URL=postgres://yauth:yauth@127.0.0.1:5433/yauth_test \
  cargo run --example server --features full
```

**Key environment variables:**

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | *(required)* | PostgreSQL connection string |
| `PORT` | `3000` | Server listen port |
| `BASE_URL` | `http://localhost:3000` | Public-facing base URL |
| `JWT_SECRET` | `dev-secret-change-me` | HMAC secret for bearer JWTs |
| `SMTP_HOST` | *(none)* | SMTP host (enables email) |
| `PASSKEY_RP_ID` | `localhost` | WebAuthn Relying Party ID |
| `REDIS_URL` | *(none)* | Redis connection (enables Redis store) |
| `ALLOW_SIGNUPS` | `true` | Global signup toggle |

---

## Common Patterns

### Migration Ordering in Your App

yauth migrations should run **before** your app's migrations, in the same place — whether that's app startup, a separate migration binary, or a CI step. yauth tables need to exist first because your app's tables may reference them (e.g., foreign keys to `yauth_users`).

```rust
// In your migration binary or app startup
async fn run_all_migrations(pool: &DbPool) {
    // 1. yauth migrations FIRST — creates yauth_users, yauth_sessions, etc.
    yauth::migration::diesel_migrations::run_migrations(pool).await
        .expect("yauth migrations failed");

    // 2. Your app's migrations SECOND — can now reference yauth tables
    conn.run_pending_migrations(APP_MIGRATIONS).await
        .expect("app migrations failed");
}
```

Both systems coexist cleanly — yauth uses idempotent `CREATE TABLE IF NOT EXISTS` statements (no tracking table), while your app can use diesel-async's migration runner with its own tracking. They operate on different tables (`yauth_*` vs your app's tables).

### Custom Schema Isolation

Isolate yauth tables in their own PostgreSQL schema to avoid name conflicts:

```rust
let config = yauth::config::YAuthConfig {
    db_schema: "auth".into(),
    ..Default::default()
};
let pool = yauth::create_pool(&database_url, &config)?;
yauth::migration::diesel_migrations::run_migrations_with_schema(&pool, "auth").await?;
```

### Role-Based Access Control

```rust
// Require admin role on specific routes
let admin_routes = Router::new()
    .route("/api/admin/dashboard", get(admin_dashboard))
    .layer(axum::middleware::from_fn(yauth::middleware::require_admin))
    .layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        yauth::middleware::auth_middleware,
    ));
```

### Custom Plugins

Implement `YAuthPlugin` to add your own auth logic:

```rust
use yauth::plugin::{YAuthPlugin, PluginContext, AuthEvent, EventResponse};

struct MyPlugin;

impl YAuthPlugin for MyPlugin {
    fn name(&self) -> &'static str { "my-plugin" }

    fn on_event(&self, event: &AuthEvent, _ctx: &PluginContext) -> EventResponse {
        match event {
            AuthEvent::UserRegistered { user_id, email } => {
                // Send welcome notification, create default resources, etc.
                EventResponse::Continue
            }
            _ => EventResponse::Continue,
        }
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> { None }
    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> { None }
}

// Register it:
let auth = YAuthBuilder::new(pool, config)
    .with_plugin(Box::new(MyPlugin))
    .build();
```

### Integrating with an Existing utoipa/orval Setup

If your app already uses utoipa for OpenAPI spec generation and orval for TypeScript client generation, the preferred approach is to merge yauth's spec into yours so you get a single unified client.

**Merged spec — single unified client (recommended when using OpenAPI)**

yauth exposes `yauth::routes_meta::build_openapi_spec()` (requires the `openapi` feature flag), which returns a `utoipa::openapi::OpenApi` containing only the paths for your enabled feature flags. Merge this into your app's utoipa spec to produce a single `openapi.json` and one orval-generated client.

```rust
// In Cargo.toml: yauth = { version = "0.3", features = ["email-password", "openapi"] }

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(paths(/* your app's paths */), components(schemas(/* your schemas */)))]
struct AppApi;

fn build_merged_spec() -> utoipa::openapi::OpenApi {
    let mut spec = AppApi::openapi();

    // yauth's spec — dynamically includes only enabled features
    let yauth_spec = yauth::routes_meta::build_openapi_spec();

    // Merge yauth paths and schemas into your spec
    if let Some(yauth_paths) = yauth_spec.paths.paths {
        for (path, item) in yauth_paths {
            spec.paths.paths.insert(format!("/api/auth{path}"), item);
        }
    }
    if let Some(yauth_components) = yauth_spec.components {
        let app_components = spec.components.get_or_insert_with(Default::default);
        for (name, schema) in yauth_components.schemas {
            app_components.schemas.insert(name, schema);
        }
    }

    spec
}
```

Then point orval at the merged spec:

If your orval config uses `client: "vue-query"` (or `react-query`, `svelte-query`, etc.), the merged spec produces TanStack Query hooks for all yauth endpoints automatically — `useGetSession()`, `useEmailPasswordLogin()`, `useLogout()`, etc. GETs become `useQuery` hooks, POSTs become `useMutation` hooks. See `examples/vue-query/` in the yauth repo for a complete working example.

```typescript
// orval.config.ts
export default defineConfig({
  myApp: {
    input: { target: "./openapi.json" },  // The merged spec
    output: {
      target: "./src/generated.ts",
      client: "vue-query",  // or "fetch" for plain functions
      override: {
        mutator: {
          path: "./src/mutator.ts",
          name: "customFetch",
        },
      },
    },
  },
});
```

With this approach, your single generated client includes both your app's endpoints and all yauth auth endpoints. No need to install `@yackey-labs/yauth-client` separately.

**Using the generated Vue Query hooks:**

The key pattern: after login/logout mutations, invalidate the `getSession` query so components reactively update.

```vue
<script setup lang="ts">
import { useQueryClient } from "@tanstack/vue-query";
import { useEmailPasswordLogin, useGetSession, useLogout } from "./generated";

const queryClient = useQueryClient();

// Session query — provides reactive user state, auto-refetches on window focus
const { data: user, isLoading } = useGetSession();

// Login mutation — invalidates session cache on success so dashboard updates
const login = useEmailPasswordLogin({
  mutation: {
    onSuccess: (data) => {
      if (data?.mfa_required) {
        // Handle MFA challenge
      } else {
        queryClient.invalidateQueries({ queryKey: ["getSession"] });
        router.push("/dashboard");
      }
    },
  },
});

// Usage: login.mutate({ data: { email, password } })

// Logout mutation
const logout = useLogout({
  mutation: {
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["getSession"] });
      router.push("/login");
    },
  },
});
</script>
```

The `useGetSession()` query gives you reactive user state with automatic caching and refetch-on-focus — no manual session management needed.

**Pre-built UI components with a merged client:**

The `@yackey-labs/yauth-ui-vue` components (LoginForm, RegisterForm, etc.) work with any client that satisfies the `YAuthClient` interface. `YAuthPlugin` accepts either a `baseUrl` (creates a default client) or a pre-built `client` object — so you can pass your own client backed by orval-generated functions if you want the UI components to use your merged pipeline. You can also use the UI components with the default `baseUrl` setup alongside your Vue Query hooks for app data — they share the same session cookie. Or skip the pre-built components entirely and build your own forms using the generated mutations (`useEmailPasswordLogin()`, etc.) — see `examples/vue-query/` in the yauth repo.

**Alternative: Separate clients (for apps without OpenAPI)**

If your app doesn't use utoipa/orval, or you prefer not to merge specs, you can use yauth's pre-built `@yackey-labs/yauth-client` alongside your own client. They coexist naturally since yauth routes live under `/api/auth` and your app routes live elsewhere.

```typescript
// Your app's client (hand-written or generated)
import { getWidgets, createWidget } from "./api";

// yauth's client (from npm)
import { createYAuthClient } from "@yackey-labs/yauth-client";

const auth = createYAuthClient({ baseUrl: "/api/auth" });
```

**Session cookie for both approaches**

Whichever approach you use, your fetch calls need `credentials: "include"` so the browser sends the yauth session cookie on every request. If using orval, add it to your custom mutator:

```typescript
// src/mutator.ts
export const customFetch = async <T>(
  input: RequestInfo,
  init?: RequestInit,
): Promise<T> => {
  const response = await fetch(input, {
    ...init,
    credentials: "include",  // Sends the yauth session cookie
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed with status ${response.status}`);
  }
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
};
```

**Referencing yauth types in your spec**

If your app's API responses include yauth types (e.g., returning an `AuthUser`), you can reference them in your utoipa schema:

```rust
use yauth::middleware::AuthUser;

#[derive(Serialize, utoipa::ToSchema)]
struct MyResponse {
    data: Widget,
    #[schema(value_type = Object)]  // or inline the schema
    user: AuthUser,
}
```

**Regenerating yauth's client (contributors only)**

If you're modifying yauth itself (adding endpoints, changing request/response types), the pipeline is:

1. Update route metadata in `crates/yauth/src/routes_meta.rs`
2. Ensure types have `#[derive(TS)] #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]`
3. Run `bun generate` — this regenerates `openapi.json` and `packages/client/src/generated.ts`
4. Commit both regenerated files alongside your Rust changes

### Adding a Feature That Requires New Database Tables

yauth's migrations are idempotent (`CREATE TABLE IF NOT EXISTS`), so enabling a new feature flag is safe — just add it and re-run migrations. The typical workflow:

**1. Add the feature flag to `Cargo.toml`:**

```toml
# Before: just email-password
yauth = { version = "0.3", features = ["email-password"] }

# After: adding passkey + MFA
yauth = { version = "0.3", features = ["email-password", "passkey", "mfa"] }
```

**2. Add the plugin config to your builder:**

```rust
let auth = YAuthBuilder::new(pool, config)
    .with_email_password(EmailPasswordConfig::default())
    // New plugins:
    .with_passkey(PasskeyConfig {
        rp_id: "example.com".into(),
        rp_origin: "https://example.com".into(),
        rp_name: "My App".into(),
    })
    .with_mfa(MfaConfig {
        issuer: "My App".into(),
        backup_code_count: 10,
    })
    .build();
```

**3. Re-run migrations** — your existing startup code already does this. The migration runner detects which feature flags are compiled in and runs only the new ones:

```rust
// This is already in your startup code — no changes needed.
// It will create yauth_webauthn_credentials, yauth_totp_secrets,
// yauth_backup_codes tables (for passkey + mfa) alongside the
// existing tables it skips via IF NOT EXISTS.
yauth::migration::diesel_migrations::run_migrations(&pool).await?;
```

**4. Update frontend** — install or update the UI package to get the new components (PasskeyButton, MfaSetup, MfaChallenge, etc.), and wire them into your pages.

No manual SQL, no migration files to write, no version tracking — yauth handles all of it. Each feature flag maps to a known set of tables, and the migration runner creates exactly what's needed.

**What gets created per feature:**

| Feature | Tables Created |
|---|---|
| *(core, always)* | `yauth_users`, `yauth_sessions`, `yauth_audit_log` |
| `email-password` | `yauth_passwords`, `yauth_email_verifications`, `yauth_password_resets` |
| `passkey` | `yauth_webauthn_credentials` |
| `mfa` | `yauth_totp_secrets`, `yauth_backup_codes` |
| `oauth` | `yauth_oauth_accounts`, `yauth_oauth_states` |
| `bearer` | `yauth_refresh_tokens` |
| `api-key` | `yauth_api_keys` |
| `magic-link` | `yauth_magic_links` |
| `oauth2-server` | `yauth_oauth2_clients`, `yauth_authorization_codes`, `yauth_consents`, `yauth_device_codes` |
| `account-lockout` | `yauth_account_locks`, `yauth_unlock_tokens` |
| `webhooks` | `yauth_webhooks`, `yauth_webhook_deliveries` |
| `oidc` | `yauth_oidc_nonces` |

### CORS Configuration

When your frontend is on a different origin, configure CORS to include auth-related headers:

```rust
use tower_http::cors::{CorsLayer, Any};

let cors = CorsLayer::new()
    .allow_origin(["https://myapp.example.com".parse().unwrap()])
    .allow_methods(Any)
    .allow_headers([
        "content-type".parse().unwrap(),
        "authorization".parse().unwrap(),
        "x-api-key".parse().unwrap(),
        // Required for OpenTelemetry trace propagation:
        "traceparent".parse().unwrap(),
        "tracestate".parse().unwrap(),
    ])
    .allow_credentials(true);

let app = Router::new()
    .nest("/api/auth", auth.router())
    .layer(cors)
    .with_state(auth_state);
```
