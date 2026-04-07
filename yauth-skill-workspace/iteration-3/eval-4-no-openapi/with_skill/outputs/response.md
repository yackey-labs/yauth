# Adding yauth to an Axum + Vue 3 App (Without OpenAPI/utoipa)

Since you are not using utoipa or orval, you fall into the "separate clients" path: you will use yauth's pre-built `@yackey-labs/yauth-client` npm package for all auth endpoints, and continue making your own fetch calls for your app's API. The key thing that ties them together is the **session cookie** -- both clients need `credentials: "include"` so the browser sends the yauth session cookie on every request.

---

## 1. Backend: Add yauth to Your Axum App

### Cargo.toml

```toml
[dependencies]
yauth = { version = "0.3", features = ["email-password"] }
```

Add more features as needed (e.g., `"passkey"`, `"mfa"`, `"api-key"`). There are no separate `yauth-entity` or `yauth-migration` crates -- everything is built into the `yauth` crate.

### Database Pool and Migrations

```rust
use yauth::prelude::*;

let config = yauth::AsyncDieselConnectionManager::<yauth::AsyncPgConnection>::new(&database_url);
let pool = yauth::DieselPool::builder(config).build()?;

// Creates only the tables for your enabled features (idempotent)
yauth::migration::diesel_migrations::run_migrations(&pool).await?;
```

### Build the YAuth Instance

```rust
let auth = YAuthBuilder::new(pool, yauth::config::YAuthConfig {
    base_url: "https://myapp.example.com".into(),
    session_cookie_name: "session".into(),
    session_ttl: Duration::from_secs(7 * 24 * 3600),
    secure_cookies: true, // set to false for local dev over HTTP
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

### Mount yauth Routes Alongside Your Own Routes

```rust
use axum::{Router, routing::get, Extension};
use tower_http::cors::{CorsLayer, Any};

let auth_state = auth.state().clone();

// Your own protected routes -- AuthUser is injected via Extension
let app_protected = Router::new()
    .route("/api/widgets", get(list_widgets))
    .route("/api/widgets/:id", get(get_widget))
    .layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        yauth::middleware::auth_middleware,
    ));

// CORS -- required when frontend and backend are on different origins
let cors = CorsLayer::new()
    .allow_origin(["https://myapp.example.com".parse().unwrap()])
    .allow_methods(Any)
    .allow_headers([
        "content-type".parse().unwrap(),
        "authorization".parse().unwrap(),
        "x-api-key".parse().unwrap(),
        // Include these if using OpenTelemetry:
        "traceparent".parse().unwrap(),
        "tracestate".parse().unwrap(),
    ])
    .allow_credentials(true); // Critical -- allows cookies cross-origin

let app = Router::new()
    .route("/api/health", get(health_handler))
    .merge(app_protected)
    .nest("/api/auth", auth.router()) // All yauth routes live under /api/auth
    .layer(cors)
    .with_state(auth_state);
```

### Access the Authenticated User in Your Handlers

```rust
use yauth::middleware::AuthUser;

async fn list_widgets(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    // user.id, user.email, user.role are available
    let widgets = fetch_widgets_for_user(user.id).await;
    Json(widgets)
}
```

The auth middleware checks credentials in order: session cookie, then `Authorization: Bearer <jwt>`, then `X-Api-Key` header. Since you are using session cookies, the cookie is what will authenticate your users.

---

## 2. Frontend: Install the yauth Packages

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-vue
```

This gives you:
- `@yackey-labs/yauth-client` -- the HTTP client for all auth endpoints
- `@yackey-labs/yauth-ui-vue` -- pre-built Vue 3 components (LoginForm, RegisterForm, etc.)

### Register the Plugin

In your Vue app entry point:

```typescript
// main.ts
import { createApp } from 'vue'
import { YAuthPlugin } from '@yackey-labs/yauth-ui-vue'
import App from './App.vue'
import router from './router'

createApp(App)
  .use(router)
  .use(YAuthPlugin, { baseUrl: '/api/auth' })
  .mount('#app')
```

The `baseUrl` must match where you nested the yauth routes on the backend (i.e., `/api/auth`).

---

## 3. Using yauth UI Components

The Vue package provides ready-made components. Here are the most common ones:

### Login Page

```vue
<!-- LoginPage.vue -->
<script setup lang="ts">
import { ref } from 'vue'
import { LoginForm, MfaChallenge } from '@yackey-labs/yauth-ui-vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const mfaPending = ref<string | null>(null)
</script>

<template>
  <MfaChallenge
    v-if="mfaPending"
    :pendingSessionId="mfaPending"
    @success="router.push('/dashboard')"
  />
  <LoginForm
    v-else
    @success="router.push('/dashboard')"
    @mfa-required="(id) => mfaPending = id"
  />
</template>
```

### Registration Page

```vue
<!-- RegisterPage.vue -->
<script setup lang="ts">
import { RegisterForm } from '@yackey-labs/yauth-ui-vue'
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <RegisterForm @success="router.push('/dashboard')" />
</template>
```

### Dashboard with Auth State

```vue
<!-- DashboardPage.vue -->
<script setup lang="ts">
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

### Available Composables

```typescript
import { useAuth, useSession, useYAuth } from '@yackey-labs/yauth-ui-vue'

// useYAuth -- raw client + reactive user
const { client, user, loading, refetch } = useYAuth()

// useAuth -- high-level actions with built-in error/submitting state
const { login, register, logout, forgotPassword, resetPassword, changePassword, error, submitting } = useAuth()

// useSession -- reactive computed properties for templates
const { isAuthenticated, isEmailVerified, userEmail, userRole, displayName } = useSession()
```

---

## 4. Making Your Own API Calls Carry the Session Cookie

This is the critical piece. When yauth logs a user in, it sets an `HttpOnly` session cookie. The browser will automatically include this cookie on requests to the same origin **only if you use `credentials: "include"`** in your fetch calls.

### Option A: Simple Fetch Wrapper

Create a small wrapper that you use for all your app's API calls:

```typescript
// src/api/fetch.ts
export async function apiFetch<T>(
  url: string,
  options?: RequestInit,
): Promise<T> {
  const response = await fetch(url, {
    ...options,
    credentials: "include", // This sends the yauth session cookie
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }

  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}
```

Then use it everywhere:

```typescript
// src/api/widgets.ts
import { apiFetch } from './fetch'

export async function getWidgets() {
  return apiFetch<Widget[]>('/api/widgets')
}

export async function createWidget(data: CreateWidgetInput) {
  return apiFetch<Widget>('/api/widgets', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}
```

### Option B: Axios

If you use Axios, set `withCredentials` globally:

```typescript
import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  withCredentials: true, // Sends session cookie on every request
})

export async function getWidgets() {
  const { data } = await api.get<Widget[]>('/widgets')
  return data
}
```

### Option C: Using the yauth Client Directly for Custom Calls

You can also get the underlying `createYAuthClient` instance from the `useYAuth()` composable and use it for auth-specific operations, while your own wrapper handles everything else:

```typescript
import { createYAuthClient } from '@yackey-labs/yauth-client'

// This client already has credentials: "include" built in
const authClient = createYAuthClient({
  baseUrl: '/api/auth',
  credentials: 'include',
})

// Auth operations go through the yauth client
await authClient.emailPassword.login({ email, password })
await authClient.getSession()
await authClient.logout()

// Your own API calls go through your own fetch wrapper
const widgets = await apiFetch<Widget[]>('/api/widgets')
```

---

## 5. How It All Fits Together

Here is the mental model:

```
Browser
  |
  |-- @yackey-labs/yauth-client (credentials: "include")
  |       --> POST /api/auth/login
  |       --> GET  /api/auth/session
  |       --> POST /api/auth/logout
  |       (yauth sets/reads the session cookie)
  |
  |-- Your own fetch wrapper (credentials: "include")
  |       --> GET  /api/widgets
  |       --> POST /api/widgets
  |       (yauth's auth_middleware reads the same session cookie
  |        and injects AuthUser into the request)
  |
Axum Server
  |-- /api/auth/*  --> yauth router (handles login, register, etc.)
  |-- /api/*       --> your routes (protected by yauth::middleware::auth_middleware)
```

The session cookie is the glue. yauth's login endpoint sets it, the browser stores it, and both the yauth client and your own fetch calls send it back. On the server side, yauth's `auth_middleware` reads that same cookie on your protected routes and provides the `AuthUser` via Axum's `Extension`.

---

## 6. Route Guards in Vue Router

To protect frontend routes, check the session before navigating:

```typescript
// router/index.ts
import { createYAuthClient } from '@yackey-labs/yauth-client'

const authClient = createYAuthClient({ baseUrl: '/api/auth', credentials: 'include' })

router.beforeEach(async (to) => {
  if (to.meta.requiresAuth) {
    try {
      await authClient.getSession()
    } catch {
      return { name: 'login', query: { redirect: to.fullPath } }
    }
  }
})
```

Then mark routes:

```typescript
{
  path: '/dashboard',
  component: DashboardPage,
  meta: { requiresAuth: true },
}
```

---

## Summary

1. **Backend**: Add `yauth` to `Cargo.toml`, build with `YAuthBuilder`, nest yauth routes at `/api/auth`, and protect your own routes with `yauth::middleware::auth_middleware`. Set `allow_credentials(true)` on your CORS layer.

2. **Frontend**: Install `@yackey-labs/yauth-client` and `@yackey-labs/yauth-ui-vue`. Register `YAuthPlugin` with `baseUrl: '/api/auth'`. Use the provided components (`LoginForm`, `RegisterForm`, etc.) and composables (`useAuth`, `useSession`).

3. **Session cookie for your own API calls**: Add `credentials: "include"` to every `fetch` call (or `withCredentials: true` for Axios). This is the only thing needed -- the browser sends the same session cookie that yauth set, and yauth's middleware on the backend validates it and injects `AuthUser` into your handlers.

No OpenAPI generation, no utoipa, no orval needed. The `@yackey-labs/yauth-client` package is a standalone, pre-built client that works out of the box.
