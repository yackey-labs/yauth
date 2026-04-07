# Adding yauth to an Axum + Vue 3 App (Without OpenAPI Generation)

You don't need utoipa or orval to use yauth. The published npm packages give you a ready-made TypeScript client and Vue 3 UI components. Here's how to wire everything up.

---

## 1. Rust Backend Setup

### Add yauth crates

In your `Cargo.toml`:

```toml
[dependencies]
yauth = { version = "0.3", features = ["email-password"] }
yauth-entity = { version = "0.3", features = ["email-password"] }
yauth-migration = { version = "0.3", features = ["email-password"] }
```

Add more feature flags as needed (e.g., `passkey`, `mfa`, `bearer`, `api-key`, `admin`). The `full` feature enables everything.

### Configure and mount yauth

```rust
use axum::Router;
use yauth::{YAuthBuilder, YAuthConfig, EmailPasswordConfig};

#[tokio::main]
async fn main() {
    // Create your diesel-async pool
    let pool = yauth::create_pool(&database_url).await.unwrap();

    // Run yauth migrations
    yauth_migration::run_migrations(&pool).await.unwrap();

    // Configure yauth
    let config = YAuthConfig {
        db_schema: "public".to_string(),
        // ... other config fields
        ..Default::default()
    };

    let ep_config = EmailPasswordConfig {
        // Configure email/password settings
        ..Default::default()
    };

    let yauth = YAuthBuilder::new(pool.clone(), config)
        .with_email_password(ep_config)
        .build();

    // Get the yauth router and state
    let yauth_router = yauth.router();
    let yauth_state = yauth.into_state();

    // Mount yauth under /auth and nest your own app routes
    let app = Router::new()
        .nest("/auth", yauth_router)
        .route("/api/my-endpoint", axum::routing::get(my_handler))
        .with_state(yauth_state);

    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### CORS configuration

Make sure your CORS layer allows credentials and the necessary headers:

```rust
use tower_http::cors::{CorsLayer, Any};
use http::{HeaderName, Method};

let cors = CorsLayer::new()
    .allow_origin("http://localhost:5173".parse::<http::HeaderValue>().unwrap())
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH])
    .allow_headers([
        http::header::CONTENT_TYPE,
        http::header::AUTHORIZATION,
        HeaderName::from_static("x-api-key"),
        HeaderName::from_static("traceparent"),
        HeaderName::from_static("tracestate"),
    ])
    .allow_credentials(true);  // Critical for session cookies

let app = Router::new()
    .nest("/auth", yauth_router)
    .route("/api/my-endpoint", axum::routing::get(my_handler))
    .layer(cors)
    .with_state(yauth_state);
```

**`allow_credentials(true)` is essential** -- without it, the browser won't send or accept the session cookie that yauth sets.

### Protecting your own routes with yauth middleware

yauth injects an `Extension<AuthUser>` on authenticated requests. You can extract it in your handlers:

```rust
use axum::Extension;
use yauth_entity::AuthUser;

async fn my_handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    format!("Hello, user {}", user.id)
}
```

To protect routes, apply the yauth auth middleware layer to your app routes. The middleware checks (in order): session cookie, bearer token, API key -- and rejects unauthenticated requests.

---

## 2. TypeScript Client Setup

### Install the npm packages

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-shared
bun add @yackey-labs/yauth-ui-vue   # Vue 3 components
```

### Configure the yauth client

The `@yackey-labs/yauth-client` package exports a `createYAuthClient()` factory that returns an object with grouped methods for every auth endpoint:

```typescript
// src/lib/auth.ts
import { createYAuthClient } from "@yackey-labs/yauth-client";

export const authClient = createYAuthClient({
  baseURL: "http://localhost:3000/auth",
  // The client uses fetch with credentials: "include" by default,
  // so session cookies are sent automatically.
});
```

### Using the client

```typescript
// Register a new user
await authClient.emailPassword.register({
  email: "user@example.com",
  password: "SecureP@ssw0rd!",
});

// Log in (sets session cookie automatically)
await authClient.emailPassword.login({
  email: "user@example.com",
  password: "SecureP@ssw0rd!",
});

// Get current session / user info
const session = await authClient.session.get();
console.log(session.user);

// Log out
await authClient.session.logout();
```

The client's internal fetch wrapper (the "mutator") is configured with `credentials: "include"`, which means the browser automatically sends and receives the `Set-Cookie` / `Cookie` headers for the yauth session. You don't need to manage tokens manually for session-based auth.

---

## 3. Making Your Own fetch Calls Carry the Session Cookie

The session cookie that yauth sets is a standard HTTP cookie. Any fetch call to the same origin (or a CORS-allowed origin with credentials) will carry it automatically -- **as long as you include `credentials: "include"`**.

### Option A: Set credentials on every fetch call

```typescript
const response = await fetch("http://localhost:3000/api/my-endpoint", {
  method: "GET",
  credentials: "include",  // This sends the session cookie
  headers: {
    "Content-Type": "application/json",
  },
});
```

### Option B: Create a reusable fetch wrapper (recommended)

```typescript
// src/lib/api.ts

const API_BASE = "http://localhost:3000/api";

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include",  // Always send session cookie
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    if (response.status === 401) {
      // Session expired or not authenticated -- redirect to login
      window.location.href = "/login";
      throw new Error("Unauthorized");
    }
    throw new Error(`API error: ${response.status}`);
  }

  return response.json();
}

// Usage:
const data = await apiFetch<MyData>("/my-endpoint");
const result = await apiFetch<CreateResult>("/items", {
  method: "POST",
  body: JSON.stringify({ name: "New Item" }),
});
```

### Option C: Use axios with `withCredentials`

If you prefer axios:

```typescript
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:3000/api",
  withCredentials: true,  // Sends cookies with every request
});

// Usage:
const { data } = await api.get("/my-endpoint");
```

---

## 4. Using yauth Vue 3 UI Components

The `@yackey-labs/yauth-ui-vue` package provides ready-made components:

```vue
<script setup lang="ts">
import { LoginForm, RegisterForm } from "@yackey-labs/yauth-ui-vue";
import { authClient } from "@/lib/auth";

function onLoginSuccess(user: any) {
  // Redirect to dashboard or wherever
  router.push("/dashboard");
}
</script>

<template>
  <LoginForm :client="authClient" @success="onLoginSuccess" />
</template>
```

The Vue package also likely provides composables like `useAuth()` for reactive auth state management in your components.

---

## 5. Protecting Vue Routes

Use a Vue Router navigation guard to redirect unauthenticated users:

```typescript
// src/router/index.ts
import { createRouter, createWebHistory } from "vue-router";
import { authClient } from "@/lib/auth";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/login", component: () => import("@/pages/Login.vue") },
    {
      path: "/dashboard",
      component: () => import("@/pages/Dashboard.vue"),
      meta: { requiresAuth: true },
    },
  ],
});

router.beforeEach(async (to) => {
  if (to.meta.requiresAuth) {
    try {
      await authClient.session.get();
      // Session is valid, proceed
    } catch {
      // Not authenticated, redirect to login
      return { path: "/login" };
    }
  }
});

export default router;
```

---

## Key Points

1. **You don't need OpenAPI or code generation** to use yauth. The `@yackey-labs/yauth-client` package is a pre-built client that covers all yauth endpoints.

2. **Session cookies work automatically** as long as:
   - Your backend has `allow_credentials(true)` in the CORS config
   - Your frontend uses `credentials: "include"` on fetch calls
   - The `allow_origin` in CORS is an explicit origin (not `*` -- wildcard origins cannot be used with credentials)

3. **Your own API calls** just need `credentials: "include"` to carry the same session cookie that yauth sets. The yauth auth middleware on the backend will validate the cookie and inject `AuthUser` into your handlers.

4. **The yauth client's fetch wrapper already handles credentials** -- you only need to worry about `credentials: "include"` for your own non-yauth API calls.

5. **Feature flags control what's available** -- if you only enable `email-password`, the client methods for passkey/MFA/etc. will still exist in the TypeScript types but the backend routes won't be mounted. Enable features incrementally as you need them.
