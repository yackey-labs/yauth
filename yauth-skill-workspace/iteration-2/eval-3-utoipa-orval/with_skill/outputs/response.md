# Adding yauth to an Axum App with an Existing utoipa/orval Pipeline

You already have utoipa generating your `openapi.json` and orval generating a TypeScript client from it. Adding yauth does not require merging anything into your existing spec or pipeline. yauth ships its own pre-built TypeScript client on npm, so the two clients coexist side by side.

## Strategy: Keep Specs Separate (Recommended)

yauth routes live under `/api/auth`. Your app routes live elsewhere (e.g., `/api/widgets`, `/api/orders`). There is no reason to merge the two OpenAPI specs. Instead:

- Your app keeps its own `openapi.json` and orval config, generating your own TypeScript client as before.
- yauth's `@yackey-labs/yauth-client` package (installed from npm) handles all auth endpoints.

This is the cleanest approach because yauth's spec and client are maintained upstream and versioned with the library. You avoid coupling your release cycle to yauth's API surface.

## Backend Setup

### 1. Add yauth to Cargo.toml

```toml
[dependencies]
yauth = { version = "0.3", features = ["email-password"] }
# Your existing utoipa dependency stays as-is
utoipa = { version = "...", features = ["axum_extras"] }
```

### 2. Set up the database pool and run migrations

```rust
use yauth::prelude::*;

// Create the yauth pool (can be the same DB as your app)
let config = yauth::AsyncDieselConnectionManager::<yauth::AsyncPgConnection>::new(&database_url);
let pool = yauth::DieselPool::builder(config).build()?;

// Run yauth migrations (idempotent, safe to call every startup)
yauth::migration::diesel_migrations::run_migrations(&pool).await?;
```

If you want to isolate yauth tables from your app tables, use a separate PostgreSQL schema:

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

### 4. Mount yauth alongside your existing app router

```rust
let auth_state = auth.state().clone();

// Your existing app routes (with your utoipa OpenAPI doc)
let app_routes = Router::new()
    .route("/api/widgets", get(list_widgets).post(create_widget))
    .route("/api/openapi.json", get(serve_openapi_spec));

// Your protected routes - AuthUser is injected via Extension
let app_protected = Router::new()
    .route("/api/me", get(me_handler))
    .route("/api/orders", get(list_orders).post(create_order))
    .layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        yauth::middleware::auth_middleware,
    ));

let app = Router::new()
    .merge(app_routes)
    .merge(app_protected)
    .nest("/api/auth", auth.router())   // yauth routes mounted here
    .with_state(auth_state);
```

Your existing `/api/openapi.json` endpoint and all your app routes remain unchanged. yauth simply adds its own routes under `/api/auth`.

### 5. Access the authenticated user in your handlers

Your existing handlers can now receive the authenticated user:

```rust
use yauth::middleware::AuthUser;

async fn list_orders(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    // user.id, user.email, user.role are available
    let orders = fetch_orders_for_user(user.id).await;
    Json(orders)
}
```

### 6. If your API responses include AuthUser

If any of your utoipa-annotated endpoints return an `AuthUser` (or a struct containing one), you can reference it in your OpenAPI schema:

```rust
use yauth::middleware::AuthUser;

#[derive(Serialize, utoipa::ToSchema)]
struct OrderResponse {
    order: Order,
    #[schema(value_type = Object)]  // Treat as opaque JSON object in your spec
    user: AuthUser,
}
```

This keeps your spec self-contained without needing to import yauth's OpenAPI definitions.

## Frontend Setup

### 1. Install packages

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-solidjs
```

### 2. Use both clients side by side

```typescript
// Your orval-generated client (from YOUR openapi.json) - unchanged
import { listWidgets, createWidget, listOrders } from "./generated";

// yauth's client (from npm)
import { createYAuthClient } from "@yackey-labs/yauth-client";

const auth = createYAuthClient({ baseUrl: "/api/auth" });
```

### 3. Session cookie is automatic

This is the key detail: yauth uses `credentials: "include"` in its fetch calls, which means the browser sends the session cookie on every request to your origin. Your orval-generated client needs the same setting to carry the cookie automatically.

In your orval custom mutator (the file you already have for your orval config), make sure `credentials: "include"` is set:

```typescript
// src/mutator.ts (your existing custom fetch wrapper for orval)
export const customFetch = async <T>(url: string, options: RequestInit): Promise<T> => {
  const response = await fetch(url, {
    ...options,
    credentials: "include",  // THIS is what carries the session cookie
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.json() as Promise<T>;
};
```

And in your orval config, point to this mutator:

```typescript
// orval.config.ts
export default defineConfig({
  myApp: {
    input: { target: "./openapi.json" },
    output: {
      target: "./src/generated.ts",
      client: "fetch",
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

With `credentials: "include"` on both clients, the browser sends the `session` cookie on every request to your origin. yauth's auth middleware on the backend picks it up automatically. No token passing, no header wiring -- it just works.

### 4. Wire up auth UI components

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

```tsx
import { LoginForm } from "@yackey-labs/yauth-ui-solidjs";

function LoginPage() {
  return (
    <LoginForm
      onSuccess={() => navigate("/dashboard")}
      onError={(err) => console.error(err)}
    />
  );
}
```

```tsx
import { useYAuth } from "@yackey-labs/yauth-ui-solidjs";

function DashboardPage() {
  const { user, loading } = useYAuth();

  return (
    <Show when={!loading()} fallback={<div>Loading...</div>}>
      <Show when={user()}>
        {(u) => <p>Logged in as {u().email}</p>}
      </Show>
    </Show>
  );
}
```

## CORS Configuration

If your frontend runs on a different origin during development (e.g., Vite on port 5173, Axum on port 3000), configure CORS to allow credentials and auth-related headers:

```rust
use tower_http::cors::{CorsLayer, Any};

let cors = CorsLayer::new()
    .allow_origin(["http://localhost:5173".parse().unwrap()])
    .allow_methods(Any)
    .allow_headers([
        "content-type".parse().unwrap(),
        "authorization".parse().unwrap(),
        "x-api-key".parse().unwrap(),
        "traceparent".parse().unwrap(),
        "tracestate".parse().unwrap(),
    ])
    .allow_credentials(true);

let app = Router::new()
    .merge(app_routes)
    .merge(app_protected)
    .nest("/api/auth", auth.router())
    .layer(cors)
    .with_state(auth_state);
```

Note: `.allow_credentials(true)` is required for the session cookie to be sent cross-origin. You cannot use wildcard origins with credentials -- you must list specific origins.

## Summary

| Concern | Approach |
|---|---|
| OpenAPI spec | Keep yours separate. Do not merge with yauth's spec. |
| TypeScript client | Use your orval-generated client for your API, `@yackey-labs/yauth-client` for auth. |
| Session cookie on your API calls | Set `credentials: "include"` in your orval mutator. |
| Auth middleware on your routes | Apply `yauth::middleware::auth_middleware` to protected route groups. |
| Database tables | yauth creates its own `yauth_`-prefixed tables (or use `db_schema` for full isolation). |
| Your existing orval pipeline | Completely unchanged. Nothing to modify in your `orval.config.ts` input/output settings. |

The two systems are additive. yauth does not touch your existing spec, your existing generated client, or your existing routes. The only integration point is the auth middleware layer on your protected routes and `credentials: "include"` in your fetch calls.
