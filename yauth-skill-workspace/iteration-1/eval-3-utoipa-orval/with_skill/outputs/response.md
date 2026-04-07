# Integrating yauth Into an Existing utoipa/orval App

You already have a working pipeline: your Axum app generates `openapi.json` via utoipa, and orval generates a TypeScript client from it. Adding yauth does not require merging yauth's spec into yours. The recommended approach is to keep the two specs and clients separate.

## Why Separate Specs Work

yauth routes are mounted under a dedicated prefix (typically `/api/auth`), while your app's routes live elsewhere (e.g., `/api/widgets`, `/api/orders`). The two never overlap. yauth ships a pre-built TypeScript client on npm (`@yackey-labs/yauth-client`) that already covers every auth endpoint, so there is no need to run orval against yauth's OpenAPI spec yourself.

The session cookie is shared across both clients automatically. The browser sends cookies for all requests to the same origin regardless of which client library made the call. You just need to make sure your orval-generated client also uses `credentials: "include"` in its fetch calls.

---

## Step 1: Add yauth to Cargo.toml

Pick the feature flags you need. Your existing utoipa dependency stays unchanged.

```toml
[dependencies]
yauth = { version = "0.3", features = ["email-password"] }

# Your existing deps stay as-is
utoipa = { version = "...", features = ["axum_extras"] }
utoipa-swagger-ui = { version = "...", features = ["axum"] }
```

Common feature combos:

```toml
# Web app with passwords + passkeys + MFA
yauth = { version = "0.3", features = ["email-password", "passkey", "mfa"] }

# API service with bearer tokens + API keys
yauth = { version = "0.3", features = ["email-password", "bearer", "api-key"] }
```

## Step 2: Set Up the Database Pool and Run Migrations

```rust
use yauth::prelude::*;

let config = yauth::AsyncDieselConnectionManager::<yauth::AsyncPgConnection>::new(&database_url);
let pool = yauth::DieselPool::builder(config).build()?;

// Runs only the migrations for your enabled features -- all idempotent
yauth::migration::diesel_migrations::run_migrations(&pool).await?;
```

If you want yauth's tables in a separate PostgreSQL schema to keep them isolated from your app's tables:

```rust
let yauth_config = yauth::config::YAuthConfig {
    db_schema: "auth".into(),
    ..Default::default()
};
let pool = yauth::create_pool(&database_url, &yauth_config)?;
yauth::migration::diesel_migrations::run_migrations_with_schema(&pool, "auth").await?;
```

## Step 3: Build the YAuth Instance and Mount Routes

The key integration point: nest yauth's router alongside your existing app router. Your utoipa OpenAPI doc and Swagger UI remain on your app's routes; yauth's routes live under `/api/auth`.

```rust
use yauth::prelude::*;

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

let auth_state = auth.state().clone();

// Your existing protected routes -- yauth middleware injects AuthUser
let app_protected = Router::new()
    .route("/api/widgets", get(list_widgets))
    .route("/api/widgets/:id", get(get_widget))
    .layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        yauth::middleware::auth_middleware,
    ));

// Your existing public routes + utoipa swagger
let app = Router::new()
    .route("/api/health", get(health_handler))
    .merge(app_protected)
    .nest("/api/auth", auth.router())          // yauth routes
    .merge(SwaggerUi::new("/swagger-ui")       // your existing swagger UI
        .url("/api-docs/openapi.json", ApiDoc::openapi()))
    .with_state(auth_state);
```

Your utoipa `#[derive(OpenApi)]` and all your `#[utoipa::path(...)]` annotations remain exactly as they are. yauth's routes simply do not appear in your spec, and that is fine -- they have their own pre-built client.

## Step 4: Access the Authenticated User in Your Handlers

Your existing handlers can now receive the authenticated user:

```rust
use yauth::middleware::AuthUser;

async fn list_widgets(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    // user.id, user.email, user.role are available
    let widgets = fetch_widgets_for_user(user.id).await;
    Json(widgets)
}
```

The auth middleware tries credentials in this order: session cookie, then `Authorization: Bearer <jwt>` header, then `X-Api-Key` header. The first valid credential wins.

## Step 5: Install Frontend Packages

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-solidjs
```

Your existing orval-generated client stays untouched.

## Step 6: Make Your orval-Generated Client Carry the Session Cookie

This is the critical piece. yauth sets a session cookie on login. For your app's API calls to be authenticated, your orval-generated fetch calls must include `credentials: "include"`.

### Option A: Custom mutator in your orval config (recommended)

Create a mutator file for your app's client that mirrors the pattern yauth uses:

```typescript
// src/api/mutator.ts
export const customFetch = async <T>(
  input: RequestInfo,
  init?: RequestInit,
): Promise<T> => {
  const response = await fetch(input, {
    ...init,
    credentials: "include",  // This sends the yauth session cookie
    headers: {
      ...init?.headers,
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed with status ${response.status}`);
  }

  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
};
```

Then reference it in your orval config:

```typescript
// orval.config.ts
import { defineConfig } from "orval";

export default defineConfig({
  myApp: {
    input: {
      target: "./openapi.json",  // YOUR app's OpenAPI spec
    },
    output: {
      mode: "single",
      target: "./src/api/generated.ts",
      client: "fetch",
      override: {
        mutator: {
          path: "./src/api/mutator.ts",
          name: "customFetch",
        },
      },
    },
  },
});
```

Now every generated function in `src/api/generated.ts` will use `credentials: "include"`, meaning the yauth session cookie is sent automatically on every request. No extra wiring needed.

### Option B: If you already have a custom mutator

Just add `credentials: "include"` to the fetch call in your existing mutator:

```typescript
const response = await fetch(url, {
  ...init,
  credentials: "include",  // Add this line
});
```

## Step 7: Use Both Clients in Your Frontend

```typescript
// Your app's generated client (from your openapi.json via orval)
import { listWidgets, getWidget, createWidget } from "./api/generated";

// yauth's client (from npm)
import { createYAuthClient } from "@yackey-labs/yauth-client";

const auth = createYAuthClient({
  baseUrl: "/api/auth",
  credentials: "include",
});

// Auth operations use yauth's client
await auth.emailPassword.login({ email: "user@example.com", password: "..." });

// App operations use your generated client -- session cookie sent automatically
const widgets = await listWidgets();
const widget = await getWidget("widget-123");
```

For SolidJS, wrap your app in `YAuthProvider` for the UI components:

```tsx
import { YAuthProvider } from "@yackey-labs/yauth-ui-solidjs";

function App() {
  return (
    <YAuthProvider baseUrl="/api/auth">
      <Router>
        <Route path="/login" component={LoginPage} />
        <Route path="/dashboard" component={DashboardPage} />
      </Router>
    </YAuthProvider>
  );
}
```

The `LoginForm`, `RegisterForm`, and other components handle all auth UI out of the box.

---

## CORS Configuration

If your frontend runs on a different origin from your backend (e.g., Vite dev server on `:5173`, backend on `:3000`), you need CORS with credentials enabled. This applies to both yauth routes and your app routes:

```rust
use tower_http::cors::{CorsLayer, Any};

let cors = CorsLayer::new()
    .allow_origin(["http://localhost:5173".parse().unwrap()])
    .allow_methods(Any)
    .allow_headers([
        "content-type".parse().unwrap(),
        "authorization".parse().unwrap(),
        "x-api-key".parse().unwrap(),
        // For OpenTelemetry trace propagation:
        "traceparent".parse().unwrap(),
        "tracestate".parse().unwrap(),
    ])
    .allow_credentials(true);  // Required for cookies to work cross-origin

let app = Router::new()
    .merge(app_protected)
    .nest("/api/auth", auth.router())
    .merge(SwaggerUi::new("/swagger-ui")
        .url("/api-docs/openapi.json", ApiDoc::openapi()))
    .layer(cors)
    .with_state(auth_state);
```

Note: `allow_credentials(true)` is required for the session cookie to be sent on cross-origin requests. You cannot use wildcard origins with credentials -- you must specify exact origins.

---

## What If Your API Returns AuthUser in Responses?

If any of your app's endpoints return yauth's `AuthUser` type (e.g., a `/api/me` endpoint that appears in your own OpenAPI spec), you can reference it in your utoipa schema:

```rust
use yauth::middleware::AuthUser;

#[derive(Serialize, utoipa::ToSchema)]
struct MeResponse {
    #[schema(value_type = Object)]  // Treat as opaque JSON object in the spec
    user: AuthUser,
    widgets_count: i64,
}
```

This keeps things simple. If you need the full typed schema for `AuthUser` in your spec, you could create a wrapper struct that derives `ToSchema`, but in practice the opaque approach works well since the auth-specific types are already fully typed in `@yackey-labs/yauth-client`.

---

## Summary

| Concern | Approach |
|---|---|
| OpenAPI spec | Keep separate -- your app's spec via utoipa, yauth's spec is pre-built |
| TypeScript client | Two clients side by side -- your orval output + `@yackey-labs/yauth-client` |
| Session cookie | Both clients use `credentials: "include"` -- browser handles the rest |
| Route mounting | `nest("/api/auth", auth.router())` alongside your existing routes |
| Auth middleware | `yauth::middleware::auth_middleware` on your protected routes |
| Frontend UI | `@yackey-labs/yauth-ui-solidjs` components handle login/register/etc. |

Nothing in your existing utoipa annotations, orval config, or generated client needs to change. You add yauth as a parallel system that shares the same session cookie.
