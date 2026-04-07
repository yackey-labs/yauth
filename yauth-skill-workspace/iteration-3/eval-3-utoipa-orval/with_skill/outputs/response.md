# Integrating yauth into an Existing utoipa/orval Pipeline

You already have utoipa generating `openapi.json` and orval generating a TypeScript client from it. yauth fits cleanly into this setup: you merge yauth's OpenAPI spec into yours so you end up with a single unified client that covers both your app's endpoints and all auth endpoints.

## 1. Add yauth with the `openapi` feature flag

The `openapi` feature flag is what enables yauth to expose its OpenAPI spec for merging. Add it alongside whatever auth features you need:

```toml
[dependencies]
yauth = { version = "0.3", features = ["email-password", "openapi"] }
```

Add more features as needed (e.g., `"passkey"`, `"mfa"`, `"bearer"`, `"api-key"`). The OpenAPI spec yauth generates will automatically include only the paths for your enabled features.

## 2. Set up the database pool and run migrations

```rust
use yauth::prelude::*;

let config = yauth::AsyncDieselConnectionManager::<yauth::AsyncPgConnection>::new(&database_url);
let pool = yauth::DieselPool::builder(config).build()?;

// Runs only the migrations for your enabled features -- all idempotent
yauth::migration::diesel_migrations::run_migrations(&pool).await?;
```

## 3. Build the YAuth instance and mount routes

```rust
let auth = YAuthBuilder::new(pool.clone(), yauth::config::YAuthConfig {
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

// Your own protected routes -- AuthUser injected via Extension
let app_protected = Router::new()
    .route("/api/widgets", get(list_widgets))
    .route("/api/widgets", post(create_widget))
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

## 4. Merge yauth's OpenAPI spec into yours

This is the key step. Instead of maintaining two separate specs, you merge yauth's spec into your existing utoipa-generated spec. yauth exposes `yauth::routes_meta::build_openapi_spec()` which returns a `utoipa::openapi::OpenApi` containing only the paths for your enabled feature flags.

```rust
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(list_widgets, create_widget, health_handler),
    components(schemas(Widget, CreateWidgetRequest))
)]
struct AppApi;

fn build_merged_spec() -> utoipa::openapi::OpenApi {
    let mut spec = AppApi::openapi();

    // yauth's spec -- dynamically includes only enabled features
    let yauth_spec = yauth::routes_meta::build_openapi_spec();

    // Merge yauth paths into your spec, prefixed with /api/auth
    if let Some(yauth_paths) = yauth_spec.paths.paths {
        for (path, item) in yauth_paths {
            spec.paths.paths.insert(format!("/api/auth{path}"), item);
        }
    }

    // Merge yauth schemas (request/response types) into your spec
    if let Some(yauth_components) = yauth_spec.components {
        let app_components = spec.components.get_or_insert_with(Default::default);
        for (name, schema) in yauth_components.schemas {
            app_components.schemas.insert(name, schema);
        }
    }

    spec
}
```

Write the merged spec to `openapi.json` as part of your existing spec generation step (however you currently produce it). The result is a single file containing both your app's endpoints and all yauth auth endpoints.

## 5. No changes to orval.config.ts (almost)

Your existing orval config already points at `openapi.json` and generates a client. Since yauth's paths and schemas are now merged into that same file, orval will generate functions for them automatically. The only change you need is to make sure your custom fetch mutator sends the session cookie (see next step).

```typescript
// orval.config.ts -- no structural changes needed
export default defineConfig({
  myApp: {
    input: { target: "./openapi.json" },  // The merged spec
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

## 6. Add `credentials: "include"` to your fetch mutator

This is how you ensure the session cookie is sent on every API call -- both your app's endpoints and yauth's auth endpoints. Add `credentials: "include"` to the fetch call in your custom mutator:

```typescript
// src/mutator.ts
export const customFetch = async <T>(
  input: RequestInfo,
  init?: RequestInit,
): Promise<T> => {
  const response = await fetch(input, {
    ...init,
    credentials: "include",  // Sends the yauth session cookie on every request
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed with status ${response.status}`);
  }
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
};
```

With `credentials: "include"`, the browser will automatically attach the session cookie (set by yauth on login) to every fetch request to your API. This means:

- After a user logs in via the generated `postLogin()` function, the session cookie is set.
- Every subsequent call to your app's endpoints (e.g., `getWidgets()`) and auth endpoints (e.g., `getSession()`) will carry that cookie.
- The yauth auth middleware on the backend will validate the cookie and inject the `AuthUser` into the request.

## 7. Access the authenticated user in your handlers

```rust
use yauth::middleware::AuthUser;

async fn list_widgets(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    // user.id, user.email, user.role are available
    let widgets = fetch_widgets_for_user(user.id).await;
    Json(widgets)
}
```

## 8. Referencing yauth types in your own API responses

If your endpoints return yauth types (e.g., embedding the current user in a response), you can reference them in your utoipa schemas:

```rust
use yauth::middleware::AuthUser;

#[derive(Serialize, utoipa::ToSchema)]
struct WidgetListResponse {
    widgets: Vec<Widget>,
    #[schema(value_type = Object)]
    current_user: AuthUser,
}
```

## 9. CORS configuration

If your frontend is on a different origin from the backend, configure CORS to allow credentials and auth-related headers:

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
    .allow_credentials(true);  // Required for session cookies across origins

let app = Router::new()
    .route("/api/health", get(health_handler))
    .merge(app_protected)
    .nest("/api/auth", auth.router())
    .layer(cors)
    .with_state(auth_state);
```

The `.allow_credentials(true)` is essential -- without it, the browser will not send or accept cookies on cross-origin requests.

## Summary

The integration points are:

1. **Rust side:** Enable the `openapi` feature flag, call `yauth::routes_meta::build_openapi_spec()`, and merge the result into your existing utoipa spec before writing `openapi.json`.
2. **orval side:** No config changes needed -- it already generates from `openapi.json`. You get auth functions (login, register, logout, getSession, etc.) alongside your app's functions in the same generated client.
3. **Fetch mutator:** Add `credentials: "include"` so the session cookie is sent on every request automatically.
4. **No need for `@yackey-labs/yauth-client`:** Since your orval-generated client now includes all yauth endpoints, you do not need to install the separate npm package.

You do still want `@yackey-labs/yauth-ui-solidjs` (or the Vue equivalent) if you want pre-built login/register/MFA UI components -- those work independently of how your client is generated.
