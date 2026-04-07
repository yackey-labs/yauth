# Integrating yauth Into an Existing Axum App With utoipa + orval

You already have a working pipeline: Rust types with `utoipa::ToSchema` + route annotations generate `openapi.json`, and orval turns that into a TypeScript client. Adding yauth should extend this pipeline, not replace it.

## 1. Add yauth to Your Rust Project

In your `Cargo.toml`, enable the features you need plus `openapi`:

```toml
[dependencies]
yauth = { version = "0.3", features = ["email-password", "passkey", "mfa", "bearer", "api-key", "openapi"] }
```

The `openapi` feature is critical -- it makes yauth's request/response types derive `utoipa::ToSchema` and exposes route metadata you can merge into your own OpenAPI spec.

## 2. Merge yauth's OpenAPI Spec Into Yours

yauth provides its own OpenAPI paths and schemas via `routes_meta.rs`. You need to merge these into your app's `utoipa::OpenApi` definition rather than maintaining two separate specs.

The approach:

```rust
use utoipa::OpenApi;

// Your existing app OpenAPI definition
#[derive(OpenApi)]
#[openapi(
    paths(
        // your existing paths...
        my_app::get_items,
        my_app::create_item,
    ),
    components(schemas(
        // your existing schemas...
        my_app::Item,
        my_app::CreateItemRequest,
    ))
)]
struct AppApi;

fn build_openapi_spec(yauth_state: &yauth::YAuthState) -> utoipa::openapi::OpenApi {
    let mut spec = AppApi::openapi();

    // Merge yauth's OpenAPI spec into yours
    let yauth_spec = yauth::openapi_spec(yauth_state);
    spec.merge(yauth_spec);

    spec
}
```

If yauth does not expose a direct `openapi_spec()` function, you may need to build it from yauth's route metadata. Check what yauth exports under the `openapi` feature flag. The key principle is: produce a single merged `openapi.json` that contains both your app's routes and yauth's auth routes.

## 3. Mount yauth's Router Into Your Axum App

```rust
use yauth::{YAuthBuilder, YAuthConfig, EmailPasswordConfig};

#[tokio::main]
async fn main() {
    let pool = yauth::create_pool(&database_url, "public").await.unwrap();

    let config = YAuthConfig {
        db_schema: "public".to_string(),
        // ... other config
    };

    let yauth = YAuthBuilder::new(pool.clone(), config)
        .with_email_password(EmailPasswordConfig::default())
        // .with_passkey(passkey_config)
        // .with_mfa(mfa_config)
        // .with_bearer(bearer_config)
        .build();

    let yauth_router = yauth.router();
    let yauth_state = yauth.into_state();

    let app = Router::new()
        // Your existing routes
        .route("/api/items", get(get_items).post(create_items))
        // Nest yauth routes under /auth (or wherever you prefer)
        .nest("/auth", yauth_router)
        // Apply yauth's auth middleware to your protected routes
        .with_state(yauth_state);

    // Write merged OpenAPI spec
    let spec = build_openapi_spec(&yauth_state);
    std::fs::write("openapi.json", spec.to_pretty_json().unwrap()).unwrap();

    axum::serve(listener, app).await.unwrap();
}
```

### Protecting Your App's Routes

yauth injects `Extension<AuthUser>` on authenticated requests. Extract it in your handlers:

```rust
use yauth::AuthUser;

async fn get_items(
    Extension(user): Extension<AuthUser>,
) -> impl IntoResponse {
    // user.id, user.email, etc. are available
    // ...
}
```

For routes that require auth, nest them under yauth's auth middleware layer rather than making them fully public.

## 4. Configure orval for Session Cookies

This is the critical part for your client generation pipeline. You need orval's generated client to automatically include credentials (cookies) on every request.

### Custom Fetch Mutator

Create a custom mutator file that orval will use instead of raw `fetch`. This is how yauth's own `@yackey-labs/yauth-client` handles it:

```typescript
// src/api/mutator.ts

type MutatorOptions = {
  url: string;
  method: string;
  headers?: Record<string, string>;
  data?: unknown;
  params?: Record<string, string>;
  signal?: AbortSignal;
};

export const customFetch = async <T>(options: MutatorOptions): Promise<T> => {
  const { url, method, headers, data, params, signal } = options;

  const searchParams = params
    ? '?' + new URLSearchParams(params).toString()
    : '';

  const response = await fetch(`${url}${searchParams}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    // THIS IS THE KEY LINE: credentials: 'include' sends cookies
    credentials: 'include',
    body: data ? JSON.stringify(data) : undefined,
    signal,
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw {
      status: response.status,
      statusText: response.statusText,
      body: errorBody,
    };
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
};

export default customFetch;
```

### orval Configuration

In your `orval.config.ts`, point the mutator at this custom fetch wrapper:

```typescript
// orval.config.ts
import { defineConfig } from 'orval';

export default defineConfig({
  myApp: {
    input: {
      target: './openapi.json',
    },
    output: {
      target: './src/api/generated.ts',
      client: 'fetch',
      // Use your custom mutator so all requests include credentials
      override: {
        mutator: {
          path: './src/api/mutator.ts',
          name: 'customFetch',
        },
      },
    },
  },
});
```

Now every generated API function will go through `customFetch`, which sets `credentials: 'include'`. This means the browser automatically sends the yauth session cookie (`yauth_session` or similar) on every API call without you doing anything per-request.

## 5. CORS Configuration

For cookies to work cross-origin, your Axum server must be configured with the correct CORS policy:

```rust
use tower_http::cors::{CorsLayer, AllowOrigin, AllowHeaders, AllowMethods};
use http::{header, Method};

let cors = CorsLayer::new()
    .allow_origin(AllowOrigin::exact(
        "http://localhost:5173".parse().unwrap()  // your frontend dev server
    ))
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH])
    .allow_headers([
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        // Required for OpenTelemetry trace propagation
        "traceparent".parse().unwrap(),
        "tracestate".parse().unwrap(),
        // Required for API key auth
        "x-api-key".parse().unwrap(),
    ])
    // THIS IS REQUIRED for cookies to be sent cross-origin
    .allow_credentials(true);

let app = Router::new()
    .nest("/auth", yauth_router)
    .route("/api/items", get(get_items))
    .layer(cors)
    .with_state(yauth_state);
```

Key points:
- `allow_credentials(true)` is mandatory for `credentials: 'include'` to work.
- You cannot use `AllowOrigin::any()` with `allow_credentials(true)` -- you must specify exact origins.
- Include `traceparent` and `tracestate` headers if you use OpenTelemetry.

## 6. Regeneration Workflow

Your pipeline stays the same, just with yauth's routes included:

```bash
# 1. Build the Rust binary that writes the merged openapi.json
#    (or use a dedicated bin target / build script that generates it)
cargo run --features openapi -- --generate-openapi

# 2. Generate TypeScript client from the merged spec
bunx orval

# 3. Commit both openapi.json and generated.ts
```

If you want a single `bun generate` command, add it to your `package.json`:

```json
{
  "scripts": {
    "generate:openapi": "cargo run --features openapi -- --generate-openapi",
    "generate:client": "bunx orval",
    "generate": "bun run generate:openapi && bun run generate:client",
    "generate:check": "bun run generate && git diff --exit-code openapi.json src/api/generated.ts"
  }
}
```

## 7. Using the Generated Client

The generated client will have functions for both your app's endpoints and yauth's auth endpoints:

```typescript
import {
  // yauth-generated functions
  postAuthLogin,
  postAuthRegister,
  postAuthLogout,
  getAuthSession,
  // your app's generated functions
  getApiItems,
  postApiItems,
} from './api/generated';

// Login -- cookie is set automatically by the server response
await postAuthLogin({ email: 'user@example.com', password: 'secret' });

// Subsequent calls automatically include the session cookie
const items = await getApiItems();

// Check current session
const session = await getAuthSession();
```

Because `customFetch` sets `credentials: 'include'` on every request, the session cookie flows automatically after login. No token management code needed on the client side.

## Summary

| Concern | Solution |
|---|---|
| Keep one OpenAPI spec | Merge yauth's spec into your existing `utoipa::OpenApi` |
| Keep one orval pipeline | Single `orval.config.ts` pointing at the merged `openapi.json` |
| Session cookie on all requests | Custom orval mutator with `credentials: 'include'` |
| CORS for cookies | `allow_credentials(true)` + explicit origin (no wildcard) |
| Auth in your handlers | Extract `Extension<AuthUser>` from yauth's middleware |
| CI validation | `bun generate:check` fails if generated client is stale |

The main principle: yauth slots into your existing architecture as an additional set of routes and schemas that get merged into the same OpenAPI spec you already produce. The orval mutator ensures cookies flow automatically. You do not need a separate client package for auth -- it all comes out of the same generated client.
