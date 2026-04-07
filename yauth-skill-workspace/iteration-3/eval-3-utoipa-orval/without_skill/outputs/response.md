# Integrating yauth into an Existing Axum + utoipa + orval Pipeline

## Overview

yauth is designed as a plugin that merges into your Axum router. Since you already have a utoipa OpenAPI spec and orval-based TypeScript client generation, the key challenge is **merging yauth's auth routes into your existing OpenAPI spec** so that orval generates a single, unified client that covers both your app routes and yauth's auth routes.

## Step 1: Add yauth to Your Rust Dependencies

In your `Cargo.toml`, enable the features you need plus `openapi`:

```toml
[dependencies]
yauth = { version = "0.3", features = ["email-password", "mfa", "bearer", "api-key", "openapi"] }
yauth-entity = { version = "0.3", features = ["email-password", "mfa", "bearer", "api-key"] }
yauth-migration = { version = "0.3", features = ["email-password", "mfa", "bearer", "api-key"] }
```

The `openapi` feature flag is critical -- it enables `utoipa::ToSchema` derives on all yauth request/response types and exposes the OpenAPI spec builder.

## Step 2: Build yauth and Merge the Router

```rust
use yauth::{YAuthBuilder, YAuthConfig, YAuthState};
use yauth::plugins::email_password::EmailPasswordConfig;
use yauth::plugins::mfa::MfaConfig;
use yauth::plugins::bearer::BearerConfig;

// Build yauth
let yauth = YAuthBuilder::new(pool.clone(), yauth_config)
    .with_email_password(ep_config)
    .with_mfa(mfa_config)
    .with_bearer(bearer_config)
    .build();

// Get yauth's router (mounted under /auth by convention)
let yauth_router = yauth.router();
let yauth_state = yauth.into_state();

// Merge into your existing app router
let app = Router::new()
    .nest("/auth", yauth_router)
    .merge(your_existing_routes)
    .with_state(your_app_state);
```

## Step 3: Merge OpenAPI Specs

This is the most important part for preserving your existing pipeline. yauth (with the `openapi` feature) provides a `routes_meta` module that builds its portion of the OpenAPI spec programmatically. You need to merge yauth's paths and schemas into your existing utoipa-generated spec.

### Option A: Merge at the utoipa Level (Recommended)

If your app uses `#[derive(OpenApi)]` with `utoipa`, you can merge yauth's spec into yours:

```rust
use utoipa::OpenApi;

// Your existing OpenAPI spec
#[derive(OpenApi)]
#[openapi(
    paths(
        // your existing paths...
        your_handler_1,
        your_handler_2,
    ),
    components(schemas(
        // your existing schemas...
        YourRequest,
        YourResponse,
    ))
)]
struct ApiDoc;

fn build_merged_openapi() -> utoipa::openapi::OpenApi {
    let mut spec = ApiDoc::openapi();

    // Get yauth's OpenAPI spec fragment
    // yauth's routes_meta module builds paths + schemas per enabled feature
    let yauth_spec = yauth::routes_meta::build_openapi_spec();

    // Merge paths
    if let Some(yauth_paths) = yauth_spec.paths {
        for (path, item) in yauth_paths.paths {
            // Prefix with /auth to match your nest()
            spec.paths.paths.insert(format!("/auth{}", path), item);
        }
    }

    // Merge component schemas
    if let Some(yauth_components) = yauth_spec.components {
        let components = spec.components.get_or_insert_with(Default::default);
        for (name, schema) in yauth_components.schemas {
            components.schemas.insert(name, schema);
        }
    }

    spec
}
```

### Option B: Merge at the JSON Level

If merging at the Rust level is awkward, you can generate two separate JSON files and merge them with a script before running orval:

```bash
# Generate your app's openapi.json (your existing process)
cargo run --bin generate-openapi > openapi-app.json

# Generate yauth's openapi.json
cargo run --bin generate-yauth-openapi > openapi-yauth.json

# Merge them (using jq or a custom script)
jq -s '
  .[0] * {
    paths: (.[0].paths + (.[1].paths | with_entries(.key = "/auth" + .key))),
    components: {
      schemas: ((.[0].components.schemas // {}) + (.[1].components.schemas // {}))
    }
  }
' openapi-app.json openapi-yauth.json > openapi.json
```

### Option C: Use yauth's Committed openapi.json

yauth commits its own `openapi.json` to the repo. You could reference it directly, but this is less ideal because it won't reflect your specific feature flag combination. Options A or B are preferred.

## Step 4: Configure orval for Session Cookies

This is where you ensure your generated client automatically carries the session cookie. The key is orval's **custom mutator** -- a wrapper around `fetch` that sets `credentials: 'include'`.

### orval.config.ts

```typescript
import { defineConfig } from 'orval';

export default defineConfig({
  api: {
    input: {
      target: './openapi.json',
    },
    output: {
      target: './src/generated.ts',
      client: 'fetch',
      // Point to your custom fetch mutator
      override: {
        mutator: {
          path: './src/mutator.ts',
          name: 'customFetch',
        },
      },
    },
  },
});
```

### src/mutator.ts

This is the custom fetch wrapper that ensures cookies are sent with every request:

```typescript
interface MutatorOptions {
  url: string;
  method: string;
  headers?: Record<string, string>;
  data?: unknown;
  signal?: AbortSignal;
}

export const customFetch = async <T>(options: MutatorOptions): Promise<T> => {
  const { url, method, headers = {}, data, signal } = options;

  const baseUrl = import.meta.env.VITE_API_URL ?? '';

  const response = await fetch(`${baseUrl}${url}`, {
    method,
    // This is the critical line -- 'include' sends cookies cross-origin,
    // 'same-origin' sends them for same-origin requests only.
    // Use 'include' if your API is on a different subdomain.
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      // Forward OTel trace context headers if present
      ...headers,
    },
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
```

**If you already have a custom mutator**, just make sure it includes `credentials: 'include'` in the fetch options. That single property is what makes the browser send the `yauth_session` cookie automatically.

## Step 5: CORS Configuration

Your Axum CORS configuration must allow credentials and the correct headers:

```rust
use tower_http::cors::{CorsLayer, Any};
use http::{HeaderName, Method};

let cors = CorsLayer::new()
    .allow_origin([
        "https://yourapp.yackey.cloud".parse().unwrap(),
        // Add localhost for dev
        "http://localhost:5173".parse().unwrap(),
    ])
    // CRITICAL: allow_credentials is required for cookies
    .allow_credentials(true)
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH])
    .allow_headers([
        HeaderName::from_static("content-type"),
        HeaderName::from_static("authorization"),
        // Required for OTel trace propagation
        HeaderName::from_static("traceparent"),
        HeaderName::from_static("tracestate"),
        // Required for API key auth
        HeaderName::from_static("x-api-key"),
    ]);
```

**Important:** When `allow_credentials(true)` is set, you cannot use wildcard (`Any`) for `allow_origin`. You must list specific origins.

## Step 6: Use the Generated Client

After running `bun generate` (or `bunx orval`), your generated client will have both your app endpoints and yauth auth endpoints. Usage looks like:

```typescript
import { postAuthLogin, getAuthSession, postAuthLogout } from './generated';

// Login -- cookie is set automatically by the server's Set-Cookie header
await postAuthLogin({ email: 'user@example.com', password: 'secret' });

// Subsequent calls automatically include the session cookie
const session = await getAuthSession();
console.log(session.user); // AuthUser object

// Your app's own endpoints also carry the cookie automatically
const data = await getYourAppEndpoint({ id: '123' });

// Logout
await postAuthLogout();
```

## Step 7: yauth's Tri-Mode Auth Middleware

yauth checks credentials in this order on protected routes:

1. **Session cookie** (`yauth_session`) -- checked first, works automatically with `credentials: 'include'`
2. **Bearer token** (`Authorization: Bearer <jwt>`) -- if the `bearer` feature is enabled
3. **API key** (`X-Api-Key: <key>`) -- if the `api-key` feature is enabled

For browser-based apps, the session cookie approach (steps 4-5 above) is the simplest and most secure. Bearer tokens are useful for mobile apps or service-to-service calls.

## Summary Checklist

1. Add `yauth` with the `openapi` feature flag
2. Build yauth with `YAuthBuilder` and nest its router under `/auth`
3. Merge yauth's OpenAPI paths/schemas into your existing spec (Option A recommended)
4. Ensure your orval custom mutator uses `credentials: 'include'`
5. Configure CORS with `allow_credentials(true)` and explicit origins
6. Run `bun generate` to regenerate your unified TypeScript client
7. All API calls (both your app and auth endpoints) will automatically carry the session cookie

## Common Pitfalls

- **Forgetting `credentials: 'include'`** -- without this, the browser will not send cookies on fetch requests, and you will get 401 on every authenticated call.
- **Using wildcard CORS origins with credentials** -- browsers reject `Access-Control-Allow-Origin: *` when credentials are included. You must list specific origins.
- **Schema name collisions** -- if your app has a type named `User` and yauth has `AuthUser`, there should be no collision. But check for any overlapping schema names when merging.
- **Path prefix mismatch** -- if you `nest("/auth", yauth_router)` in Axum, make sure the merged OpenAPI paths also have the `/auth` prefix.
- **Missing `openapi` feature flag** -- without it, yauth's types won't derive `ToSchema` and you won't be able to build the OpenAPI spec fragment.
