# TypeScript / Vue / SolidJS setup

yauth ships a generated TypeScript HTTP client plus pre-built UI components, so
a frontend can talk to a yauth backend without hand-writing fetch calls. All
packages are published to npm under the `@yackey-labs/` scope and track the
backend's `openapi.json`.

## Packages

| Package                         | Purpose                                                        |
| ------------------------------- | ------------------------------------------------------------- |
| `@yackey-labs/yauth-client`     | Auto-generated HTTP client (orval reads the OpenAPI spec)     |
| `@yackey-labs/yauth-shared`     | Shared types (`AuthUser`, `AuthMethod`, AAGUID map)           |
| `@yackey-labs/yauth-ui-vue`     | Vue 3 components + composables                                 |
| `@yackey-labs/yauth-ui-solidjs` | SolidJS components + provider                                  |

> Migrating from the old `@yackey-labs/yauth-go-*` packages? Drop the `-go`
> infix — `@yackey-labs/yauth-go-client` → `@yackey-labs/yauth-client`.

## Install

```bash
# Vue
npm install @yackey-labs/yauth-client @yackey-labs/yauth-ui-vue
# SolidJS
npm install @yackey-labs/yauth-client @yackey-labs/yauth-ui-solidjs
# or pnpm / yarn / bun
```

## Get set up (Vue, end to end)

1. **Run a yauth backend** with the routes mounted under a prefix (default
   `/api/auth`). See `yauth docs readme` and `yauth init` for the server side.

2. **Install the Vue plugin** in `main.ts` before mounting. `baseUrl` is the
   only required option and must match the backend prefix:

   ```ts
   import { createApp } from 'vue'
   import { YAuthPlugin } from '@yackey-labs/yauth-ui-vue'
   import App from './App.vue'

   const app = createApp(App)
   app.use(YAuthPlugin, { baseUrl: '/api/auth' })
   app.mount('#app')
   ```

   To supply a pre-built client (custom fetch options / interceptors), pass the
   `client` option instead of `baseUrl`.

3. **Use the components.** They take **callback props** (React style), not Vue
   emits — `:on-success`, not `@success` (the emit form silently does nothing):

   ```vue
   <script setup lang="ts">
   import { LoginForm, useSession } from '@yackey-labs/yauth-ui-vue'
   import { useRouter } from 'vue-router'

   const router = useRouter()
   const { user } = useSession()
   </script>

   <template>
     <LoginForm :on-success="() => router.push('/dashboard')" />
   </template>
   ```

### Component prop API

| Component      | Prop        | Callback signature            | Notes                                    |
| -------------- | ----------- | ----------------------------- | ---------------------------------------- |
| `LoginForm`    | `onSuccess` | `(user: AuthUser) => void`    | After successful login                   |
| `LoginForm`    | `onMfa`     | `(pendingId: string) => void` | When the server returns `require_mfa`    |
| `RegisterForm` | `onSuccess` | `(message: string) => void`   | With the server's success message        |

### `useSession()`

Returns reactive session state plus helpers:
`{ user, loading, isAuthenticated, isLoading, isEmailVerified, userRole, userEmail, displayName, refetch, logout }`.
`user` is `null` when unauthenticated and an `AuthUser` after login. Call
`await logout()` to end the session.

## SolidJS

`@yackey-labs/yauth-ui-solidjs` mirrors the Vue package with a provider +
components. Wrap your app in the provider with the same `baseUrl`, then import
components from the package. The client and shared-types packages are identical
across frameworks.

## Regenerating the client

The client is generated from the backend's `openapi.json` via `orval`. After
changing backend routes, regenerate and the typed client + UI stay in sync.
The CI `openapi-fresh` job regenerates-and-compares to catch drift. Keep the
`openapi.json` the frontend builds against on the same yauth version as the
backend it calls.

## Runnable example

`examples/vue` is a full SPA wired against the `@yackey-labs/yauth-*` packages
end to end:

```bash
cd examples/vue && npm install && npm run dev
```

## Contributing to the packages

The commands above are for *consuming* the published packages — use whatever
package manager your app already uses (npm, pnpm, yarn, bun).

*Building* the packages in this repo is different: the `clients/` workspace is
**pnpm-only** (`packageManager: pnpm@9.x`, a committed `pnpm-lock.yaml`, a
`pnpm-workspace.yaml`, and `vp`/vite-plus scripts). To work on the client or UI
packages, use pnpm from `clients/`:

```bash
cd clients
pnpm install
pnpm run build        # build all packages
pnpm run generate     # regenerate the client from openapi.json
pnpm run validate     # lint + typecheck + build
```

