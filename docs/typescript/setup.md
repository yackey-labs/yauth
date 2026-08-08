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

   > **Vite dev-mode trap — double-configure the client.** If your app ALSO
   > imports functions directly from `@yackey-labs/yauth-client` (e.g.
   > `ssooidcLoginOptions`, the admin functions), call
   > `configureClient({ baseUrl })` from your own import in `main.ts` too.
   > `configureClient` stores `{baseUrl}` in module-level state, and in dev
   > vite's dep optimizer inlines a SEPARATE copy of that state into the
   > ui-vue chunk vs your app's chunk — `YAuthPlugin` configures ui-vue's copy
   > while your direct calls run with `baseUrl: ""` and fetch your SPA's
   > index.html ("Unexpected token '<' … is not valid JSON"). Production
   > builds dedupe to one module instance, so the bug ONLY bites in dev.
   > Apps that build an instance via `createYAuthClient(...)` are unaffected.

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

| Component      | Prop             | Callback signature            | Notes                                                    |
| -------------- | ---------------- | ----------------------------- | -------------------------------------------------------- |
| `LoginForm`    | `onSuccess`      | `(user: AuthUser) => void`    | After a successful login (never fires with a null user)   |
| `LoginForm`    | `onMfaRequired`  | `(pendingId: string) => void` | When the server returns `require_mfa` — see MFA below     |
| `LoginForm`    | `onError`        | `(error: Error) => void`      | Login failed (also rendered inside the form)              |
| `RegisterForm` | `onSuccess`      | `(message: string) => void`   | With the server's success message                         |

### MFA step-up

MFA is **not** an error path. When the authenticating user has a verified TOTP
secret, `POST /login` returns **HTTP 200** with no session cookie and this body:

```json
{ "require_mfa": true, "pending_session_id": "…" }
```

The field is `require_mfa` (`mfa_required` is an unrelated org-policy field).
`LoginForm` handles this for you: it calls `onMfaRequired(pendingSessionId)`
instead of `onSuccess`, and you render `<MfaChallenge :pending-session-id="…">`,
which posts the code to `/mfa/verify` and only then issues the real session.
The headless equivalent is `useAuth().login()`, which resolves to
`{ mfaRequired: true, pendingSessionId }` on that branch and `{ user }` on a
plain login.

### `useSession()`

Returns reactive session state plus helpers:
`{ user, loading, isAuthenticated, isLoading, isEmailVerified, mustChangePassword, userRole, userEmail, displayName, refetch, logout }`.
`user` is `null` when unauthenticated and an `AuthUser` after login. Call
`await logout()` to end the session.

`isAuthenticated` is `true` only when the user is signed in **and** not in a
forced password-change state — so it stays `false` for a bootstrapped/reset
account until the password is rotated (see the next section). `mustChangePassword`
is the underlying flag; the prebuilt `LoginForm` handles the gate for you, so
most apps only need `isAuthenticated` and never read `mustChangePassword`
directly.

## Forced password change (`must_change_password`)

When an account is provisioned out-of-band — the secure **admin bootstrap**
(`yauth docs admin-bootstrap`), or an admin who set `must_change_password` — the
user can authenticate but is **locked out of every API route except
change-password, logout, and `/session` until they rotate the password.**

The login response shape is **unchanged**. `POST /login` still returns 200 with
`{ "user": { …, "must_change_password": true } }`, and `GET /session` surfaces
the same flag. The server-side enforcement is the new piece: any other
authenticated request from that cookie session returns:

```
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json

{ "title": "Forbidden", "status": 403, "detail": "password change required" }
```

**The prebuilt Vue UI handles this for you — no extra wiring.** Keep using
`LoginForm` and `useSession` exactly as in the happy-path setup above:

- When a login (or a page reload that resolves a must-change session) lands a
  user with `must_change_password: true`, **`LoginForm` self-gates**: it swaps
  its own body for the forced `ChangePasswordForm` and does **not** call
  `onSuccess` until the password is actually rotated. Because the host's usual
  `v-if="!isAuthenticated"` branch still renders `LoginForm` while the flag
  holds (see `isAuthenticated` above), this works across reloads with no host
  changes.
- On a successful change, `LoginForm` re-fetches the session (the server
  re-issues the cookie with the flag cleared), `isAuthenticated` flips `true`,
  and `onSuccess` fires with the now-unblocked user — your normal post-login
  navigation runs.
- **403 backstop.** When `YAuthPlugin` builds the client from `baseUrl`, it
  installs an `onError` that flips the gate on whenever any stray authenticated
  call returns the `403 "password change required"` problem — so an app that
  fired a data request before checking the session can't dead-end. If you pass
  your **own pre-built `client`** instead of `baseUrl`, forward its `onError`
  to the same effect; `useSession()` does not expose the flag-setter, so the
  simplest path is to let the plugin build the client, or to surface
  `must_change_password` from your own login/session handling.

The standalone `ChangePasswordForm` (for an in-app "change my password" screen)
and the `mustChangePassword` flag on `useSession()` remain available if you want
to build a custom gate; the login response shape and `AuthUser` are unchanged.

Machine credentials (bearer JWT / api-key) are never gated by this flag — it is
a password-login concept.

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

