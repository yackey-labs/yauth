# yauth-go Vue Example

A minimal Vue 3 SPA that drives the yauth-go HTTP API end to end. Use it as
a reference for wiring `@yackey-labs/yauth-ui-vue` into a real app and as a
smoke test for the backend.

> **Note** — the TypeScript client and UI components live in the
> [yauth (Rust)](https://github.com/yackey-labs/yauth) repo. Both backends
> share a single set of npm packages (`@yackey-labs/yauth-{client,shared,ui-vue,ui-solidjs}`)
> built from a converged OpenAPI spec. The previously-published
> `@yackey-labs/yauth-go-*` packages are deprecated; their last version
> redirects to the unified ones.

## Stack

- **Frontend** — Vue 3 + Vite + vue-router, using `@yackey-labs/yauth-ui-vue`
  for the `LoginForm`, `RegisterForm`, `useSession()` composable, and
  `YAuthPlugin` provider. `main.ts` constructs the client explicitly with
  `createYAuthClient({ baseUrl: "/api/auth" })` and passes it to the
  plugin.
- **Backend** — `examples/vue/server` boots an in-memory repository,
  wires the `email-password`, `status`, and `admin` plugins, seeds a demo
  admin user, and serves `/api/auth/*` on `:3000`.

## Try it for real

```bash
# 1. Install JS deps (pulls @yackey-labs/yauth-* from npm).
cd examples/vue
npm install

# 2. Start the Go backend (in-memory repository, demo admin seeded).
cd ../..
go run ./examples/vue/server
# → "yauth-go Vue example backend listening on :3000"

# 3. In a separate shell, start the Vue dev server.
cd examples/vue
npm run dev
# → "Local: http://localhost:5173"
```

Open <http://localhost:5173> in a browser.

### Walkthrough

1. **Register** — `/register` → fill out the form → `POST /api/auth/register`
   returns `{user: {...}, message?}` and sets the session cookie. The form
   redirects you to `/login` after the success toast.
2. **Login** — `/login` → enter the seeded admin
   `admin@example.com` / `correct horse battery staple` → `POST /api/auth/login`
   returns 200 (or `{mfa_required, pending_session_id}` if MFA is on) and
   sets the cookie. The form redirects to `/dashboard`.
3. **Dashboard** — `/dashboard` reads `useSession()`, which calls
   `GET /api/auth/session`. The wrapped response (`{user, expires_at?}`)
   is unwrapped by the client so the `user` ref holds the bare user.
4. **Logout** — click *Logout* on the dashboard → `POST /api/auth/logout`
   clears the cookie → redirected back to `/login`.

### MFA (optional)

The seeded admin has no MFA enabled, but the `MfaSetup` and `MfaChallenge`
components from `@yackey-labs/yauth-ui-vue` work against the same backend.
To extend the example, mount `MfaSetup` on the dashboard and add a route
that the login flow redirects to when the server returns
`{mfa_required: true, pending_session_id: "..."}`.

## Why this exists

This example is the cross-language E2E sanity check. The backend uses the
in-memory `memrepo` repository, and the
frontend uses the published TS client + UI components from the yauth
repo. If both halves boot and the walkthrough flows complete in a
browser, the shape contracts in `openapi.json` are intact.
