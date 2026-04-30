# yauth-go Vue Example

A minimal Vue 3 SPA that drives the yauth-go HTTP API end to end. Use it as
a reference for wiring `@yackey-labs/yauth-go-ui-vue` into a real app and
as a smoke test for the backend.

## Stack

- **Frontend** — Vue 3 + Vite + vue-router, using `@yackey-labs/yauth-go-ui-vue`
  for the `LoginForm`, `RegisterForm`, `useSession()` composable, and
  `YAuthPlugin` provider. `main.ts` constructs the client explicitly with
  `createYAuthClient({ baseUrl: "/api/auth" })` and passes it to the
  plugin — this avoids vite's bare-specifier resolution running at runtime
  inside the pre-built `ui-vue/dist`.
- **Backend** — `examples/vue/server` boots an in-memory SQLite database,
  wires the `email-password`, `status`, and `admin` plugins, seeds a demo
  admin user, and serves `/api/auth/*` on `:3000`.

## Try it for real

```bash
# 1. Build the workspace TS packages (one-time).
bun install
(cd packages/client   && bun run build)
(cd packages/shared   && bun run build)
(cd packages/ui-vue   && bun run build)

# 2. Start the Go backend (in-memory SQLite, demo admin seeded).
go run ./examples/vue/server
# → "yauth-go Vue example backend listening on :3000"

# 3. In a separate shell, start the Vue dev server.
cd examples/vue
bun dev
# → "Local: http://localhost:5173"
```

Open <http://localhost:5173> in a browser.

### Walkthrough

1. **Register** — `/register` → fill out the form → `POST /api/auth/register`
   returns `{message: "..."}` and sets the session cookie. The form
   redirects you to `/login` after the success toast.
2. **Login** — `/login` → enter the seeded admin
   `admin@example.com` / `correct horse battery staple` → `POST /api/auth/login`
   returns `{user: {...}}` and sets the cookie. The form redirects to
   `/dashboard`.
3. **Dashboard** — `/dashboard` reads `useSession()`, which calls
   `GET /api/auth/session`. The wrapped response (`{user, expires_at?}`)
   is unwrapped by the client so the `user` ref holds the bare user.
4. **Logout** — click *Logout* on the dashboard → `POST /api/auth/logout`
   clears the cookie → redirected back to `/login`.

### MFA (optional)

The seeded admin has no MFA enabled, but the `MfaSetup` and `MfaChallenge`
components from `@yackey-labs/yauth-go-ui-vue` work against the same
backend. To extend the example, mount `MfaSetup` on the dashboard and add
a route that the login flow redirects to when the server returns
`{require_mfa: true, pending_session_id: "..."}`.

## Why this exists

This example is the cross-language E2E sanity check for v0.1.0. The
backend uses the same `gormrepo` SQLite driver that the unit tests run
against, and the frontend uses the published TS client + UI components.
If both halves boot and the walkthrough flows complete in a browser, the
shape contracts in `openapi.json` are intact.
