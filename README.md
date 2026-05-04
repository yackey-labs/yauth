# yauth-go

Modular, plugin-based authentication library for Go (`net/http`) with a
generated TypeScript client, Vue 3 components, and SolidJS components.

- **Plugin system** — register only the auth methods you want
- **Two database backends** — Postgres + SQLite via GORM (the Rust crate
  ships 14 backend permutations; Go's GORM reach covers the two that
  matter cleanly — see "Pick a Backend" for the pluggable contract)
- **Tri-mode auth** — session cookies, JWT bearer tokens, and `X-Api-Key`
  headers, all simultaneous; resolved into one `*domain.AuthUser`
- **Full OAuth2 / OIDC provider** — authorization code + PKCE, device
  flow, client credentials; published JWKS for cross-trust-domain
  validation
- **OpenAPI 3.1 spec out of the box** — code-first via [Huma](https://huma.rocks),
  served at `/openapi.json` + a Stoplight Elements UI at `/docs`
- **TypeScript included** — auto-generated HTTP client (`orval`) plus
  pre-built Vue 3 and SolidJS components

## Try It in 30 Seconds

No external database needed. SQLite + email/password ships first.

```bash
go get github.com/yackey-labs/yauth-go@latest
```

```go
package main

import (
    "context"
    "log"
    "net/http"

    yauth "github.com/yackey-labs/yauth-go"
    "github.com/yackey-labs/yauth-go/openapi"
    "github.com/yackey-labs/yauth-go/plugins/emailpassword"
    "github.com/yackey-labs/yauth-go/repo/gormrepo"
)

func main() {
    db, err := gormrepo.OpenSQLite("file::memory:?cache=shared&_pragma=foreign_keys(1)")
    if err != nil { log.Fatal(err) }
    if err := gormrepo.Migrate(context.Background(), db); err != nil { log.Fatal(err) }

    ya, err := yauth.New(gormrepo.New(db), yauth.NewDefaultConfig()).
        WithPlugin(emailpassword.New(emailpassword.Config{})).
        Build()
    if err != nil { log.Fatal(err) }

    mux := http.NewServeMux()
    mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
    mux.Handle("/", openapi.YAuth(ya))           // /openapi.json + /docs
    log.Fatal(http.ListenAndServe(":3000", mux))
}
```

```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"yauth-quickstart!Aq7z"}'

# Login (cookie carries the session)
curl -i -c jar.txt -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"yauth-quickstart!Aq7z"}'

# Authenticated session
curl -b jar.txt http://localhost:3000/api/auth/session

# Live API docs
open http://localhost:3000/docs
```

> **HIBP check:** Registration rejects passwords found in the
> [HaveIBeenPwned](https://haveibeenpwned.com/Passwords) database (the
> k-anonymity range API — no full password is sent). The example
> password above passes. To disable it during local development:
>
> ```go
> emailpassword.New(emailpassword.Config{
>     HIBPCheck:    false,
>     HIBPCheckSet: true,   // sentinel — without this, false is ignored
> })
> ```
>
> `HIBPCheckSet` is required because the zero value of `bool` is `false`,
> so setting only `HIBPCheck: false` is indistinguishable from "not
> configured" and the default (enabled) wins.

A runnable copy lives at [`examples/sqlite/main.go`](examples/sqlite/main.go).

### Try it for real (Vue + Go end-to-end)

`examples/vue` is a full SPA + Go backend wired together. It boots the
in-memory SQLite repo, the email-password / status / admin plugins, and
a Vue 3 frontend that uses `@yackey-labs/yauth-ui-vue` for the
login/register/dashboard flow. See
[`examples/vue/README.md`](examples/vue/README.md) for the walkthrough;
the short version:

```bash
# Install JS deps from npm (the unified yauth client + UI components).
cd examples/vue && npm install && cd ../..

# terminal 1 — backend on :3000
go run ./examples/vue/server

# terminal 2 — frontend on :5173 (proxies /api → :3000)
cd examples/vue && npm run dev
```

Open <http://localhost:5173>, log in with the seeded admin
(`admin@example.com` / `correct horse battery staple`), and watch
`useSession()` populate the dashboard from `GET /api/auth/session`.

**CORS for SPA development:** When your frontend runs on a different
origin (e.g. Vite on `:5173`, backend on `:3000`), browsers block
cross-origin requests unless the server sets CORS headers. The example
uses a Vite proxy so CORS is not needed there, but if you wire up the
backend directly (no proxy), configure it via `YAuthConfig.CORS`:

```go
cfg := yauth.NewDefaultConfig()
cfg.CORS = yauth.CORSConfig{
    AllowedOrigins:   []string{"http://localhost:5173"},
    AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowedHeaders:   []string{"Content-Type"},
    AllowCredentials: true,   // required — session cookies are credentials
}
ya, err := yauth.New(repo, cfg).WithPlugin(...).Build()
```

`AllowCredentials: true` is essential — without it the browser refuses
to include cookies on cross-origin requests, breaking session auth.

## How It Works

**Plugins** implement `plugin.Plugin` — `Name()` and
`Routes(host PluginHost, mux *http.ServeMux, prefix string)`. Each plugin
owns its own URL paths and uses the `PluginHost` to reach the repository,
the auth middleware, the event bus, and config. Plugins can also
implement `events.Handler` to short-circuit decisions across the
codebase (e.g., the lockout plugin watches `login.failed` events; the
mfa plugin returns `RequireMfa` on `login.succeeded` so the caller
doesn't issue a session yet). Plugins can implement `ShutdownAware` to
drain background work before process exit (the webhooks dispatcher uses
this).

**Tri-mode auth middleware** (`middleware.Middleware`) tries credentials
in order: session cookie, then `Authorization: Bearer <jwt>`, then
`X-Api-Key`. The first plugin that registers an `AuthResolver` for a
given mode handles it. On success the resolved `*domain.AuthUser` is
injected via `context.WithValue`; retrieve it with
`middleware.AuthUserFromContext(ctx)`.

**Protecting your own routes** — wrap any `http.Handler` or `http.HandlerFunc`
with the helpers on `ya.Middleware()`:

```go
// Require any authenticated user
mux.Handle("/api/profile", ya.Middleware().RequireAuth(profileHandler))

// Require admin role
mux.Handle("/api/admin/", ya.Middleware().RequireAdmin(adminHandler))

// Extract the resolved user inside a handler
func profileHandler(w http.ResponseWriter, r *http.Request) {
    user := middleware.AuthUserFromContext(r.Context()) // *domain.AuthUser
    fmt.Fprintf(w, "hello %s", user.Email)
}
```

`RequireAuth` returns `401` for unauthenticated requests; `RequireAdmin`
returns `403` for non-admin users. Import `middleware` from
`github.com/yackey-labs/yauth-go/middleware`.

**Event system** — every authentication operation emits an
`events.AuthEvent` (`UserRegistered`, `LoginAttempt`, `LoginSucceeded`,
`LoginFailed`, `Logout`, `PasswordChanged`, ...). Handlers respond with
`Continue`, `Block { status, message }`, or `RequireMfa { pending_session_id }`.
The first non-Continue decision short-circuits the chain.

## Pick a Backend

| Backend | Constructor | Database |
| --- | --- | --- |
| GORM Postgres | `gormrepo.OpenPostgres(dsn)` | PostgreSQL |
| GORM SQLite   | `gormrepo.OpenSQLite(dsn)`   | SQLite (incl. `:memory:`) |
| GORM MySQL    | `gormrepo.OpenMySQL(dsn)`    | MySQL / MariaDB |
| Redis cache   | `redisrepo.New(inner, client, opts)` | — wraps any backend; caches sessions, rate limits, and revocations in Redis |
| In-memory     | `memrepo.New()`              | — no persistence; for testing and zero-config quickstart |

**Zero-config quickstart with `memrepo`** — no database, no migrations,
no `context` import needed:

```go
package main

import (
    "log"
    "net/http"

    yauth "github.com/yackey-labs/yauth-go"
    "github.com/yackey-labs/yauth-go/plugins/emailpassword"
    "github.com/yackey-labs/yauth-go/repo/memrepo"
)

func main() {
    ya, err := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).
        WithPlugin(emailpassword.New(emailpassword.Config{})).
        Build()
    if err != nil { log.Fatal(err) }

    mux := http.NewServeMux()
    mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
    log.Fatal(http.ListenAndServe(":3000", mux))
}
```

The Rust crate ships 14 ORM/dialect permutations (Diesel, sqlx, SeaORM,
Toasty across PG/MySQL/SQLite). yauth-go covers PG, SQLite, and MySQL via
GORM and exposes the `repo.Repository` interface as the extension point.
New backends plug in by implementing `repo.Repository` + the per-feature
sub-interfaces under `repo/`. A conformance harness at `repo/conformance/`
validates any new backend against the full interface contract.

Migrations run via `gormrepo.Migrate(ctx, db)` (uses GORM `AutoMigrate`
under the hood).

## Pick Your Plugins

| Plugin           | Package                      | Status |
| ---------------- | ---------------------------- | ------ |
| email-password   | `plugins/emailpassword`      | ✅     |
| bearer JWT       | `plugins/bearer`             | ✅     |
| api-key          | `plugins/apikey`             | ✅     |
| magic-link       | `plugins/magiclink`          | ✅     |
| account-lockout  | `plugins/lockout`            | ✅     |
| status           | `plugins/status`             | ✅     |
| admin            | `plugins/admin`              | ✅     |
| MFA (TOTP)       | `plugins/mfa`                | ✅     |
| passkey          | `plugins/passkey`            | ✅     |
| OAuth client     | `plugins/oauth`              | ✅     |
| webhooks         | `plugins/webhooks`           | ✅     |
| asymmetric-jwt   | `plugins/asymjwt`            | ✅     |
| oidc             | `plugins/oidc`               | ✅     |
| oauth2-server    | `plugins/oauth2server`       | ✅     |

Every plugin in the table maps 1:1 to a Rust feature flag. Each ships
with one or more runnable examples under [`examples/`](examples/).

### Webhooks lifecycle

The webhooks plugin starts a background worker pool when `Build()` runs.
To drain in-flight deliveries on process exit, call `ya.Shutdown(ctx)` —
it invokes `Shutdown(ctx)` on every plugin that implements
`plugin.ShutdownAware`. Pair the call with a context deadline so a stuck
receiver cannot wedge process exit:

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
_ = ya.Shutdown(ctx)
```

See [`examples/webhooks/main.go`](examples/webhooks/main.go) for a
SIGTERM-aware setup with an in-process receiver.

## Configuration

`yauth.YAuthConfig` is the runtime config shape (cookie name/domain,
session TTL, etc.). The companion package `yauthcfg` parses an external
YAML/TOML config + `YAUTH_*` environment variables into a fully-resolved
`yauth.YAuthConfig`. Use it whenever you want config-driven setups
(twelve-factor, k8s ConfigMap-backed, etc.).

Notable fields beyond cookie/session settings:

| Field | Default | Purpose |
| --- | --- | --- |
| `AllowSignups` | `true` | Set `false` to disable new user registration (`SIGNUPS_DISABLED` 403) |
| `AutoAdminFirstUser` | `false` | Promote the first registered user to role `admin` |
| `CORS.AllowedOrigins` | `[]` (off) | CORS middleware; empty slice disables it entirely |
| `AllowAdminMachineCallers` | `false` | Allow bearer/API-key callers to pass `RequireAdmin` (default: cookie-only) |
| `RateLimit.*` | various | Per-operation max+window pairs; `Max=0` disables that operation's limit |
| `SessionBinding.BindIP/UA` | `false` | Reject sessions on IP or User-Agent mismatch |

To layer a Redis read-cache over any primary backend, add a `cache:` block
to `yauth.yaml`:

```yaml
cache:
  enabled: true
  provider: redis
  redis_addr: "localhost:6379"
  key_prefix: "yauth:"   # optional; default "yauth:"
```

Or in Go: `redisrepo.New(primaryRepo, redisClient, redisrepo.Options{})`.
The decorator accelerates session lookup, challenge reads, revocation
checks, and rate-limit counters without changing the `repo.Repository`
interface seen by the rest of the library.

The `yauth` CLI (`cmd/yauth`) is the operator-facing companion, mirroring
`cargo-yauth`:

```bash
go install github.com/yackey-labs/yauth-go/cmd/yauth@latest

yauth init               # scaffold yauth.yaml
yauth migrate up         # run AutoMigrate against the configured DSN
yauth check              # validate yauth.yaml + reachability
yauth gen-secrets        # cryptographically random session/JWT secrets
yauth gen-keys --type RS256 --out ./keys # asymmetric JWT keypair
yauth status             # ping the running yauth instance
yauth dump-schema        # emit the table layout
yauth version            # version info
```

## Telemetry

`telemetry` wraps OpenTelemetry tracing. Every plugin handler runs inside
a server span when telemetry is enabled, and outbound HTTP from the
webhooks dispatcher carries traceparent headers automatically.

```go
shutdown, err := telemetry.Init(ctx, telemetry.Config{
    Enabled:     true,
    ServiceName: "my-app",
    Endpoint:    "otlp://otel-collector:4317",
})
defer shutdown(context.Background())

ya, _ := yauth.New(repo, cfg).
    WithTelemetry(telemetry.DefaultConfig()).
    WithTelemetryShutdown(shutdown).
    Build()
```

## OpenAPI

The OpenAPI 3.1 spec for every yauth-go route is authored in
`openapi/spec.go` using the
[Huma](https://github.com/danielgtaylor/huma) primitives — code-first,
the same philosophy as the Rust `utoipa` integration.

Why Huma over schema-first generators (e.g. `ogen`)? The plugins are
hand-written `net/http` handlers that already exist; rewriting every
plugin to a schema-first request/response struct would change the
runtime surface. Huma's primitive types (`*huma.OpenAPI`,
`huma.Operation`, `huma.Schema`, `huma.Registry`) let us declare the
spec by hand without touching plugin code, which is exactly the
abstraction we needed.

```bash
go generate ./openapi/   # writes openapi.json at the repo root
```

`openapi.YAuth(ya)` returns an `http.Handler` that serves
`/openapi.json` and a Stoplight Elements UI at `/docs`. Mount it
alongside your main router:

```go
mux := http.NewServeMux()
mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
mux.Handle("/", openapi.YAuth(ya))
```

> **Note:** The `ya` argument is currently unused — the spec is fully
> static and built at startup. The parameter exists so the API can later
> embed runtime fields (e.g. loaded plugin names) without a breaking
> change. If you prefer, `openapi.Handler()` is an identical no-arg
> alternative.

## TypeScript / Vue / SolidJS

The TypeScript client and UI components live in the
[yauth (Rust)](https://github.com/yackey-labs/yauth) repo. yauth-go's
`openapi.json` is converged with yauth's, so a single set of npm packages
serves both backends:

| Package                            | Purpose                                                        |
| ---------------------------------- | -------------------------------------------------------------- |
| `@yackey-labs/yauth-client`        | Auto-generated HTTP client (orval reads the unified spec)      |
| `@yackey-labs/yauth-shared`        | Shared types (`AuthUser`, `AuthMethod`, AAGUID map)            |
| `@yackey-labs/yauth-ui-vue`        | Vue 3 components + composables                                 |
| `@yackey-labs/yauth-ui-solidjs`    | SolidJS components + provider                                  |

```bash
npm install @yackey-labs/yauth-client @yackey-labs/yauth-ui-vue
# or pnpm / yarn / bun
```

> **Migrating from `@yackey-labs/yauth-go-*`:** the previously-published
> Go-suffixed packages are deprecated; their last release redirects to the
> unified ones. Drop the `-go` infix from imports and reinstall:
>
> ```diff
> - import { createYAuthClient } from "@yackey-labs/yauth-go-client";
> + import { createYAuthClient } from "@yackey-labs/yauth-client";
> ```

CI guarantees yauth and yauth-go's `openapi.json` files are equivalent
(see the `openapi-conformance` job and
[`scripts/openapi-conformance.py`](scripts/openapi-conformance.py)) — any
contract drift fails the build on both sides.

### Wiring the Vue plugin

Install `YAuthPlugin` in your app's `main.ts` before mounting:

```ts
import { createApp } from 'vue'
import { YAuthPlugin } from '@yackey-labs/yauth-ui-vue'
import App from './App.vue'

const app = createApp(App)
app.use(YAuthPlugin, { baseUrl: '/api/auth' })
app.mount('#app')
```

The `baseUrl` option is the only required field. It is passed to the
auto-generated client so every component and composable resolves to the
right API origin. To pass a pre-built client instance instead, use the
`client` option (useful when you need custom fetch options or interceptors).

#### Component prop API

Components use **callback props** (React style), not Vue emits. The pattern
is `<LoginForm :on-success="handler" />`:

| Component      | Prop         | Callback signature                         | Notes                                     |
| -------------- | ------------ | ------------------------------------------ | ----------------------------------------- |
| `LoginForm`    | `onSuccess`  | `(user: AuthUser) => void`                 | Called after successful login             |
| `LoginForm`    | `onMfa`      | `(pendingId: string) => void`              | Called when server returns `require_mfa`  |
| `RegisterForm` | `onSuccess`  | `(message: string) => void`                | Called with the server's success message  |

`useSession()` returns a `{ user, loading, error }` reactive ref; `user` is
`null` when unauthenticated and a bare `AuthUser` object after login. Call it
inside any component to read or react to the current session state.

```vue
<script setup lang="ts">
import { LoginForm } from '@yackey-labs/yauth-ui-vue'
import { useSession }  from '@yackey-labs/yauth-ui-vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const { user } = useSession()
</script>

<template>
  <LoginForm :on-success="() => router.push('/dashboard')" />
</template>
```

> **Note:** `@success="handler"` (Vue emit syntax) silently does nothing —
> you must use `:on-success="handler"` (prop binding).

## Status: Parity Table

| Rust feature           | yauth-go     | Notes                                                                                    |
| ---------------------- | ------------ | ---------------------------------------------------------------------------------------- |
| email-password         | ✅           | Argon2id, dummy-verify on miss to defeat enumeration timing                              |
| bearer JWT             | ✅           | HS256 access + opaque refresh; family rotation with reuse-revocation                     |
| api-key                | ✅           | `yak_<prefix>_<secret>` header credential, scoped + per-user cap                         |
| magic-link             | ✅           | LoggingMailer for dev; SMTP / Resend mailers via the `Mailer` interface                  |
| account-lockout        | ✅           | Exponential ladder; events-based interception of `login.attempt/failed/succeeded`        |
| status                 | ✅           | Admin-gated diagnostic                                                                   |
| admin                  | ✅           | Users CRUD-ish + ban/unban/impersonate + audit log                                       |
| MFA (TOTP)             | ✅           | TOTP secrets encrypted with AES-256-GCM at rest; backup codes hashed with SHA-256        |
| passkey                | ✅           | go-webauthn library; supports discoverable + non-discoverable flows                      |
| OAuth client           | ✅           | Google + GitHub + generic OIDC; tokens encrypted at rest; lockout-guard on unlink        |
| webhooks               | ✅           | HMAC-SHA256-signed delivery; async worker pool; replay through `/test`                   |
| asymmetric-jwt         | ✅           | Loads RS256 / ES256 keypair; publishes `/.well-known/jwks.json`                          |
| oidc                   | ✅           | Discovery + UserInfo (`/userinfo`); id_token issuance via oauth2-server                  |
| oauth2-server          | ✅           | RFC 6749 (auth code, refresh, client_credentials), RFC 7636 PKCE S256, RFC 7009 revoke, RFC 7662 introspect, RFC 8628 device flow |
| HIBP password breach   | ✅           | k-anonymity range query via `auth/hibp/`; default-on at registration and password change |
| Password history       | ✅           | Hashed history with configurable depth (email-password plugin)                           |
| Configurable complexity policy | ✅   | Uppercase / lowercase / digit / special / common-word / history checks (`auth/passwordpolicy/`) |
| Session IP/UA binding  | ⚙️ partial   | Sessions store IP + UA; rejection on mismatch is opt-in via a custom event handler      |
| OpenTelemetry          | ✅           | Server spans on every handler; configurable via `telemetry.Config`                       |
| OpenAPI                | ✅           | Huma-driven; equivalent to utoipa                                                        |
| Forgot/reset password  | ✅           | `/forgot-password` + `/reset-password` wired in email-password plugin                   |
| Email verification     | ✅           | `/verify-email` + `/resend-verification` wired in email-password plugin                  |
| 14 DB backends         | ⚙️ 3 of 14   | GORM PG + SQLite + MySQL; the `repo.Repository` interface is the extension point        |

`✅ done · ⚙️ partial · ❌ not yet`

## Project Layout

- `auth/`              — Argon2id, session token gen, cookies, HIBP check, password policy (leaf, no internal deps)
- `domain/`            — `User`, `Session`, `AuthUser`, ...
- `events/`            — `AuthEvent`, `Decision`, `Handler`
- `plugin/`            — `Plugin` and `PluginHost` interfaces
- `middleware/`        — tri-mode auth resolver + `RequireAuth` / `RequireAdmin` + CORS + rate-limit wrapper
- `repo/`              — repository interface + sub-interfaces
- `repo/gormrepo/`     — GORM-backed implementation (Postgres + SQLite + MySQL)
- `repo/redisrepo/`    — Redis caching decorator (sessions, rate limits, revocations)
- `repo/memrepo/`      — in-memory backend (testing + zero-config quickstart)
- `repo/conformance/`  — portable conformance harness for any `repo.Repository` implementation
- `plugins/`           — every plugin (one directory per name)
- `yautherr/`          — sentinel errors as a leaf package (avoids import cycles across sub-packages)
- `telemetry/`         — OpenTelemetry init + HTTP middleware
- `openapi/`           — hand-rolled Huma spec + `/docs` + `/openapi.json` handlers
- `yauthcfg/`          — YAML/TOML + env config loader (supports `cache:` block for Redis)
- `cmd/yauth/`         — operator CLI (cobra)
- `cmd/openapigen/`    — `go generate` target for `openapi.json`
- `examples/`          — runnable single-file demos per plugin (plus
  `examples/vue` — full SPA wired against the unified `@yackey-labs/yauth-*`
  npm packages)

## Development

```bash
# Go
go build ./...
go test ./...
go vet ./...
gofmt -l .                    # report any unformatted files
go generate ./openapi/        # regenerate openapi.json

# Lint (golangci-lint)
brew install golangci-lint
golangci-lint run ./...
```

The TS client + UI components live in the
[yauth (Rust)](https://github.com/yackey-labs/yauth) repo; develop them
there and consume from npm here.

## Releases

Releases are cut by pushing an annotated tag matching `v*.*.*`. The
`Release` workflow (`.github/workflows/release.yml`) runs
[GoReleaser](https://goreleaser.com) against `.goreleaser.yaml` and
publishes a GitHub Release with:

- `cmd/yauth` binaries for `linux` and `darwin` × `amd64` and `arm64`
  (4 archives, `tar.gz`).
- `SHA256SUMS` checksum file.
- An auto-generated changelog grouped by Conventional Commit type
  (`feat`, `fix`, `perf`, other).
- A `ghcr.io/yackey-labs/yauth-cli` Docker image tagged with the
  release version (and `latest`). Requires `Dockerfile.cli` at the
  repo root; the docker build step is skipped when `PUSH_DOCKER` is
  not `true`.

Cutting a release:

```bash
# 1. ensure main is green and openapi.json is in sync
git checkout main && git pull

# 2. tag and push
git tag -a v0.1.0 -m "yauth-go v0.1.0"
git push origin v0.1.0
```

Dry-run a release locally before tagging:

```bash
# Requires goreleaser installed (`brew install goreleaser`).
goreleaser release --snapshot --clean --skip=publish,docker
```

The `openapi-fresh` CI job guards against `openapi.json` drift: it
runs `go generate ./openapi/` and fails if the working tree is dirty.
Always commit a regenerated `openapi.json` alongside any handler
shape change.

### Cross-language conformance

The `openapi-conformance` CI job diffs the Rust crate's `openapi.json`
against this repo's `openapi.json` and uploads a markdown report as a
build artifact. It runs `scripts/openapi-diff.py`, which fetches the
Rust spec from `yackey-labs/yauth@main` and falls back to the snapshot
at `scripts/yauth-rust-openapi.json` when the network fetch fails.

Findings are categorised:

- `BREAKING` — path published by Rust but absent in Go.
- `MISSING`  — path+method present in Rust but absent in Go.
- `SHAPE`    — request/response top-level fields diverge for the same
  operation. (Deliberately shallow; nested-object changes are not
  flagged unless cheap to detect.)
- `DOC`      — description/summary-only differences.
- `GO-EXTRA` — routes Go ships that Rust does not. yauth-go is
  intentionally a "Go superset", so these are informational only and do
  not fail the check.

The job runs as `continue-on-error: true` during initial roll-out so the
report surfaces in the artifact tab without blocking merges. After one
round of triage, flip the flag so divergence becomes a hard gate. Run
the diff locally with:

```bash
python3 scripts/openapi-diff.py \
  ../yauth/openapi.json openapi.json
```

The script exits non-zero if any `BREAKING`, `MISSING`, or `SHAPE`
finding is reported.

## License

MIT
