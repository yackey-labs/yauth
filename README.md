# yauth

Modular, plugin-based authentication library for Go (`net/http`) with a
generated TypeScript client, Vue 3 components, and SolidJS components.

- **Plugin system** — register only the auth methods you want
- **Two repository backends** — native pgx/v5 + sqlc for Postgres
  (`pgxrepo`, goose migrations) and an in-memory backend (`memrepo`) for
  dev/tests; plus an optional Redis cache decorator (`redisrepo`)
- **Tri-mode auth** — session cookies, JWT bearer tokens, and `X-Api-Key`
  headers, all simultaneous; resolved into one `*domain.AuthUser`
- **Full OAuth2 / OIDC provider** — authorization code + PKCE, device
  flow, client credentials; published JWKS for cross-trust-domain
  validation
- **OpenAPI 3.1 spec out of the box** — code-first via [Huma](https://huma.rocks);
  the spec is auto-derived from the live route registrations and published as a
  generated, checked-in `openapi.json`
- **TypeScript included** — auto-generated HTTP client (`orval`) plus
  pre-built Vue 3 and SolidJS components

## Try It in 30 Seconds

No external database needed — the in-memory backend + email/password ships first.

```bash
go get github.com/yackey-labs/yauth@latest
go mod tidy   # pulls transitive deps for the openapi subpackage (Huma)
```

```go
package main

import (
    "log"
    "net/http"

    yauth "github.com/yackey-labs/yauth"
    "github.com/yackey-labs/yauth/plugins/emailpassword"
    "github.com/yackey-labs/yauth/repo/memrepo"
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

A runnable copy lives at [`examples/apikey/main.go`](examples/apikey/main.go).

### Try it for real (Vue + Go end-to-end)

`examples/vue` is a full SPA + Go backend wired together. It boots the
in-memory repo (memrepo), the email-password / status / admin plugins, and
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

// Same as RequireAuth, but WITHOUT the must_change_password gate — for the
// narrow set of host routes a locked-out user must still reach.
mux.Handle("/api/change-password", ya.Middleware().RequireAuthAllowMustChange(changePwHandler))

// Extract the resolved user inside a handler.
// Returns (*domain.AuthUser, bool) — the bool is true when the request was
// authenticated. RequireAuth guarantees that, but in unprotected handlers
// you should still check.
func profileHandler(w http.ResponseWriter, r *http.Request) {
    user, ok := middleware.AuthUserFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthenticated", http.StatusUnauthorized)
        return
    }
    fmt.Fprintf(w, "hello %s", user.User.Email)
}
```

`RequireAuth` returns `401` for unauthenticated requests; `RequireAdmin`
returns `403` for non-admin users. Import `middleware` from
`github.com/yackey-labs/yauth/middleware`.

> **Behaviour change (unreleased):** `RequireAuth` and `RequireAdmin` now also
> enforce the `must_change_password` gate — the same gate the huma
> `RequireAuthHuma` / `RequireAdminHuma` middlewares have always applied, and
> the one `yauth docs admin-bootstrap` has always documented as "enforced
> centrally in the auth middleware". It was previously missing on the net/http
> path, so a bootstrapped or admin-provisioned account could reach every
> host-owned route the docs tell you to protect this way. A **cookie-session**
> caller whose account has `must_change_password=true` now gets a `403`;
> bearer-JWT / `X-Api-Key` callers are never gated. If your app has its own
> change-password or logout route, switch it to `RequireAuthAllowMustChange` so
> the user can escape the gate.
>
> That 403 is **RFC 9457 problem+json**, byte-identical to what the huma gate
> emits — one condition, one wire shape, whichever stack served the route:
>
> ```http
> HTTP/1.1 403 Forbidden
> Content-Type: application/problem+json
>
> {"title":"Forbidden","status":403,"detail":"password change required"}
> ```
>
> This is the one place these wrappers depart from their plain-text
> `http.Error` bodies; the `401` and the non-admin `403` are unchanged. It is
> deliberate — this response is meant to be parsed (yauth's own Vue client
> matches on `detail`), and a client should not have to know which middleware
> stack served a route to know how to read the answer. A test asserts the two
> stacks stay byte-identical.
>
> `OptionalAuth` is deliberately **not** gated — it authorizes nothing on its
> own.

**Event system** — every authentication operation emits an
`events.AuthEvent` (`UserRegistered`, `LoginAttempt`, `LoginSucceeded`,
`LoginFailed`, `Logout`, `PasswordChanged`, ...). Handlers respond with
`Continue`, `Block { status, message }`, or `RequireMfa { pending_session_id }`.
The first non-Continue decision short-circuits the chain.

## Pick a Backend

| Backend | Constructor | Database | Migrations |
| --- | --- | --- | --- |
| **pgx (recommended for Postgres)** | `pgxrepo.New(pool)` | PostgreSQL (pgx/v5, sqlc-generated) | goose |
| In-memory     | `memrepo.New()`              | — (in-process, non-persistent) | none |
| Redis cache   | `redisrepo.New(inner, client, opts)` | — wraps any backend | — |

**Zero-config quickstart with `memrepo`** — no database, no migrations,
no `context` import needed:

```go
package main

import (
    "log"
    "net/http"

    yauth "github.com/yackey-labs/yauth"
    "github.com/yackey-labs/yauth/plugins/emailpassword"
    "github.com/yackey-labs/yauth/repo/memrepo"
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

yauth uses Postgres (native pgx/v5 + sqlc) as its only persistent backend,
with an in-memory backend (`memrepo`) for dev and tests, and exposes the
`repo.Repository` interface as the extension point. New backends plug in by
implementing that interface; the conformance suite (`repo/conformance`)
validates any backend against the full contract.

**Migrations** are managed by [goose](https://github.com/pressly/goose)
with embedded SQL files for Postgres. The `migrate` package is
the single entry point:

```go
import (
    "github.com/yackey-labs/yauth/migrate"
    "github.com/yackey-labs/yauth/repo/pgxrepo"
)

pool, _ := pgxrepo.Open(ctx, dsn)
migrate.Run(ctx, pgxrepo.StdDB(pool), "pgx")   // "pgx"
```

Or use the CLI: `yauth migrate up` (see Configuration).

**Using pgxrepo directly:**

```go
import (
    "context"
    "time"

    yauth "github.com/yackey-labs/yauth"
    "github.com/yackey-labs/yauth/migrate"
    "github.com/yackey-labs/yauth/plugins/emailpassword"
    "github.com/yackey-labs/yauth/repo/pgxrepo"
)

ctx := context.Background()

// PoolOption helpers let you tune sizing beyond what the DSN provides.
// You can also use DSN query params (pool_max_conns=25&pool_min_conns=5)
// or call pgxpool.NewWithConfig directly for full control.
pool, err := pgxrepo.Open(ctx, "postgres://user:pass@localhost/mydb?sslmode=disable",
    pgxrepo.WithMaxConns(25),
    pgxrepo.WithMinConns(5),
    pgxrepo.WithMaxConnLifetime(time.Hour),
)
if err != nil { /* handle */ }
defer pool.Close()

// StdDB wraps the pgxpool as a *sql.DB so goose can use it.
// Run goose migrations (idempotent). In production run this as a
// one-shot job before starting replicas — never with multiple replicas
// all migrating simultaneously. Use `yauth migrate -c yauth.yaml` instead.
if err := migrate.Run(ctx, pgxrepo.StdDB(pool), "pgx"); err != nil { /* handle */ }

ya, err := yauth.New(pgxrepo.New(pool), yauth.NewDefaultConfig()).
    WithPlugin(emailpassword.New(emailpassword.Config{})).
    Build()
```

**Shared pool vs dedicated pool:** `pgxrepo.New` accepts any `*pgxpool.Pool`
— you choose whether to share your application's existing pool or give yauth
its own:

```go
// Option A — shared pool (fewer total connections, simpler setup)
// Pass your app's existing pool directly. yauth and app share the budget.
appPool := getAppPool()  // your existing *pgxpool.Pool
yauthRepo := pgxrepo.New(appPool)

// Option B — dedicated pool (yauth can't starve the app, or vice versa)
// Create a separate pool sized for auth workloads.
yauthPool, _ := pgxrepo.Open(ctx, dsn, pgxrepo.WithMaxConns(10))
defer yauthPool.Close()
yauthRepo := pgxrepo.New(yauthPool)
```

Shared is fine for most apps; a dedicated pool is worth it when auth is
high-traffic or you need separate connection-limit accounting.

A full runnable example lives at [`examples/pgxrepo/main.go`](examples/pgxrepo/main.go):

```bash
docker run -d --rm -p 5432:5432 \
  -e POSTGRES_USER=yauth -e POSTGRES_PASSWORD=yauth -e POSTGRES_DB=yauth_example \
  postgres:16-alpine

DATABASE_URL="postgres://yauth:yauth@localhost/yauth_example?sslmode=disable" \
  go run ./examples/pgxrepo
```

Or let `NewFromConfig` wire everything when `database.driver = "pgx"` in `yauth.yaml`:

```yaml
database:
  driver: pgx
  dsn: "postgres://user:pass@localhost/mydb?sslmode=disable"
  auto_migrate: true   # DEV ONLY — when true, NewFromConfig calls migrate.Run
                       # at startup; concurrent replicas will race, so never
                       # use this in production. Default is false.
```

> **Production migration:** `yauth migrate -c yauth.yaml` reads `database.dsn`
> from `yauth.yaml` (default filename; override with `-c path/to/config.yaml`)
> and runs goose migrations as a one-shot process. Run it as a Kubernetes Job or
> init-container before rolling out app replicas; keep `auto_migrate: false`
> (the default) in the app config. Do not call both `migrate.Run` and set
> `auto_migrate: true` for the same database — they both run the same goose
> migrations and are idempotent together, but it's redundant and surprising.

**`migrate.Run` vs `migrate.NewProvider` — when to use each:**

| Situation | Use |
| --- | --- |
| Running yauth migrations standalone (init-container, startup hook, test setup) | `migrate.Run(ctx, db, driver)` |
| Your app already uses goose for its own tables | `migrate.NewProvider(db, driver)` — runs in a separate version table (`goose_db_version_yauth`) so yauth and app migrations never collide |
| You want to embed yauth's SQL into your own goose provider | `migrate.MigrationFS` + `fs.Sub` + `goose.NewProvider` |

**Integrating yauth migrations with your own goose pipeline:**

```go
import "github.com/yackey-labs/yauth/migrate"

// Your app's provider (uses default goose_db_version table)
appProvider, _ := goose.NewProvider(goose.DialectPostgres, db, appMigrationsFS)

// yauth's provider — separate goose_db_version_yauth table, no collision
yauthProvider, _ := migrate.NewProvider(db, "pgx")

// Run both in sequence (or wrap in your own error handling)
if _, err := appProvider.Up(ctx); err != nil { /* handle */ }
if _, err := yauthProvider.Up(ctx); err != nil { /* handle */ }
```

The raw SQL files are exported as `migrate.MigrationFS` (`embed.FS` with
the `postgres/` subdirectory) if you need to merge them
with your own `fs.FS` via standard library tools.

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
| organizations    | `plugins/organizations`      | ✅     |
| scim             | `plugins/scim`               | ✅     |
| audit-export     | `plugins/auditexport`        | ✅     |

Every plugin in the table maps 1:1 to a Rust feature flag. Each ships
with one or more runnable examples under [`examples/`](examples/).

The `organizations` plugin (port of yauth Rust PR #98 / issue #87) is
the multi-tenancy primitive — `Organization` + `Membership` +
`Invitation`. It is OFF by default: nothing happens until you opt in
with `.WithPlugin(organizations.New(organizations.Config{}))`. The
data model is identical to Better Auth / WorkOS / Stytch — see the
package doc for the route surface and invariants.

#### Org-scoped RBAC

The `organizations` plugin ships with built-in role-based access
control (port of yauth Rust issue #88). Built-in role strings are in
`auth/rbac.go`:

- `auth.RoleOwner` — exactly one per org; cannot be demoted or removed
  unless ownership is transferred first
- `auth.RoleAdmin` — manage members, settings, invite
- `auth.RoleBillingAdmin` — billing-only
- `auth.RoleMember` — default for invitees; read-mostly
- `auth.RoleViewer` — strict read-only

Each role maps to a default permission set under
`auth.DefaultPermissions(role)`. Custom role strings on
`Membership.Role` are persisted verbatim but get an empty default
permission set — applications are responsible for layering their own
permission map on top.

Gate handlers using the helpers in `middleware/rbac.go`:

```go
err := middleware.RequireOrgRole(ctx, repo, orgID, auth.RoleAdmin)
err := middleware.RequireOrgPermission(ctx, repo, orgID, auth.PermMembersInvite)
```

Owner-protection is enforced at the repo layer: `UpdateMembership` /
`DeleteMembership` refuse to demote or remove the last owner of an
org, returning `yautherr.ErrOwnerProtected`. To swap the owner, call
`POST /organizations/{id}/transfer-ownership`, which atomically
promotes the new owner and demotes the prior owner to admin.

RBAC routes (mounted alongside the base org routes):

- `POST /organizations/{id}/members/{user_id}/role` — change a non-owner's role (admin+)
- `POST /organizations/{id}/transfer-ownership` — transfer ownership (owner-only)
- `GET  /organizations/{id}/permissions` — list caller's permissions on the org

The creator of an org is automatically the `owner` (previously `admin`
in #87) — owner is a strict superset of admin under the default
catalogue, so admin-gated endpoints continue to work for the creator
without changes.

#### Active-org switcher (yauth #89 / Go #15)

For users with memberships in multiple organizations, every request
needs to answer "which org am I acting in?". yauth answers this
with a per-session **active org** that flows through both cookie and
JWT identity paths:

- **Cookie sessions** carry the active org in the `active_org_id`
  column on `yauth_sessions`. Switching updates the row; the cookie
  itself is unchanged.
- **JWT bearer tokens** carry the additive `org` / `role` / `orgs`
  claims when the `organizations` plugin is registered alongside
  bearer. Switching the active org returns a payload; the client must
  call `/token` to mint a fresh JWT (older tokens keep working until
  expiry — document this for clients).

Selection rules on login / refresh / signup:

1. 0 active memberships → no active org (legacy single-user path)
2. 1 active membership → auto-picked
3. multiple → first by name (case-insensitive), tiebreak by id

Endpoints (mounted only when `organizations.New(...)` is registered):

- `GET    /sessions/active-org` — read current active org + memberships
- `POST   /sessions/active-org { organization_id }` — switch (403 if not an active member)
- `DELETE /sessions/active-org` — clear

Inside handlers, read the active context off `domain.AuthUser`:

```go
au, _ := middleware.AuthUserFromContext(ctx)
if au.ActiveOrgID != nil {
    // tenant-scoped path; au.OrgRole carries the caller's role
    // au.AllOrgs lists every membership for switcher UIs
} else {
    // single-user / no-org path — backward compatible
}
```

Single-user deployments that never register the `organizations` plugin
pay zero overhead: `ActiveOrgID` stays nil and the JWT/cookie shapes
are identical to pre-#89 yauth.

#### Verified domains + JIT membership

The `organizations` plugin supports domain-verified SSO: register an
email domain (e.g. `acme.com`), prove ownership via a DNS TXT challenge,
and any new user that signs up with a matching email is automatically
invited into the org at the configured default role (Just-In-Time
provisioning).

Routes:

- `POST   /organizations/{id}/domains` — register a domain + get the DNS challenge
- `POST   /organizations/{id}/domains/{domain}/verify` — confirm the TXT record
- `DELETE /organizations/{id}/domains/{domain}` — unregister
- `GET    /organizations/{id}/domains` — list registered domains + status

#### Per-org auth policy

Each organization carries an `AuthPolicy` that overrides the instance-level
defaults for members of that org:

| Field | Type | Effect |
|---|---|---|
| `RequireMfa` | `bool` | Force TOTP/passkey challenge on login for all org members |
| `AllowedIdPs` | `[]string` | Restrict SSO connections to a whitelist of provider IDs |
| `SessionTTL` | `*Duration` | Override global session expiry for the org |
| `PasswordMinLength` | `int` | Minimum password length for org members |

Update policy:

```go
POST /organizations/{id}/policy
{ "require_mfa": true, "session_ttl": "8h", "password_min_length": 16 }
```

Read policy: `GET /organizations/{id}/policy` (admin+).

#### Org-scoped API keys

The `organizations` plugin issues API keys that carry the org ID and
the caller's role in their payload, so `X-Api-Key` requests are
automatically tenant-scoped. Create a key:

```
POST /organizations/{id}/api-keys
{ "name": "CI pipeline", "scopes": ["read"], "expires_at": "2026-12-31T00:00:00Z" }
```

The returned `yak_<prefix>_<secret>` header value works as a drop-in
`X-Api-Key` — the middleware resolves it to `*domain.AuthUser` with
`ActiveOrgID` and `OrgRole` populated.

#### SSO connections — OIDC client

Add an OIDC identity provider to an org so members can sign in via
`/sso/oidc/login` (authorization-code + PKCE). Supported providers
include Google Workspace, Entra ID, Okta, Auth0, Keycloak, and any
standards-compliant OIDC issuer.

```go
POST /organizations/{id}/sso/connections
{
  "type": "oidc",
  "client_id": "...",
  "client_secret": "...",
  "issuer_url": "https://accounts.google.com",
  "default_role": "member"
}
```

Routes:

- `GET  /sso/oidc/login?connection_id=<cid>` — redirect to IdP
- `GET  /sso/oidc/callback` — handle IdP redirect + issue session
- `GET  /sso/oidc/connections` — list connections (admin)

#### SSO connections — SAML 2.0 SP

SAML Service Provider support for ADFS, Entra ID, Okta, Auth0,
OneLogin, and Ping Identity. The spec for these routes lives in
`openapi/saml.go`; the routes are Go-only (see
[cross-language conformance](#cross-language-conformance)).

```go
POST /organizations/{id}/sso/connections
{ "type": "saml", "metadata_url": "https://login.microsoftonline.com/...federationmetadata/...", "default_role": "member" }
```

Routes:

- `GET  /sso/saml/login?connection_id=<cid>` — SP-initiated redirect
- `POST /sso/saml/acs` — Assertion Consumer Service (IdP POST)
- `GET  /sso/saml/metadata/{cid}` — SP metadata XML (give to your IdP)
- `GET  /sso/saml/logout` — SP-initiated SLO
- `POST /sso/saml/slo` — IdP-initiated SLO

#### SCIM 2.0 provisioning

The `scim` plugin mounts RFC 7643/7644 Users + Groups endpoints under
`/api/scim/v2/organizations/{org_id}/`. Configure your IdP (Okta,
Entra, OneLogin) to push user/group changes here; SCIM operations map
directly to `Membership` create/update/deactivate events. Requires
the `organizations` and `api-key` plugins — the IdP authenticates with
a long-lived `X-Api-Key`.

```go
WithPlugin(scim.New(scim.Config{}))
```

Routes (SCIM spec-standard):

- `GET/POST   /api/scim/v2/organizations/{org_id}/Users`
- `GET/PUT/PATCH/DELETE /api/scim/v2/organizations/{org_id}/Users/{id}`
- `GET/POST   /api/scim/v2/organizations/{org_id}/Groups`
- `GET/PUT/PATCH/DELETE /api/scim/v2/organizations/{org_id}/Groups/{id}`
- `GET        /api/scim/v2/organizations/{org_id}/ServiceProviderConfig`
- `GET        /api/scim/v2/organizations/{org_id}/Schemas`

Like the SAML routes, the SCIM surface is Go-only in `openapi/scim.go`
and categorised as `GO-EXTRA` in the conformance report.

#### Audit export / SIEM

The `audit-export` plugin delivers a copy of every `yauth_audit_log`
row to one or more external destinations with at-least-once delivery
semantics. Requires the `webhooks` and `admin` plugins.

```go
WithPlugin(auditexport.New(auditexport.Config{}))
```

Configure destinations via `POST /audit/export/destinations`:

| `type` | Notes |
|---|---|
| `webhook` | HMAC-SHA256 signed HTTP POST, same wire format as the webhooks plugin |
| `syslog` | RFC 5424 over TLS (port 6514); works with Splunk, syslog-ng, rsyslog |
| `s3` | S3-compatible (AWS, Cloudflare R2, MinIO); newline-delimited JSON |
| `splunk` | Splunk HEC (`/services/collector/event`) |
| `datadog` | Datadog Logs API (`/api/v2/logs`) |

Routes:

- `GET/POST   /audit/export/destinations` — list / add
- `GET/DELETE /audit/export/destinations/{id}` — inspect / remove
- `POST       /audit/export/destinations/{id}/test` — send a synthetic event
- `GET        /audit/export/queue` — delivery queue depth (admin diagnostics)

#### MCP server (OAuth for AI tool endpoints)

Putting an MCP endpoint in front of an AI client (Claude Code, Claude Desktop)
means speaking the MCP OAuth 2.1 flow. yauth's `oauth2-server` plugin is the
authorization server, but the discovery documents MCP clients need
(`/.well-known/oauth-protected-resource`, root `/.well-known/oauth-authorization-server`)
must live at the resource-server **root** — which a yauth plugin can't reach.
The [`mcpauth`](mcpauth) helper mounts them in one call, and the SPA
`ConsentScreen` / `OAuthConsentPage` components render the browser consent step.

```go
mcpauth.Mount(mux, ya, mcpauth.Config{AuthBasePath: "/api/auth", ConsentPath: "/authorize"})
mux.Handle("/mcp", mcpauth.Guard(ya, mcpHandler))
mux.Handle("/mcp/", mcpauth.Guard(ya, mcpHandler))
```

See [docs/mcp](docs/mcp/README.md) for the full walkthrough, the footgun
checklist, scope catalogs, and the SPA + HTML consent options.

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
YAML/TOML config into a fully-resolved `yauth.YAuthConfig`. Use it whenever
you want config-driven setups (twelve-factor, k8s ConfigMap-backed, etc.).

**Two ways to assemble a server (mixable):** declarative —
`yauth.NewFromConfig(ctx, cfg)` wires every enabled plugin from `yauth.yaml`;
or programmatic — `yauth.New(repo, cfg).WithPlugin(...).Build()`. Mix with
`yauth.NewBuilderFromConfig(ctx, cfg)` then `.WithPlugin(custom).Build()`.
Precedence, env handling, and the no-duplicate-plugin rule are documented in
[docs/configuration.md](docs/configuration.md) (or `yauth docs configuration`).

**Environment variables.** When config is loaded via `yauthcfg.Load` (the CLI,
and the standard `Load` + `NewFromConfig` flow), any scalar field can be
overridden with a `YAUTH_*` env var (env wins over the file, but not over
explicit Go values) — e.g. `YAUTH_SERVER_ADDR=:8080`, `YAUTH_SESSION_TTL=24h`,
`YAUTH_PLUGINS_BEARER_ENABLED=true`. The var name is `YAUTH_` + the uppercased
YAML path joined by `_`. In addition, `database.dsn: env:VAR` reads the DSN from
`VAR`, and `*_env` fields name the env var holding a secret/key. Full precedence
ladder: [docs/configuration.md](docs/configuration.md).

Notable fields beyond cookie/session settings:

| Field | Default | Purpose |
| --- | --- | --- |
| `AllowSignups` | `true` | Set `false` to disable new user registration (`SIGNUPS_DISABLED` 403) |
| `AutoAdminFirstUser` | `false` | Promote the first registered user to role `admin`. **Legacy** — prefer `plugins.email_password.bootstrap_admin` (`yauth docs admin-bootstrap`), which deterministically provisions the admin at startup with a forced password change instead of letting whoever registers first become admin. |
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
go install github.com/yackey-labs/yauth/cmd/yauth@latest

yauth init               # scaffold yauth.yaml
yauth migrate up         # run goose migrations
                         #   reads yauth.yaml by default; override with -c path/to/config.yaml
yauth check              # validate yauth.yaml + reachability
yauth gen-secrets        # cryptographically random session/JWT secrets
yauth gen-keys --type RS256 --out ./keys # asymmetric JWT keypair
yauth status             # ping the running yauth instance
yauth dump-schema        # emit the table layout
yauth version            # version info
```

### Agent / AI context (version-exact, embedded)

The CLI embeds its own documentation and config schema, so an AI agent (or a
human) can learn this **exact version** of yauth from the binary — no doc site,
no MCP server, no skill file to keep in sync. Because the docs ship inside the
same artifact as the code (and, via `go tool`, the same version as the library
you link), they cannot drift from what the binary actually does.

```bash
go tool yauth context                 # llms.txt-style index: commands, doc topics, plugins — start here
go tool yauth docs                    # list embedded doc topics
go tool yauth docs scim/okta          # print one topic (README + everything under docs/)
go tool yauth docs typescript/setup   # frontend: TypeScript / Vue / SolidJS
go tool yauth schema config           # JSON Schema (Draft 2020-12) for yauth.yaml, reflected from this binary
```

(Installed via [`go tool`](#install-as-a-go-tool), shown above — these stay
pinned to the yauth version your app links. If you `go install`ed the binary
onto your PATH instead, drop the `go tool` prefix: `yauth context`.)

`go tool yauth schema config` is reflected from the real `yauthcfg.Config`
structs at runtime, so field names, types, and defaults always match what this
version parses.

**Point your coding agent at it.** Add this one line to your project's
`AGENTS.md` (or `CLAUDE.md`) and any agent starts from the version-exact source:

> When working with yauth, run `go tool yauth context` first — it prints the
> version-exact commands, doc topics, and config schema for the installed
> version. Use `go tool yauth schema config` to author/validate `yauth.yaml`,
> `go tool yauth docs <topic>` for guides, and `go tool yauth docs typescript/setup`
> for the TypeScript / Vue / SolidJS frontend.

That one-liner is the portable, tool-agnostic way to wire in agent context —
nothing to install or keep in sync, because it points back at the binary. (A
thin skill at `.claude/skills/yauth/` does the same for contributors working in
this repo, auto-discovered by Claude Code.)

### Install as a Go tool

If you already depend on `yauth` as a library, pin the CLI as a
[Go tool](https://go.dev/doc/modules/managing-dependencies#tools)
(Go 1.24+) instead of installing a loose binary. From inside your module:

```bash
go get -tool github.com/yackey-labs/yauth/cmd/yauth
```

This adds a `tool` directive to your `go.mod`. Run it through `go tool`:

```bash
go tool yauth migrate -c yauth.yaml
go tool yauth version
```

**Version is locked to the library automatically.** `cmd/yauth` lives in the
same module as the `yauth` package, and Go modules resolve a single version
per module (MVS). So the `tool` directive and your
`require github.com/yackey-labs/yauth vX.Y.Z` always point at the same
version — the CLI can never drift from the library you build against. To move
both in lockstep, bump the one module:

```bash
go get github.com/yackey-labs/yauth@v1.2.3   # updates library + tool together
```

This is the recommended pattern for CI/CD: the migration tool is guaranteed to
match the schema embedded in the exact `yauth` version your app links.

## Running Migrations in CI/CD

**Golden rule: migrations run once before replicas start — never at startup.**
Multiple replicas racing through DDL will corrupt the schema. Set
`auto_migrate: false` (the default) and use one of the patterns below.

### `yauth migrate` CLI

```bash
go install github.com/yackey-labs/yauth/cmd/yauth@latest
yauth migrate -c yauth.yaml   # reads database.dsn from yauth.yaml
```

`-c` defaults to `yauth.yaml` in the working directory. Override for
non-default paths: `yauth migrate -c /etc/yauth/prod.yaml`.

### GitHub Actions (run before deploy)

```yaml
- name: Migrate database
  run: |
    go install github.com/yackey-labs/yauth/cmd/yauth@latest
    yauth migrate -c config/yauth.yaml
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

Keep this step in its own job with `needs: [migrate]` on the deploy job
so the deploy never proceeds if migration fails.

### Kubernetes Job (recommended)

Run a Job to completion before rolling out the Deployment:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: yauth-migrate
spec:
  backoffLimit: 2
  ttlSecondsAfterFinished: 600
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: ghcr.io/yackey-labs/yauth-cli:latest
          args: ["migrate", "-c", "/etc/yauth/yauth.yaml"]
          envFrom:
            - secretRef:
                name: yauth-secrets   # must contain DATABASE_URL
          volumeMounts:
            - name: config
              mountPath: /etc/yauth
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: yauth-config
```

```bash
kubectl apply -f migrate-job.yaml
kubectl wait --for=condition=complete job/yauth-migrate --timeout=120s
kubectl apply -f deployment.yaml   # safe to roll out replicas now
```

> **Note:** Init-containers run once per Pod, not once per rollout — avoid
> using them for migrations in multi-replica Deployments.

### Go entrypoint (custom binary)

For teams that want full control in Go rather than the CLI:

```go
pool, _ := pgxrepo.Open(ctx, dsn)
if err := migrate.Run(ctx, pgxrepo.StdDB(pool), "pgx"); err != nil {
    log.Fatalf("migrate: %v", err)
}
log.Println("migrations complete — starting app")
// ... build YAuth, start server
```

`migrate.Run` is idempotent: goose skips already-applied migrations.
For teams with existing goose pipelines see `migrate.NewProvider` above.

## Telemetry

`telemetry` wraps OpenTelemetry tracing. When enabled:

- Every plugin HTTP handler runs inside a server span
- Authenticated requests tag the active span with the resolved identity: `user.id` (OTel semantic convention) plus, when the relevant plugins are loaded, `yauth.active_org.id` and `yauth.org.role` (organizations), `yauth.auth.method` (`cookie`/`bearer`/`api_key`), and `yauth.principal.kind` (`user`/`service_account`). Absent context is skipped — a single-user deployment emits only `user.id`. These tags land on whichever span is active, so they enrich a consumer's `otelhttp` span too.
- Outbound HTTP from the webhooks dispatcher carries `traceparent` headers
- **Database operations are traced automatically** — pgxrepo emits a child span per SQL query ([otelpgx](https://github.com/exaring/otelpgx))

When using `NewFromConfig` with `telemetry.enabled: true`, DB tracing is
wired automatically for pgxrepo — no extra code needed.

### Bring your own OpenTelemetry SDK

If your application already runs an OpenTelemetry SDK (a global `TracerProvider`
plus an HTTP instrumentation such as `otelhttp`), let yauth join your pipeline
instead of standing up its own:

- Call `WithTelemetry(telemetry.Config{Enabled: true})` but **do not** call
  `telemetry.Init`. yauth's internal instrumentation — DB spans, internal
  spans, and the `user.id` tag — records against your already-installed global
  provider; yauth never calls `otel.SetTracerProvider` on this path.
- If you already wrap your handler tree in `otelhttp` (or equivalent), disable
  yauth's own HTTP server span with `WithTraceMiddleware(false)` so requests
  aren't traced twice. yauth then enriches *your* server span (including
  `user.id`) rather than nesting a redundant one.

```go
// app owns the OTel SDK + exporter and wraps everything in otelhttp
ya, _ := yauth.New(repo, cfg).
    WithPlugin(emailpassword.New(emailpassword.Config{})).
    WithTelemetry(telemetry.Config{Enabled: true}). // join the global provider
    WithTraceMiddleware(false).                      // otelhttp already opens the server span
    Build()

mux := http.NewServeMux()
mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
http.ListenAndServe(addr, otelhttp.NewHandler(mux, "api")) // your span layer
```

From config, the same opt-out is `telemetry.http_middleware: false` (defaults
to true). By default `NewFromConfig` with `telemetry.enabled: true` calls
`telemetry.Init` and owns the SDK; set `telemetry.manage_provider: false` to
attach to a provider your application installed itself instead of opening a
second export stream (`otlp_endpoint`/`otlp_protocol` are then ignored).

### Choosing the OTLP transport (gRPC or HTTP)

When yauth manages the exporter, `Init` speaks **gRPC** by default (port 4317).
Set `Protocol: "http"` (or `telemetry.otlp_protocol: http`) to use the OTLP/HTTP
receiver instead — the common case when your collector only exposes HTTP (port
4318):

```go
shutdown, _ := telemetry.Init(ctx, telemetry.Config{
    Enabled:  true,
    Protocol: "http",                          // OTLP/HTTP
    Endpoint: "http://otel-collector:4318",    // omit to default to :4318
})
```

`Config.Protocol` and `Config.Endpoint` fall back to the standard
`OTEL_EXPORTER_OTLP_PROTOCOL` (`grpc` / `http/protobuf`) and
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT` env vars
when empty.

For manual wiring:

```go
shutdown, err := telemetry.Init(ctx, telemetry.Config{
    Enabled:     true,
    ServiceName: "my-app",
    Protocol:    "grpc",                       // or "http"
    Endpoint:    "http://otel-collector:4317",
})
defer shutdown(context.Background())

// pgxrepo: pass WithOTelTracing() — uses global provider set by telemetry.Init
pool, _ := pgxrepo.Open(ctx, dsn, pgxrepo.WithOTelTracing())

ya, _ := yauth.New(repo, cfg).
    WithTelemetry(telemetry.DefaultConfig()).
    WithTelemetryShutdown(shutdown).
    Build()
```

## OpenAPI

The OpenAPI 3.1 spec for every yauth route is authored in
`openapi/spec.go` using the
[Huma](https://github.com/danielgtaylor/huma) primitives — code-first,
the same philosophy as the Rust `utoipa` integration.

Every plugin registers its routes as huma operations (typed handlers,
auto-derived request/response schemas). `YAuth.OpenAPI()` returns huma's
auto-derived `*huma.OpenAPI` for the full route set — serving and spec come
from the same registrations, so route-level drift is structurally impossible.

The spec is published as a generated, checked-in `openapi.json` at the repo
root. Regenerate it whenever a route or schema changes:

```bash
YAUTH_GEN_OPENAPI=1 go test -run TestGenerateOpenAPI .   # writes openapi.json
```

`TestOpenAPISpecUpToDate` (in the default `go test ./...` suite, and the
`openapi-fresh` CI job) rebuilds the spec in memory and asserts byte-equality
with the committed file, so a change that forgets to regenerate fails the build.

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

The `openapi-fresh` CI job keeps yauth's checked-in `openapi.json` in sync
with the live routes (regenerate-and-compare). The Rust backend is archived, so
there is no longer a cross-language conformance gate.

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

`useSession()` returns reactive session state plus helpers:
`{ user, loading, isAuthenticated, isLoading, isEmailVerified, userRole, userEmail, displayName, refetch, logout }`.
`user` is `null` when unauthenticated and a bare `AuthUser` object after
login. Call it inside any component to read or react to the current session
state, or `await logout()` to end the session.

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

| Rust feature           | yauth        | Notes                                                                                    |
| ---------------------- | ------------ | ---------------------------------------------------------------------------------------- |
| email-password         | ✅           | Argon2id, dummy-verify on miss to defeat enumeration timing                              |
| bearer JWT             | ✅           | HS256 access + opaque refresh; family rotation with reuse-revocation                     |
| api-key                | ✅           | `yak_<prefix>_<secret>` header credential, scoped + per-user cap                         |
| magic-link             | ✅           | LoggingMailer for dev; bundled SMTP + Cloudflare mailers, or any `Mailer` impl           |
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
| organizations          | ✅           | Org + Membership + Invitation + RBAC; verified domains + JIT; active-org claim; per-org auth policy |
| org-scoped RBAC        | ✅           | Built-in roles (owner/admin/billing-admin/member/viewer); `RequireOrgRole` / `RequireOrgPermission` |
| active-org switcher    | ✅           | Cookie + JWT paths; auto-picks on login; `GET/POST/DELETE /sessions/active-org`         |
| verified domains + JIT | ✅           | DNS TXT challenge; JIT membership at configurable default role                          |
| per-org auth policy    | ✅           | `require_mfa`, `allowed_idps`, `session_ttl`, `password_min_length` per org             |
| org-scoped API keys    | ✅           | `yak_` keys carry `active_org_id` + `org_role`; `POST /organizations/{id}/api-keys`    |
| SSO — OIDC client      | ✅           | Auth code + PKCE; Google/Entra/Okta/Auth0/Keycloak; JIT + role mapping                 |
| SSO — SAML 2.0 SP      | ✅           | SP-initiated + IdP-initiated; metadata XML; Entra/Okta/ADFS/Auth0/OneLogin/Ping        |
| SCIM 2.0               | ✅           | RFC 7643/7644 Users + Groups push sync; Okta/Entra/OneLogin; Go-only routes            |
| audit-export / SIEM    | ✅           | Webhook, syslog TLS, S3, Splunk HEC, Datadog; at-least-once; Go-only routes            |
| 14 DB backends         | ⚙️ Postgres  | pgxrepo (sqlc+pgx) as the only persistent backend + memrepo (in-memory, dev/tests); goose migrations for Postgres |

`✅ done · ⚙️ partial · ❌ not yet`

## Project Layout

- `auth/`              — Argon2id, session token gen, cookies, HIBP check, password policy (leaf, no internal deps)
- `domain/`            — `User`, `Session`, `AuthUser`, ...
- `events/`            — `AuthEvent`, `Decision`, `Handler`
- `plugin/`            — `Plugin` and `PluginHost` interfaces
- `middleware/`        — tri-mode auth resolver + `RequireAuth` / `RequireAdmin` + CORS + rate-limit wrapper
- `migrate/`           — goose runner with embedded SQL migration files for postgres
- `repo/`              — repository interface + sub-interfaces
- `repo/pgxrepo/`      — native pgx/v5 + sqlc-generated backend (Postgres; recommended)
- `repo/redisrepo/`    — Redis caching decorator (sessions, rate limits, revocations)
- `repo/memrepo/`      — in-memory backend (testing + zero-config quickstart)
- `repo/conformance/`  — portable conformance harness for any `repo.Repository` implementation
- `plugins/`           — every plugin (one directory per name; `organizations/`, `scim/`, `auditexport/` are the enterprise additions)
- `yautherr/`          — sentinel errors as a leaf package (avoids import cycles across sub-packages)
- `telemetry/`         — OpenTelemetry init + HTTP middleware
- `humaapi/`           — builds the huma.API plugins register onto; its auto-derived spec is the published `openapi.json`
- `yauthcfg/`          — YAML/TOML + env config loader (supports `cache:` block for Redis)
- `cmd/yauth/`         — operator CLI (cobra)
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
YAUTH_GEN_OPENAPI=1 go test -run TestGenerateOpenAPI .   # regenerate openapi.json

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
git tag -a v0.2.0 -m "yauth-go v0.2.0"
git push origin v0.2.0
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
- `GO-EXTRA` — routes Go ships that Rust does not. yauth is
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
