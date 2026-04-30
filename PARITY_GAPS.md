# yauth-go vs Rust yauth — Parity Gap Analysis

Generated: 2026-04-30. Comparison between:
- Rust source: `/Users/syackey/steveyackey/yackey-labs/yauth`
- Go source: `/Users/syackey/steveyackey/yackey-labs/yauth-go`

Sources of truth used for diffing:
- Rust route list: `/Users/syackey/steveyackey/yackey-labs/yauth/docs/api-routes.md`
- Go route list: extracted from `/Users/syackey/steveyackey/yackey-labs/yauth-go/openapi.json`
- Rust config: `/Users/syackey/steveyackey/yackey-labs/yauth/crates/yauth/src/config.rs` + `docs/configuration.md`
- Go config: `/Users/syackey/steveyackey/yackey-labs/yauth-go/yauthcfg/config.go`

---

## 1. Routes / endpoints missing

Legend: **Yes** = present, **No** = absent, **Partial** = present but path/semantics differ.

### Core

| Method | Path | Rust | Go | Notes |
|---|---|---|---|---|
| GET | `/session` | Yes | Yes | parity |
| POST | `/logout` | Yes | Yes | parity |
| PATCH | `/me` | Yes | **No** | Rust mounts `update_profile` at `crates/yauth/src/plugins/mod.rs:59`; Go has no `/me` route (grep finds none). Display-name update missing. |

### Email/Password (plugin: `email-password`)

Rust file: `crates/yauth/src/plugins/email_password.rs` (public_routes lines 39–44).
Go file: `plugins/emailpassword/plugin.go` (Routes lines 51–55).

| Method | Path | Rust | Go | Notes |
|---|---|---|---|---|
| POST | `/register` | Yes | Yes | |
| POST | `/login` | Yes | Yes | Go does not honor `remember_me` (no `remember_me_ttl` config) |
| POST | `/verify-email` | Yes | **No** | Email verification flow not implemented in Go |
| POST | `/resend-verification` | Yes | **No** | |
| POST | `/forgot-password` | Yes | **No** | |
| POST | `/reset-password` | Yes | **No** | |
| POST | `/change-password` | Yes | Yes | |
| POST | `/logout` | (core) | Yes (mounted by emailpassword) | divergence: Go's email-password owns logout |

The Go email-password plugin's own header comment (`plugins/emailpassword/plugin.go:5`) calls out: "every other authentication method… is planned but not yet wired" — and verify/resend/forgot/reset are simply absent.

### MFA (plugin: `mfa`)

Path-prefix divergence: Rust uses `/mfa/...`; Go uses unprefixed paths.

| Method | Rust path | Go path | Status |
|---|---|---|---|
| POST | `/mfa/verify` | `/verify` | Path differs (Go = `/verify`) |
| POST | `/mfa/totp/setup` | `/totp/setup` | Path differs |
| POST | `/mfa/totp/confirm` | `/totp/confirm` | Path differs |
| DELETE | `/mfa/totp` | `/totp` | Path differs |
| GET | `/mfa/backup-codes` | `/backup-codes` | Path differs |
| POST | `/mfa/backup-codes/regenerate` | `/backup-codes/regenerate` | Path differs |

Go's `/verify` and `/totp` paths will collide with any other plugin that wants those names — Rust's `/mfa/...` namespacing is safer. Either rename Go to match Rust, or document the divergence in the migration guide.

### OAuth2 Server (plugin: `oauth2-server`)

| Method | Rust path | Go path | Status |
|---|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | — | **Missing in Go.** RFC 8414 metadata doc absent (`grep` finds zero hits). OIDC `/.well-known/openid-configuration` exists, but the plain OAuth metadata doc does not. |
| GET/POST | `/oauth/authorize` | `/oauth2/authorize` (GET) + `/oauth2/consent` (POST) | Path namespace differs (`/oauth2/...` vs `/oauth/...`). Go splits authorize and consent into two endpoints. |
| POST | `/oauth/token` | `/oauth2/token` | Path differs |
| POST | `/oauth/introspect` | `/oauth2/introspect` | Path differs |
| POST | `/oauth/revoke` | `/oauth2/revoke` | Path differs |
| POST | `/oauth/register` | — | **Missing in Go.** RFC 7591 dynamic client registration not exposed. Go has admin-side `POST /oauth2/clients` but no public `/oauth/register`. |
| POST | `/oauth/device/code` | `/oauth2/device_authorization` | Path + name differ |
| GET/POST | `/oauth/device` | `/oauth2/device` (POST only) | Go missing the GET for the device verification UI shim |

### OAuth Client (plugin: `oauth`)

Go `plugins/oauth` registers `/oauth/{provider}/authorize`, `/oauth/{provider}/callback`, `/oauth/accounts`, `/oauth/{provider}` (DELETE), `/oauth/{provider}/link` — full parity.

### Account Lockout (plugin: `lockout` / `account-lockout`)

| Method | Rust path | Go path | Status |
|---|---|---|---|
| POST | `/account/request-unlock` | `/unlock/request` | Path differs |
| POST | `/account/unlock` | `/unlock` | Path differs |
| POST | `/admin/users/{id}/unlock` | — | **Missing in Go.** No admin force-unlock route; `grep` finds zero matches. |
| GET | — | `/lockout/state` | Go-only admin route (extra) |

### Admin (plugin: `admin`)

| Method | Rust path | Go path | Status |
|---|---|---|---|
| GET | `/admin/users` | `/admin/users` | Yes |
| GET | `/admin/users/{id}` | `/admin/users/{id}` | Yes |
| PUT | `/admin/users/{id}` | PATCH `/admin/users/{id}` | Method differs (PUT vs PATCH) |
| DELETE | `/admin/users/{id}` | — | **Missing in Go.** User deletion not exposed. |
| POST | `/admin/users/{id}/ban` | Yes | Yes |
| POST | `/admin/users/{id}/unban` | Yes | Yes |
| POST | `/admin/users/{id}/impersonate` | Yes | Yes |
| GET | `/admin/sessions` | — | **Missing in Go.** Cross-user session listing. |
| DELETE | `/admin/sessions/{id}` | — | **Missing in Go.** Single-session terminate. (Go has `DELETE /admin/users/{id}/sessions` to nuke all of a user's, but not by session id.) |
| GET | — | `/admin/audit` | Go-only (extra) — Rust writes audit log rows but does not expose a list endpoint in `api-routes.md` |

### Admin OAuth2 client management

| Method | Rust path | Go path | Status |
|---|---|---|---|
| GET | `/admin/oauth2/clients` | `/oauth2/clients` (admin-gated) | Path differs (Rust = under `/admin`) |
| POST | `/admin/oauth2/clients/{id}/ban` | — | **Missing in Go.** Per-client ban (rejects new mints + outstanding tokens). |
| POST | `/admin/oauth2/clients/{id}/unban` | — | **Missing in Go.** |
| POST | `/admin/oauth2/clients/{id}/rotate-public-key` | — | **Missing in Go.** Rotate `public_key_pem` for `private_key_jwt` clients. `grep` finds zero matches. |

---

## 2. Configuration knobs missing

Comparison: `crates/yauth/src/config.rs` vs `yauth-go/yauthcfg/config.go`.

### Top-level (`YAuthConfig` in Rust)

| Knob | Rust | Go | Notes |
|---|---|---|---|
| `base_url` | Yes | **No** | Used in email templates / OAuth redirects. Go has `Server.Addr` but no canonical app base URL. |
| `trusted_origins` (CORS) | Yes (`Vec<String>`) | **No** | No CORS allow-list in `yauthcfg`. |
| `secure_cookies` | Yes | Yes (`Session.CookieSecure`) | Parity |
| `cookie_domain` | Yes (`CookieDomainPolicy::Auto/Explicit`) | Partial (`Session.CookieDomain` string only — no `Auto` policy semantics) |
| `smtp` | Yes (`SmtpConfig{host,port,from}`) | **No** | No SMTP config. Email-driven flows (verify/forgot/magic-link) currently rely on a `Mailer` interface plumbed in code only. |
| `auto_admin_first_user` | Yes | **No** | First-user-becomes-admin bootstrap missing. |
| `allow_signups` | Yes (kill-switch) | **No** | No global signups-disabled toggle. |
| `db_schema` | Yes (`"public"` default for PG) | **No** | Cannot isolate yauth tables under e.g. `auth.` schema. |
| `session_binding.bind_ip` | Yes | **No** | |
| `session_binding.bind_user_agent` | Yes | **No** | |
| `session_binding.ip_mismatch_action` (Warn/Invalidate) | Yes | **No** | |
| `session_binding.ua_mismatch_action` | Yes | **No** | |
| `remember_me_ttl` | Yes | **No** | Login does not accept `remember_me`. |

### Email-password (`EmailPasswordConfig` in Rust)

| Knob | Rust | Go | Notes |
|---|---|---|---|
| `min_password_length` | Yes (default 8) | Yes (default 12) | Default differs |
| `require_email_verification` | Yes (default true) | Yes (default false in `Default()`) | Default differs |
| `hibp_check` | Yes (default true) | **No** | HIBP k-anonymity breach check absent in Go. See `crates/yauth/src/auth/hibp.rs`. |
| `password_policy.require_uppercase` | Yes | **No** | |
| `password_policy.require_lowercase` | Yes | **No** | |
| `password_policy.require_digit` | Yes | **No** | |
| `password_policy.require_special` | Yes | **No** | |
| `password_policy.max_length` | Yes | **No** | |
| `password_policy.disallow_common_passwords` | Yes | **No** | Top-10k-from-SecLists rejection absent. |
| `password_policy.password_history_count` | Yes (`check_password_history` in `auth/password_policy.rs`) | **No** | Password reuse prevention absent. |
| `rate_limit.max_requests` / `window_secs` | Yes (per-operation, default 10/60s) | **No** | No `RateLimitConfig` surface. |

### Webhooks (`WebhookConfig` in Rust)

| Knob | Rust | Go | Notes |
|---|---|---|---|
| `max_retries` (default 3) | Yes | Partial — `MaxAttempts` exists in `WebhooksPluginConfig` but `dispatcher.go:140-143` has `TODO(yauth-go): retry policy with exponential backoff … hard-coded to 1 until retry lands`. |
| `retry_delay` | Yes | **No** | |
| `timeout` | Yes | Partial (HTTP client uses a fixed timeout, not configurable via `yauthcfg`). |
| `max_webhooks` | Yes (per-user limit, default 10) | **No** | |

### Account lockout (`AccountLockoutConfig` in Rust)

| Knob | Rust | Go | Notes |
|---|---|---|---|
| `max_failed_attempts` | Yes | Yes (`MaxAttempts`) |
| `lockout_duration` | Yes (single duration) | Yes (`LockoutDuration` in cfg) but at runtime the plugin uses `LockoutDurations []time.Duration` ladder — the cfg knob does not expose the ladder |
| `exponential_backoff` | Yes | Implicit (the ladder is the backoff) |
| `max_lockout_duration` | Yes | **No** explicit cap |
| `auto_unlock` | Yes | **No** explicit toggle |

### Admin (`AdminConfig` in Rust)

| Knob | Rust | Go | Notes |
|---|---|---|---|
| `allow_machine_callers` | Yes | **No** | Go `AdminPluginConfig` has only `Enabled`. M2M-to-admin gating missing. |

### Bearer / Asymmetric JWT

| Knob | Rust | Go | Notes |
|---|---|---|---|
| `signing_algorithm` (HS256/RS256/ES256) | Yes | Yes (in `AsymJWTPluginConfig.KeyType`) | Parity |
| `signing_key_pem` (inline) | Yes (`#[serde(skip_serializing)]`) | **No** — only `private_key_path` (file). Inline-secret-via-env-var not supported for asymjwt key. |
| `kid` | Yes | Yes (`KeyID`) | Parity |
| Fail-fast PEM parse at build | Yes | unclear — verify in `plugins/asymjwt/signer.go` |

### OIDC

| Knob | Rust | Go | Notes |
|---|---|---|---|
| `issuer` | Yes | Yes |
| `id_token_ttl` | Yes (default 1h) | **No** |
| `claims_supported` | Yes (configurable) | **No** (hard-coded list) |

---

## 3. Security features missing or partial

Walking the bullets in `/Users/syackey/steveyackey/yackey-labs/yauth/README.md` "Security" section:

| Feature | Rust | Go | Status / file evidence |
|---|---|---|---|
| Argon2id with timing-safe dummy hash | Yes | Yes | `auth.DummyVerify` is invoked in `plugins/emailpassword/handlers.go:244,261`. **Parity.** |
| HaveIBeenPwned k-anonymity | Yes (`crates/yauth/src/auth/hibp.rs`) | **No** | `grep -r hibp` in Go = 0 matches. |
| Password policy (complexity, common rejection, history) | Yes (`auth/password_policy.rs`) | **No** | Only `MinPasswordLength` enforced; `grep PasswordHistory` = 0. |
| Per-operation rate limiting (login/register/forgot/magic-link) | Yes (`RateLimitConfig` per `EmailPasswordConfig`) | **Partial** | Foundation is wired: `repo.RateLimitRepository` and `gormrepo.RateLimit` model exist, plus `yauth_rate_limits` table; but **no plugin or middleware ever calls `CheckRateLimit`** in production handlers (only in test fakes — `grep` shows real call sites are fakes only). |
| Account lockout w/ exponential backoff | Yes | Yes (ladder via `LockoutDurations`). **Parity.** |
| Session binding (IP + UA hijack detection) | Yes (`SessionBindingConfig`) | **No** | `grep -ri "bind_ip\|BindIP\|BindingAction"` in Go = 0. |
| Session tokens stored as SHA-256 hashes | Yes | Yes (`auth.HashToken`, `plugins/emailpassword/handlers.go:369`). |
| JWT refresh family tracking, reuse-detection revocation | Yes | Likely yes (verify in `plugins/bearer`). |
| CSRF (HttpOnly + SameSite) | Yes | Yes (cookie options) |
| Email enumeration prevention | Yes | Partial — `register` returns `409 USER_EXISTS` (`plugins/emailpassword/handlers.go:130,147`), which **leaks account existence**. Rust returns the same response shape regardless. |
| Audit logging | Yes (`yauth_audit_log`) | Yes (`LogAuditEvent`, `ListAuditLog`); plus Go-only `GET /admin/audit` endpoint |
| WebAuthn challenge TTL (5min) | Yes | likely yes (verify in `plugins/passkey`) |
| Webhook HMAC-SHA256 signing | Yes | Yes (`signPayload`, `dispatcher.go:167`) |
| PKCE S256 required | Yes | Yes (`plugins/oauth2server/pkce.go`) |
| OAuth2 client ban / banned_at enforcement on outstanding tokens | Yes (`oauth2_admin.rs`) | **No** (no ban/unban admin route, no enforcement on auth_middleware) |
| `private_key_jwt` (RFC 7523) client auth at /token | Yes | Yes (`plugins/oauth2server/client_auth.go`, `token.go:78,93`) |
| Replayed JWT-assertion JTI rejection | Yes | verify in `plugins/oauth2server/client_auth.go` |
| `private_key_jwt` alg-confusion defence (reject `none`/HS\*) | Yes | verify in same file |

---

## 4. Test parity gaps

| Suite | Rust | Go | Gap |
|---|---|---|---|
| Unit tests | Yes (`cargo test --lib`) | Yes (`go test ./...`) | OK |
| Repo conformance harness (cross-backend) | Yes — `tests/repo_conformance.rs` (4206 LOC, ~65 cases × 7 backends in CI matrix) | **No** | No equivalent harness in Go. Each backend would need to be drilled through the same `RepoTester` struct of cases. |
| Pentest / OWASP suite | Yes — `tests/pentest.rs` (662 LOC) | **No** | No `pentest_test.go` or equivalent. |
| OAuth2 admin / asymmetric / m2m / private_key_jwt integration | Yes — 4 dedicated test files (`oauth2_admin.rs`, `oauth2_asymmetric.rs`, `oauth2_m2m.rs`, `oauth2_private_key_jwt.rs`) | Partial — `plugins/oauth2server/oauth2_test.go` is the only oauth2 file; no dedicated admin-ban or PKJWT regression suite. |
| MySQL integration test | Yes (`diesel_mysql_integration.rs`) | **No** | Go has no MySQL backend at all (see §5). |
| libsql / Turso integration | Yes (`libsql_integration.rs`) | **No** | |
| Memory-backend conformance | Yes (`memory_backend.rs`) | **No** | Go has no memory backend (see §5). |

---

## 5. Backend coverage gaps

Rust: 13 SQL backends + 1 in-memory (`crates/yauth/src/backends/`):
`diesel_pg`, `diesel_mysql`, `diesel_sqlite`, `diesel_libsql`, `sqlx_pg`, `sqlx_mysql`, `sqlx_sqlite`, `seaorm_pg`, `seaorm_mysql`, `seaorm_sqlite`, `toasty_pg`, `toasty_mysql`, `toasty_sqlite`, `memory`.

Go: 1 backend, 2 dialects (`repo/gormrepo/`):
- GORM Postgres (driver `postgres`)
- GORM SQLite (driver `sqlite`)

Specific gaps:

| Gap | Effort | Notes |
|---|---|---|
| GORM **MySQL** dialect | Trivial — one `gorm.io/driver/mysql` import + dialect detection branch in `gormrepo`/`yauthcfg/validate.go`. The model layer is dialect-agnostic. |
| **In-memory** backend | Medium — needed for tests + zero-config quickstart parity with Rust's `InMemoryBackend`. Required for any Go conformance harness. |
| Other ORM choice (sqlx-go, ent, sqlc) | Low priority — Go community is GORM-heavy; one ORM is fine. |
| Redis caching decorator | See §6. |

---

## 6. Infrastructure gaps

| Item | Rust | Go | Notes |
|---|---|---|---|
| Redis cache decorator | Yes — `crates/yauth/src/backends/redis/` (`RedisCachedSessionOps`, `RedisCachedChallenges`, `RedisCachedRateLimits`, `RedisCachedRevocations`); wired via `YAuthBuilder::with_redis(...)` in `lib.rs:175,289-308`. | **No** | `grep -ri redis` in Go = 0. |
| Webhook retry w/ exponential backoff + dead-letter | Yes | **No** — explicit TODO at `plugins/webhooks/dispatcher.go:140-143`: "single attempt … hard-coded to 1 until retry lands". |
| CodeQL static analysis | Yes (`codeql:` job in `.github/workflows/ci.yml`, languages = Rust + JS-TS) | **No** — Go CI has only build/lint/test/integration jobs; no `codeql-action` step. |
| Release automation (knope, semantic versioning) | Yes (`release.yml`) | **No** — Go repo has only `ci.yml`. |
| OpenAPI generation reflectivity | Both have `openapi.json`; both diff-able. | OK, but the Go spec is missing several routes documented in §1 (which means even an "OpenAPI freshness" CI check in Go won't catch the gaps). |
| Trusted-origins / CORS middleware wired | Yes via `trusted_origins` config | **No** corresponding wiring. |
| Schema generation CLI (`cargo yauth init/generate/...`) | Yes (`crates/cargo-yauth/`) | Yes (`cmd/yauth`, used in CI integration smoke). Both have CLIs — broadly at parity. |
| Vue 3 / SolidJS UI components | Yes (`packages/yauth-ui-vue`, `packages/yauth-ui-solidjs`) | Verify in `yauth-go/packages/`. (Out of scope for this analysis — README listed frontend as shipped.) |

---

## 7. Recommended priority order — top 10 gaps to close

Ranked by `(security or correctness impact) × (existing-user expectation) ÷ effort`. One-liner rationale on each.

1. **Email-password full route set** — implement `/verify-email`, `/resend-verification`, `/forgot-password`, `/reset-password`. Without these the plugin is unusable for any production app; the Rust API is the de facto contract.
2. **Per-route rate limiting** — wire the existing `RateLimitRepository` into `register/login/forgot-password/magic-link/totp/verify` via middleware. Foundation already exists; just call `CheckRateLimit` and surface `RateLimitConfig` in `yauthcfg`. High security ROI.
3. **Webhook retry + exponential backoff + dead-letter** — close the explicit TODO in `dispatcher.go:140`; wire `MaxAttempts`, add `RetryDelay`, and persist attempt numbers >1. Otherwise webhook delivery loses events on any transient downstream blip.
4. **Session binding (IP + User-Agent)** — add `SessionConfig.BindIP/BindUA/MismatchAction` and enforce in `middleware/auth.go` against `Session.IPAddress` / `UserAgent` (already on the row). Catches stolen-cookie attacks.
5. **HIBP k-anonymity password breach check** — port `auth/hibp.rs`; make it `hibp_check: true` default with fail-open semantics. ~80 LOC plus an HTTP client.
6. **Password policy (uppercase/lowercase/digit/special/common-passwords/history)** — port `auth/password_policy.rs`. The `PasswordHistory` table likely exists in domain already; verify and wire.
7. **In-memory backend** — unblocks (a) zero-config quickstart parity with Rust's 30-second README, and (b) any conformance harness. Pure-Go map + RWMutex; ~600 LOC.
8. **Repo-conformance harness** — port the `RepoTester` shape from `crates/yauth/tests/repo_conformance.rs`; run against {memory, gorm-sqlite, gorm-postgres}. Catches drift between backends.
9. **Admin OAuth2 client ban + rotate-public-key** — `POST /admin/oauth2/clients/{id}/ban|unban|rotate-public-key`. Without ban, a leaked client_secret can't be revoked except by deleting the client (which breaks audit trail). Documented as security feature in Rust README.
10. **CodeQL workflow + RFC 8414 metadata + remember_me + missing admin routes (`DELETE /admin/users/{id}`, `GET /admin/sessions`, `DELETE /admin/sessions/{id}`)** — bundle of small wins: CodeQL is a one-file CI add; metadata doc is ~30 LOC; `remember_me` is a cfg field + login branch; missing admin routes are each ~40 LOC handlers using existing repo methods (`repo.DeleteUser`, `repo.ListSessions`, `repo.DeleteSession`).

### Out-of-scope for first pass

- MySQL via `gorm.io/driver/mysql` — trivial extension after #7 + #8 land.
- Toasty/SeaORM/sqlx ports — Go community uses GORM; not worth porting.
- Redis decorator — high LOC, needed only for Redis-shop ops; defer until a user asks.
- `db_schema` PG schema isolation — niche; defer.
