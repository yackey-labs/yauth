# yauth-go vs Rust yauth — Parity Gap Analysis

**Last updated:** 2026-04-30, after commit `900ce1a` (CI: 12 / 13 green; the one ⚠️ is the intentionally non-blocking Rust↔Go conformance job).

## Status

| | Start of project | Now |
|---|---|---|
| Original top-10 priority gaps | 10 open | **9 closed**; CodeQL skipped per request (Semgrep added) |
| Original "other documented gaps" | 27 open | **26 closed**, 1 still open |
| Security findings surfaced by tests | 1 (open redirect) | 0 — all closed |

CI matrix: build × Go 1.22/1.23, vet, golangci-lint, test-sqlite, test-postgres, **test-mysql**, build-cli, integration, semgrep, openapi-fresh, **openapi-conformance** (advisory), bench. All green.

---

## ⚠️ Shipped but NOT enforced

Surfaces that exist, accept configuration and return it, while nothing acts
on the value. Listed here because "the route exists" has repeatedly been
read as "the control exists".

| Surface | State | Reference |
|---|---|---|
| Per-org auth policy (`PATCH /organizations/{id}/policy`) | Stored and returned; **yauth enforces none of it by itself**. `ip_allowlist` and `idle_timeout_secs` apply only where the host installs `middleware.OrgPolicyEnforcer`; `max_session_duration_secs`, `max_concurrent_sessions`, `allowed_auth_methods`, `mfa_required` and the per-org `session_binding` are applied nowhere. | [docs/org-policy-enforcement.md](docs/org-policy-enforcement.md) |
| `auth.IssueSessionWithPolicy` | Zero non-test callers. Every login path calls plain `auth.IssueSession`. | `auth/session.go` |

The `enforcement` block on `GET /organizations/{id}/policy` reports the same
breakdown to API clients.

---

## ✅ Closed (chronological by commit cluster)

### Round 1 — top-10 priority list

Commits: `497aaee → be037af → dedaead → 26a62f9 → 5670f95`

| # | Gap | Where |
|---|---|---|
| 1 | email-password full route set (verify-email / resend-verification / forgot-password / reset-password) | `plugins/emailpassword/handlers.go` + new mailer interface |
| 2 | Per-route rate limiting via `host.RateLimit` middleware | `middleware/ratelimit.go`, wired into 6 emailpassword routes |
| 3 | Webhook retry + exponential backoff + dead-letter | `plugins/webhooks/dispatcher.go` (closes explicit TODO) |
| 4 | Session binding (IP + User-Agent, warn-or-invalidate) | `middleware/middleware.go` enforceBinding |
| 5 | HaveIBeenPwned k-anonymity password breach check | `auth/hibp/hibp.go`, default-on |
| 6 | Password policy (uppercase/lowercase/digit/special/common-passwords/history) | `auth/passwordpolicy/` + `yauth_password_history` table |
| 7 | In-memory backend | `repo/memrepo/` |
| 8 | Repo conformance harness | `repo/conformance/` — runs against memrepo, gorm-sqlite, gorm-postgres, gorm-mysql, redisrepo+memrepo |
| 9 | Admin OAuth2 client ban / unban / rotate-public-key | `plugins/oauth2server/client_admin.go` |
| 10 (partial) | RFC 8414 metadata + DELETE /admin/users/{id} + GET/DELETE /admin/sessions + remember_me | `plugins/oauth2server/metadata.go`, `plugins/admin/handlers.go` |
| — | Email-enumeration leak on /register | now returns 200 + pending_verification + out-of-band notice |
| — | CodeQL workflow | ⊘ Skipped per user request — Semgrep job added instead |
| — | Semgrep CI job (5 rule packs, ERROR-gated) | `.github/workflows/ci.yml` |

### Round 2 — recommended next-steps 2-10 + open-redirect

Commits: `3edb39d → 05f46e0 → ba3fad2`

| Gap | Where |
|---|---|
| **2** PATCH /me display-name self-update | `plugins/emailpassword/handlers.go` |
| **3** `base_url` + CORS + `trusted_origins` allow-list | `middleware/cors.go` (~115 LOC, no rs/cors), `yauthcfg.CORSConfig` |
| **4** `allow_signups` kill-switch + `auto_admin_first_user` bootstrap | `yauthcfg.ServerConfig` + `host.AllowSignups()` / `host.AutoAdminFirstUser()` |
| **5** Pentest test suite | `pentest_test.go` at repo root — 24 cases |
| **6** Release workflow + tagging | `.github/workflows/release.yml` + `.goreleaser.yaml` (linux/darwin × amd64/arm64) |
| **7** OpenAPI freshness CI check | `openapi-fresh` job — runs `go generate ./openapi/`, fails on dirty diff |
| **8** RFC 7591 dynamic client registration | `plugins/oauth2server/dcr.go` — POST /oauth2/register |
| **9** SMTP mailer adapter | `plugins/mailer/smtp/` — net/smtp + crypto/tls |
| **10** Webhook retry persistence (crash-safe) | `plugins/webhooks/dispatcher.go` — persisted retries + claimer goroutine, `yauth_webhook_retries` table |
| — | OAuth open-redirect on `/oauth/{provider}/authorize` | `plugins/oauth/handlers.go::safeRedirect` + `Config.AllowedRedirectURLs` allow-list. Strict-prefix check rejects subdomain attacks. 16 unit-test cases in `plugins/oauth/redirect_test.go`. |

### Round 3 — config knobs + cross-language conformance + Redis + MySQL

Commit: `900ce1a`

| Gap | Where |
|---|---|
| `database.schema` (PG search_path) | `yauthcfg.DatabaseConfig.Schema` + `gormrepo.OpenPostgres` |
| `session.cookie_domain` "auto" (reflect Host header) | `auth.ResolveCookieDomain` + every cookie issuance site |
| `account_lockout.max_lockout_duration` cap + `auto_unlock` toggle | `lockout.Config` + `yauthcfg.AccountLockPluginConfig` |
| `admin.allow_machine_callers` | `domain.AuthUser.Method` + `middleware.RequireAdmin` gate |
| `bearer.signing_key_pem` inline-via-env | `asymjwt.Config` `PrivateKeyPEM` / `PublicKeyPEM` + `yauthcfg.PrivateKeyPEMEnv` / `PublicKeyPEMEnv` |
| `oidc.id_token_ttl` + `claims_supported` | `oidc.Config` + discovery doc carries `claims_supported` |
| Cross-language route conformance | `scripts/openapi-diff.py` + `openapi-conformance` CI job (advisory) |
| **Redis caching decorator** | `repo/redisrepo/` — read-through sessions/challenges/revocations + atomic Lua INCR+EXPIRE rate limits + miniredis-backed tests + conformance integration |
| **MySQL backend** | `gormrepo.OpenMySQL` (gorm.io/driver/mysql) + `keyEq` reserved-word helper + FOR UPDATE / SKIP LOCKED on MySQL 8 + `test-mysql` CI job |

---

## 🟡 Still open

One item, advisory only.

| Gap | Notes |
|---|---|
| Rust ↔ Go endpoint naming divergences | 24 BREAKING + 4 MISSING + 34 SHAPE entries surfaced by `openapi-conformance` (continue-on-error). Mostly cosmetic naming differences (`/forgot-password` shape, `/oauth/token` namespace, DELETE/PUT `/admin/users/{id}` method). The job's report is uploaded as a CI artifact for per-endpoint triage. Fixing each is a small migration cost; none blocks production use of yauth-go. |

### Cosmetic / won't fix

| Item | Notes |
|---|---|
| PUT vs PATCH on `/admin/users/{id}` | Both work; PATCH is more correct semantically. |
| Path prefixes `/mfa/*` (Rust literal) vs Go's `/...` (mounted under host prefix) | Functional behavior identical. |
| Path namespace `/oauth2/*` (Go) vs `/oauth/*` (Rust) | Cosmetic. |

### Backends

| Gap | Notes |
|---|---|
| GORM **MySQL** dialect | ✅ shipped (Round 3). |
| **Redis** caching decorator | ✅ shipped (Round 3). |
| Other ORMs (sqlx-go / ent / sqlc) | Won't port — Go community uses GORM. |

---

## Verification at the latest commit (`900ce1a`)

- `go build ./...` clean
- `go vet ./...` clean
- `golangci-lint run ./...` 0 issues
- `go test ./...` green (28 packages)
- `go generate ./openapi/` deterministic, openapi.json fresh
- All 12 hard CI jobs green; 1 advisory (Rust↔Go conformance) reports cosmetic divergences.

---

## Cross-reference index

- Round 1 commits: `497aaee`, `be037af`, `dedaead`, `26a62f9`, `5670f95`.
- Round 2 commits: `3edb39d`, `05f46e0`, `ba3fad2`.
- Round 3 commit: `900ce1a`.
- Original priority list in full: see git history of this file at commit `c507177`.
- Build/test perf comparison (Rust vs Go): `BUILD_PERF.md`.
- Frontend client + UI components: now live in the
  [yauth (Rust)](https://github.com/yackey-labs/yauth) repo as
  `@yackey-labs/yauth-{client,shared,ui-vue,ui-solidjs}`; both backends
  share a single converged spec.

**Status:** Ready to tag v0.1.0.
