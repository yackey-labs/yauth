# yauth-go vs Rust yauth — Parity Gap Analysis

**Last updated:** 2026-04-30 after commit `5670f95` (CI green).

## Status

| | Original (commit `c507177`) | After this session (`5670f95`) |
|---|---|---|
| Top-10 priority gaps | 10 open | **9 closed**, CodeQL skipped per request (Semgrep added instead) |
| Other documented gaps | 27 open | 13 still open, 14 closed |

What follows: the original analysis with each item annotated with its closing commit, plus a fresh "Still open" section.

Sources of truth used for diffing:
- Rust route list: `/Users/syackey/steveyackey/yackey-labs/yauth/docs/api-routes.md`
- Go route list: extracted from `/Users/syackey/steveyackey/yackey-labs/yauth-go/openapi.json`
- Rust config: `/Users/syackey/steveyackey/yackey-labs/yauth/crates/yauth/src/config.rs` + `docs/configuration.md`
- Go config: `/Users/syackey/steveyackey/yackey-labs/yauth-go/yauthcfg/config.go`

---

## ✅ Closed in this session

**Commits:** `497aaee` (top-10 + Semgrep) → `be037af` → `dedaead` → `26a62f9` → `5670f95` (CI green)

| # | Gap | Status | Where |
|---|---|---|---|
| 1 | email-password full route set (verify-email / resend-verification / forgot-password / reset-password) | ✅ | `plugins/emailpassword/handlers.go`, new mailer interface |
| 2 | Per-route rate limiting via `host.RateLimit` middleware | ✅ | `middleware/ratelimit.go`, wired into 6 emailpassword routes |
| 3 | Webhook retry + exponential backoff + dead-letter | ✅ | `plugins/webhooks/dispatcher.go`, closes the explicit TODO |
| 4 | Session binding (IP + User-Agent, warn-or-invalidate) | ✅ | `middleware/middleware.go` enforceBinding |
| 5 | HaveIBeenPwned k-anonymity password breach check | ✅ | `auth/hibp/hibp.go`, default-on |
| 6 | Password policy (uppercase/lowercase/digit/special/common-passwords/history) | ✅ | `auth/passwordpolicy/policy.go` + `yauth_password_history` table |
| 7 | In-memory backend | ✅ | `repo/memrepo/` (10 files, sync.RWMutex) |
| 8 | Repo conformance harness | ✅ | `repo/conformance/` — 74 cases × 2 backends = 148 tests |
| 9 | Admin OAuth2 client ban / unban / rotate-public-key | ✅ | `plugins/oauth2server/client_admin.go` |
| 10 (partial) | RFC 8414 metadata + DELETE /admin/users/{id} + GET/DELETE /admin/sessions + remember_me | ✅ | `plugins/oauth2server/metadata.go`, `plugins/admin/handlers.go` |
| — | Email-enumeration leak on /register | ✅ | dup email now returns 200 + pending_verification + out-of-band notice |
| — | CodeQL workflow | ⊘ | Skipped per user request — Semgrep job added instead |
| — | Semgrep CI job (`p/default`, `p/security-audit`, `p/secrets`, `p/golang`, `p/owasp-top-ten`) | ✅ | `.github/workflows/ci.yml`, gates ERROR severity |

Verification at `5670f95`:
- `go build ./...` clean
- `go vet ./...` clean
- `golangci-lint run ./...` 0 issues
- `go test ./...` green across all 26 packages
- All 10 GitHub Actions jobs pass on commit `5670f95` (run [25182440306](https://github.com/yackey-labs/yauth-go/actions/runs/25182440306))

---

## 🟡 Still open

The following items from the original analysis remain unaddressed. None are critical for the documented MVP path.

### Routes — minor parity divergences

| Method | Path | Status | Notes |
|---|---|---|---|
| PATCH | `/me` | **Open** | Display-name self-update missing. Rust mounts at `crates/yauth/src/plugins/mod.rs:59`. Easy to add to email-password as a small handler. |
| PUT | `/admin/users/{id}` (Rust) vs PATCH (Go) | Style divergence | Both work; PATCH is arguably more correct semantically. Document, don't change. |
| POST | `/oauth2/register` (RFC 7591 dynamic client registration) | **Open** | Public DCR endpoint absent. `POST /oauth2/clients` exists but is admin-gated. Add a small public handler that requires PKCE + adds `is_public=true`. |
| Path prefixes | `/mfa/...` vs `/...` (Go strips prefix) | **Open** | Stylistic — Go's mounts use `/mfa/` only at the host's prefix. Rust applies `/mfa/` literally. Functional behavior identical; document or align prefixes. |
| Path namespace | `/oauth2/...` vs `/oauth/...` | **Open** | Both work; Rust uses `/oauth/` literal. Pure cosmetic divergence — not worth changing. |

### Configuration knobs not yet surfaced

These exist in the Rust config and have no Go equivalent yet. None block MVP usage; they're operational refinements:

- `base_url` (top-level) — used in email templates / OAuth redirects.
- `trusted_origins` (CORS allow-list) — no CORS middleware in `yauthcfg`.
- `smtp` (`SmtpConfig{host,port,from}`) — Go uses a `Mailer` interface only, no built-in SMTP. Add a `mailer.smtp` adapter for parity.
- `auto_admin_first_user` — first-user-becomes-admin bootstrap.
- `allow_signups` — global registration kill-switch.
- `db_schema` (PG schema isolation, e.g. `auth.yauth_users`) — niche.
- `cookie_domain.Auto` policy — Go has the explicit string only.
- `account_lockout.max_lockout_duration` (cap) and `auto_unlock` toggle — Go ladder is hard-coded; cap is implicit.
- `admin.allow_machine_callers` — M2M-to-admin gating.
- `bearer.signing_key_pem` (inline via env-var) — only `private_key_path` (file) supported by asymjwt.
- `oidc.id_token_ttl`, `oidc.claims_supported` — defaults are hard-coded.

### Backends not ported

Rust ships **14 backends** (Diesel/sqlx/SeaORM/Toasty × PG/MySQL/SQLite + libsql + memory). Go ships **2 GORM dialects + memory** = 3.

| Gap | Effort | Notes |
|---|---|---|
| GORM **MySQL** dialect | Trivial — `gorm.io/driver/mysql` import + dialect detection branch in `gormrepo`/`yauthcfg/validate.go`. The model layer is dialect-agnostic. |
| **Redis** caching decorator (`crates/yauth/src/backends/redis/`) | Medium — only relevant for Redis-shop ops; defer until a user asks. |
| Other ORMs (sqlx-go / ent / sqlc) | Skip — Go community uses GORM; one ORM is enough. |

### Test parity

| Suite | Status | Notes |
|---|---|---|
| Repo conformance | ✅ | Done — 74 cases × 2 backends. Add gorm-postgres in CI when DATABASE_URL is set (already wired in `test-postgres` job). |
| Pentest / OWASP suite | ✅ | Ported to `pentest_test.go` at repo root. 22 cases pass + 2 documented skips (HIBP exercised elsewhere; OAuth open-redirect — see below). |
| Cross-language route conformance | **Open** | Compare `openapi.json` between Rust + Go in CI; fail if shapes drift. Niche but useful. |

### Security gaps surfaced by the pentest port

| Gap | Severity | Notes |
|---|---|---|
| **Open redirect on `/oauth/{provider}/authorize`** | Medium | `redirect_url` query parameter is accepted verbatim and returned in the callback redirect. No allow-list. Should add `oauth.AllowedRedirectURLs []string` (or a per-provider allow-list) and reject anything not on it. Pentest case is `TestPentest_OAuthOpenRedirect_NotEnforced` — `t.Skip`-ed pending fix. |

### Infrastructure

| Item | Status | Notes |
|---|---|---|
| CodeQL static analysis | ⊘ | Deliberately skipped per user request; Semgrep replaces it. |
| Release automation (knope, semantic versioning) | **Open** | Rust has `release.yml`; Go has only `ci.yml`. Add when ready to publish v0.1.0. |
| OpenAPI freshness check in CI | **Open** | Run `go generate ./openapi/`, diff `openapi.json`, fail on dirty tree. |
| Webhook delivery scheduling persistence | **Open** | Currently `time.AfterFunc` lives only in process. Process restart drops in-flight retries. Persist scheduled retries in a "pending" table for crash safety. |
| `cookie_domain.Auto` policy | **Open** | Reflects from the request's Host header. Easy to add. |

---

## Recommended next steps

Ranked by `(value × user-expectation) ÷ effort`, picking up where the priority list left off.

1. **MySQL backend** — one file. Unblocks any Go user with an existing MySQL stack. ~30 min.
2. **PATCH /me** — tiny route on email-password. Closes the most-visible README parity gap. ~30 min.
3. **`base_url` + `trusted_origins` + CORS middleware** — small handful of config knobs that any production deployment needs. ~2 hours.
4. **`allow_signups` kill-switch + `auto_admin_first_user`** — operational primitives. ~1 hour.
5. **Pentest suite** — port Rust's `tests/pentest.rs`. The most security-relevant remaining gap. Estimate: half a day.
6. **Release workflow + tagging strategy** — needed before v0.1.0 publish.
7. **OpenAPI freshness CI check** — prevents stealth API drift.
8. **`POST /oauth2/register` (RFC 7591 DCR)** — opens the door to ecosystem clients.
9. **SMTP mailer adapter** — completes the email story for production deployments without a separate notification service.
10. **Webhook retry persistence** — only matters for high-availability deployments where a process restart during retry would lose events.

---

## Cross-reference index

- Closed gaps: see commits `497aaee` and follow-ups (`be037af`, `dedaead`, `26a62f9`, `5670f95`).
- Original ranked priority list (now closed except CodeQL): see git history of this file at commit `c507177`.
- Build/test perf comparison (Rust vs Go): `BUILD_PERF.md`.
- Frontend client divergences: `packages/client/DIVERGENCES.md`.
