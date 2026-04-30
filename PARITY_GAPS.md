# yauth-go vs Rust yauth — Parity Gap Analysis

**Last updated:** 2026-04-30, after the open-redirect fix.

## Status

| | Start of project | Now |
|---|---|---|
| Original top-10 priority gaps | 10 open | **9 closed**; CodeQL skipped per request (Semgrep added) |
| Original "other documented gaps" | 27 open | **20 closed**, 7 still open |
| Security findings surfaced by tests | 1 (open redirect) | 0 — all closed |

CI is green. `go build` / `go vet` / `golangci-lint` / `go test ./...` all pass; full GitHub Actions matrix green at the latest commit.

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
| 7 | In-memory backend | `repo/memrepo/` (10 files, sync.RWMutex) |
| 8 | Repo conformance harness | `repo/conformance/` — 74 cases × 2 backends = 148 tests |
| 9 | Admin OAuth2 client ban / unban / rotate-public-key | `plugins/oauth2server/client_admin.go` |
| 10 (partial) | RFC 8414 metadata + DELETE /admin/users/{id} + GET/DELETE /admin/sessions + remember_me | `plugins/oauth2server/metadata.go`, `plugins/admin/handlers.go` |
| — | Email-enumeration leak on /register | now returns 200 + pending_verification + out-of-band notice |
| — | CodeQL workflow | ⊘ Skipped per user request — Semgrep job added instead |
| — | Semgrep CI job (5 rule packs, ERROR-gated) | `.github/workflows/ci.yml` |

### Round 2 — recommended next-steps 2-10

Commit: `3edb39d` (5 parallel clusters), `05f46e0` (semgrep FP fix), `<this commit>` (open-redirect fix).

| Gap | Where |
|---|---|
| **2** PATCH /me display-name self-update | `plugins/emailpassword/handlers.go` |
| **3** `base_url` + CORS + `trusted_origins` allow-list | `middleware/cors.go` (~115 LOC, no rs/cors), `yauthcfg.CORSConfig` |
| **4** `allow_signups` kill-switch + `auto_admin_first_user` bootstrap | `yauthcfg.ServerConfig` + `host.AllowSignups()` / `host.AutoAdminFirstUser()` |
| **5** Pentest test suite | `pentest_test.go` at repo root — 24 cases, 22 pass |
| **6** Release workflow + tagging | `.github/workflows/release.yml` + `.goreleaser.yaml` (linux/darwin × amd64/arm64) |
| **7** OpenAPI freshness CI check | `openapi-fresh` job — runs `go generate ./openapi/`, fails on dirty diff |
| **8** RFC 7591 dynamic client registration | `plugins/oauth2server/dcr.go` — POST /oauth2/register |
| **9** SMTP mailer adapter | `plugins/mailer/smtp/` — net/smtp + crypto/tls; satisfies all 3 plugin Mailer ifaces structurally |
| **10** Webhook retry persistence (crash-safe) | `plugins/webhooks/dispatcher.go` — persisted retries + claimer goroutine, `yauth_webhook_retries` table |
| — | OAuth open-redirect on `/oauth/{provider}/authorize` | `plugins/oauth/handlers.go::safeRedirect` + `Config.AllowedRedirectURLs` allow-list. Strict-prefix check rejects subdomain attacks (`https://app.example.com.evil.com/...` ≠ `https://app.example.com`). Empty list = redirect_url ignored entirely (safe default). 16 unit-test cases in `plugins/oauth/redirect_test.go`. |

---

## 🟡 Still open

7 items — none security-critical, all operational/stylistic refinements.

### Configuration knobs not yet surfaced

These exist in the Rust config and have no Go equivalent yet:

| Knob | Notes |
|---|---|
| `db_schema` (PG schema isolation, e.g. `auth.yauth_users`) | Niche — only matters when sharing a DB with non-yauth tables. |
| `cookie_domain.Auto` policy | Reflect from request's Host header. Easy to add — small switch in `yauthcfg.SessionConfig` + `middleware`. |
| `account_lockout.max_lockout_duration` cap + `auto_unlock` toggle | The escalating ladder is hard-coded; a cap + toggle would let operators tune. |
| `admin.allow_machine_callers` | Bearer/api-key calls to /admin/* are currently rejected if the user isn't an admin role. This knob would enable M2M-to-admin gating. |
| `bearer.signing_key_pem` (inline via env-var) | Today asymjwt accepts `private_key_path` (file). Adding inline-via-env helps environments where filesystem secrets are awkward (Lambda, etc.). |
| `oidc.id_token_ttl`, `oidc.claims_supported` | Currently hard-coded in `plugins/oidc`. |

### Backends not ported

| Gap | Notes |
|---|---|
| GORM **MySQL** dialect | Trivial — `gorm.io/driver/mysql` import + dialect detection branch. User explicitly said skip. |
| **Redis** caching decorator | Medium — only relevant for Redis-shop ops. Defer until a user asks. |
| Other ORMs (sqlx-go / ent / sqlc) | Skip — Go community uses GORM. |

### Test parity

| Suite | Notes |
|---|---|
| Cross-language route conformance | Compare Rust `openapi.json` and Go `openapi.json` in CI; fail on shape drift. Niche but cheap. |

### Style / cosmetic — won't fix

| Item | Notes |
|---|---|
| PUT vs PATCH on `/admin/users/{id}` | Both work; PATCH is arguably more correct semantically. Document in migration notes. |
| Path prefixes `/mfa/*` (Rust literal) vs Go's `/...` (mounted under host prefix) | Functional behavior identical. |
| Path namespace `/oauth2/*` (Go) vs `/oauth/*` (Rust) | Cosmetic. |

---

## Verification at the latest commit

- `go build ./...` clean
- `go vet ./...` clean
- `golangci-lint run ./...` 0 issues
- `go test ./...` green (28 packages)
- `go generate ./openapi/` deterministic, openapi.json fresh
- All 11 CI jobs green (build × 2, vet, lint, test-sqlite, test-postgres, build-cli, integration, semgrep, openapi-fresh, bench)

---

## Cross-reference index

- Round 1 commits: `497aaee`, `be037af`, `dedaead`, `26a62f9`, `5670f95`.
- Round 2 commits: `3edb39d`, `05f46e0`, plus the open-redirect commit.
- Original priority list in full: see git history of this file at commit `c507177`.
- Build/test perf comparison (Rust vs Go): `BUILD_PERF.md`.
- Frontend client divergences: `packages/client/DIVERGENCES.md`.

## Recommended next steps (prioritized)

If picking up another round:

1. **`cookie_domain.Auto`** — small, frequent need.
2. **Cross-language openapi.json diff in CI** — cheap drift guard.
3. **`bearer.signing_key_pem` inline-via-env** — modest, helps Lambda/serverless deploys.
4. **`oidc.id_token_ttl` + `claims_supported`** — small additions to oidc Config.
5. **`account_lockout.max_lockout_duration` cap** — small, lockout-policy refinement.
6. **`admin.allow_machine_callers`** — small middleware switch.
7. **MySQL backend** — user said skip, but trivial if reversed.
8. **`db_schema`** — defer, niche.
9. **Redis decorator** — defer, demand-driven.
