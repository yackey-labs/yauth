# Migration to v0.1.0 — Rust feature parity, Go-better shapes

This release intentionally **breaks the public HTTP API** to align
yauth-go with the Rust yauth crate. Every Rust capability is now
accessible from yauth-go on the same path with the same operation.

The shape of those responses, however, deliberately diverges where Go
made the better engineering call:

- **List endpoints are wrapped** with pagination metadata
  (`{items, page, per_page, total}`), not bare arrays. Adding pagination
  later without breaking clients was the goal.
- **User responses are wrapped** in `{user: {...}}` envelopes. Future
  fields like session metadata, permissions, or tenant context can land
  alongside `user` non-breakingly.
- **`POST /api-keys` returns `{api_key, secret}`** — the metadata is
  loggable, the secret is the one-time leak. Logging the whole response
  by accident leaks the secret; the split makes that mistake harder.
- **`/mfa/totp/setup` keeps `qr_code`** — CLI/mobile clients render the
  pre-baked data URL instead of importing a QR library.

The behavioural contract is unchanged — every endpoint still does the
same thing.

## Path renames (Rust feature parity)

### MFA — every route now lives under `/mfa/`

| Old | New |
|---|---|
| `POST /totp/setup` | `POST /mfa/totp/setup` |
| `POST /totp/confirm` | `POST /mfa/totp/confirm` |
| `DELETE /totp` | `DELETE /mfa/totp` |
| `GET /backup-codes` | `GET /mfa/backup-codes` |
| `POST /backup-codes/regenerate` | `POST /mfa/backup-codes/regenerate` |
| `POST /verify` | `POST /mfa/verify` |

### Lockout — `/unlock*` moved under `/account/`

| Old | New |
|---|---|
| `POST /unlock` | `POST /account/unlock` |
| `POST /unlock/request` | `POST /account/request-unlock` |
| (new) | `POST /admin/users/{id}/unlock` (admin force-unlock) |

`GET /lockout/state` is unchanged (Go superset, not in Rust).

### OAuth2 server — `/oauth2/*` collapsed to `/oauth/*`

| Old | New |
|---|---|
| `GET /oauth2/authorize` | `GET /oauth/authorize` |
| `POST /oauth2/token` | `POST /oauth/token` |
| `POST /oauth2/introspect` | `POST /oauth/introspect` |
| `POST /oauth2/revoke` | `POST /oauth/revoke` |
| `POST /oauth2/register` | `POST /oauth/register` |
| `POST /oauth2/device_authorization` | `POST /oauth/device/code` |
| `POST /oauth2/device` | `POST /oauth/device` |

`/oauth2/clients/*` (admin client CRUD) and `POST /oauth2/consent`
remain at their original paths — Rust does not expose them, and the
Go superset keeps them under the legacy namespace.

The new paths take precedence over the OAuth client plugin's
`/oauth/{provider}/*` wildcard via Go 1.22+ ServeMux specificity rules.

### Admin

- New: `PUT /admin/users/{id}` — alias for `PATCH /admin/users/{id}` (Rust uses PUT).
- The PATCH variant is preserved as a Go-only superset.

### Webhooks

- New: `PUT /webhooks/{id}` — alias for `PATCH /webhooks/{id}`.

### OAuth client

- New: `POST /oauth/{provider}/callback` — JSON / form_post variant of the existing GET callback.

### Status

- New: `GET /config` — admin-gated, returns `{allow_signups, require_email_verification}`.

## Request body changes

| Endpoint | Field changes |
|---|---|
| `POST /register` | optional `display_name` accepted |
| `POST /login` | (unchanged) — `remember_me` was already supported |
| `POST /change-password` | `old_password` → `current_password` |
| `POST /reset-password` | `new_password` → `password` |
| `POST /api-keys` | `expires_at` (RFC3339) → `expires_in_days` (int) |
| `POST /webhooks` | drop `active`; accept optional `secret` (auto-generated if absent) |
| `PUT /webhooks/{id}` | drop `rotate_secret` boolean; accept optional `secret` to replace |
| `POST /magic-link/send` | drop `redirect_url` (use plugin's `LinkBaseURL` instead) |
| `POST /passkey/login/finish` | `request_id` → `challenge_id`, `response` → `credential` |
| `POST /passkeys/register/finish` | `request_id` → `challenge_id`, `response` → `credential`, drop `device_name` |
| `PUT /admin/users/{id}` | accepts optional `email_verified` |

## Response body changes

| Endpoint | New shape |
|---|---|
| `GET /api-keys` | `{items: [...], page, per_page, total}` (paginated; was `{"keys": [...]}`) |
| `POST /api-keys` | `{api_key: {id, name, prefix, scopes, created_at, expires_at}, secret}` (split metadata from one-time plaintext) |
| `POST /change-password` | `{"message": "..."}` (was 204) |
| `POST /forgot-password` | `{"message": "..."}` (was `{"sent": true}`) |
| `POST /verify-email` | `{"message": "..."}` (was `{"verified": true}`) |
| `POST /resend-verification` | `{"message": "..."}` (was `{"sent": true}`) |
| `POST /reset-password` | `{"message": "..."}` (was `{"reset": true}`) |
| `POST /register` | `{"message": "Account created."}` (cookie carries the session) |
| `GET /session` | `{user: {id, email, ..., auth_method, scopes}, expires_at?}` |
| `PATCH /me` | `{user: {...}}` (same wrapper as `/session`) |
| `POST /magic-link/send` | `{"message": "..."}` (was `{"sent": true}`) |
| `POST /magic-link/verify` | `{user: {id, email, display_name, email_verified, role}}` |
| `GET /oauth/accounts` | `{items: [...], page, per_page, total}` |
| `POST /oauth/{provider}/link` | `{auth_url}` (was `{authorize_url}`) |
| `GET /oauth/{provider}/callback`, `POST /oauth/{provider}/callback` | `{user: {id, email, display_name, email_verified, role}}` |
| `GET /passkeys` | `{items: [...], page, per_page, total}` |
| `POST /passkey/login/finish` | `{user: {id, email, display_name, email_verified, role}}` |
| `POST /admin/users/{id}/impersonate` | `{user: {...}}` (admin user shape) |
| `POST /account/unlock`, `POST /account/request-unlock`, `POST /admin/users/{id}/unlock` | `{"message": "..."}` |
| `GET /admin/users` | `{users: [...], page, per_page, total}` |
| `GET /admin/sessions` | `{sessions: [...], page, per_page, total}` |
| `GET /webhooks` | `{items: [...], page, per_page, total}` |
| `GET /webhooks/{id}` | `{webhook: {...}}` (no embedded deliveries — use `/deliveries`) |
| `GET /webhooks/{id}/deliveries` | `{items: [...], page, per_page, total}` |
| `POST /webhooks/{id}/test` | `{delivery_queued: id}` (200) |
| `GET /mfa/backup-codes` | `{"remaining": N}` (was `{"unused": N}`) |
| `POST /mfa/totp/setup` | `{secret, otpauth_url, qr_code, backup_codes}` (qr_code is a data URL) |
| `POST /mfa/totp/confirm`, `DELETE /mfa/totp` | `{"message": "..."}` (were 204) |
| `POST /mfa/verify` | `{user: {id, email, display_name, email_verified, role}}` |

## Pagination

All list endpoints (`GET /api-keys`, `/passkeys`, `/oauth/accounts`,
`/webhooks`, `/webhooks/{id}/deliveries`, `/admin/users`,
`/admin/sessions`) accept `?page=` (1-based) and `?per_page=` (default
50, max 200). Responses include `page`, `per_page`, and `total`
alongside the `items`/`users`/`sessions` array, so clients can render
pagination UI without a second request.

`/admin/users` and `/admin/sessions` also accept the legacy
`?limit=&offset=`; if both are supplied, `limit/offset` wins.

## Cross-language conformance

> **Historical:** the Rust backend has since been archived and huma's
> auto-derived spec is now yauth-go's single source of truth. The cross-language
> conformance gate described below (`scripts/openapi-{diff,conformance}.py`, the
> `openapi-conformance` CI job) has been removed; it is preserved here only as a
> record of the v0.1.0 migration. The current spec gate is `openapi-fresh`
> (regenerate huma spec == committed `openapi.json`).

`scripts/openapi-diff.py` was a hard CI gate for **feature parity**:

- BREAKING (path missing in Go) → fails the check.
- MISSING (operation missing in Go) → fails the check.
- SHAPE (response/request field divergence) → reported as informational.
  yauth-go intentionally diverges on shape; the goal is forward
  compatibility, not byte parity.

If you're moving from a Rust frontend to a Go backend, no client changes
are required: yauth and yauth-go share a single set of npm packages
(`@yackey-labs/yauth-{client,shared,ui-vue,ui-solidjs}`) generated from
the same converged OpenAPI spec. CI gates byte-equivalence on every PR;
see `scripts/openapi-conformance.py` and the `openapi-conformance`
job in both repos.

## Documented divergences

After Phase 1 of the convergence plan there are **none** — yauth and
yauth-go agree on every path, every method, and every top-level
request/response field. Previously Go-only routes (`/admin/audit`,
`/admin/users/{id}/sessions`, `/oauth2/clients{,/{id}}`, `/oauth2/consent`,
`/lockout/state`, `/status`) all ship in the Rust backend too; the
strict CI gate (Phase 2) enforces this.
- `PATCH /admin/users/{id}` (kept alongside the new PUT)
- `PATCH /webhooks/{id}` (kept alongside the new PUT)
- `GET /oauth/{provider}/callback` (Rust only ships POST)
