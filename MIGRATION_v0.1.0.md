# Migration to v0.1.0 — Cosmetic parity with the Rust yauth spec

This release intentionally **breaks the public HTTP API** to align
yauth-go with the Rust yauth crate's route names and JSON shapes. The
`scripts/openapi-diff.py` cross-language conformance check is now a
hard gate in CI; it returns 0 for this release.

The behavioural contract is unchanged — every endpoint still does the
same thing. Only paths, request field names, and response field names
have moved.

## Path renames

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

Every `{user: {...}}` envelope is now flat. Several success bodies are
now `{"message": "..."}` instead of `{"sent": true}` / `{"verified": true}` etc.

| Endpoint | New shape |
|---|---|
| `GET /api-keys` | bare `[ApiKey]` array (was `{"keys": [...]}`) |
| `POST /api-keys` | flat `{id, name, prefix, scopes, created_at, expires_at, key}` (was nested + `key` was `secret`) |
| `POST /change-password` | `{"message": "..."}` (was 204) |
| `POST /forgot-password` | `{"message": "..."}` (was `{"sent": true}`) |
| `POST /verify-email` | `{"message": "..."}` (was `{"verified": true}`) |
| `POST /resend-verification` | `{"message": "..."}` (was `{"sent": true}`) |
| `POST /reset-password` | `{"message": "..."}` (was `{"reset": true}`) |
| `POST /register` | `{"message": "Account created."}` (was `{user: {...}}`) |
| `GET /session` | flat `{id, email, display_name, email_verified, role, banned, auth_method, scopes}` (was `{user: {...}, expires_at}`) |
| `PATCH /me` | same flat shape as `/session` |
| `POST /magic-link/send` | `{"message": "..."}` (was `{"sent": true}`) |
| `POST /magic-link/verify` | flat `{user_id, email, display_name, email_verified}` |
| `GET /oauth/accounts` | bare `[OAuthAccount]` array (was `{"accounts": [...]}`) |
| `POST /oauth/{provider}/link` | `{auth_url}` (was `{authorize_url}`) |
| `GET /oauth/{provider}/callback`, `POST /oauth/{provider}/callback` | flat `{user_id, email, display_name, email_verified}` (was `{user, provider}`) |
| `GET /passkeys` | bare `[Passkey]` array (was `{"passkeys": [...]}`) |
| `POST /passkey/login/finish` | flat user fields (was `{user: {...}}`) |
| `POST /admin/users/{id}/impersonate` | empty 200 (was `{user: {...}}`) |
| `POST /account/unlock`, `POST /account/request-unlock`, `POST /admin/users/{id}/unlock` | `{"message": "..."}` |
| `GET /admin/users` | adds `page` and `per_page` alongside `total` |
| `GET /admin/sessions` | adds `page` and `per_page` |
| `GET /webhooks` | bare `[Webhook]` array |
| `GET /webhooks/{id}` | `{webhook: {...}, recent_deliveries: [...]}` (deliveries trimmed to 10) |
| `GET /webhooks/{id}/deliveries` | bare array |
| `POST /webhooks/{id}/test` | empty 202 (was `{delivery_queued, event_type}`) |
| `GET /mfa/backup-codes` | `{"remaining": N}` (was `{"unused": N}`) |
| `POST /mfa/totp/setup` | drops `qr_code` (data-URL); only `secret`, `otpauth_url`, `backup_codes` remain |
| `POST /mfa/totp/confirm`, `DELETE /mfa/totp` | `{"message": "..."}` (were 204) |
| `POST /mfa/verify` | `{user_id, email, display_name, email_verified}` |

## Pagination

`GET /admin/users` and `GET /admin/sessions` now accept either
`?limit=&offset=` or `?page=&per_page=`. The two are translated
internally; if both are supplied, `limit/offset` wins.

## Documented divergences (Go superset)

These remain Go-only and the conformance check accepts them as
informational:

- `/admin/audit`, `/admin/users/{id}/sessions`
- `/oauth2/clients`, `/oauth2/clients/{id}`, `/oauth2/consent`
- `/lockout/state`
- `/status`
- `/webhooks/{id}/deliveries`
- `PATCH /admin/users/{id}` (kept alongside the new PUT)
- `PATCH /webhooks/{id}` (kept alongside the new PUT)
- `GET /oauth/{provider}/callback` (Rust only ships POST)
