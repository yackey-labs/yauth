# Client Divergences from `@yackey-labs/yauth-client`

These TS packages were copied from the Rust yauth tree on 2026-04-30 and
adjusted to fit the yauth-go OpenAPI surface. Below is the
delta between the two clients so consumers migrating from the Rust client
know what to expect.

## Status — 2026-04-30 (post Task #39)

Cross-language conformance is **green**:
`scripts/openapi-diff.py` reports 0 BREAKING / 0 MISSING / 0 SHAPE
divergences and the `openapi-conformance` CI job is now hard-gated
(`continue-on-error: false`). yauth-go now exposes a strict superset of
the Rust route surface:

- All BREAKING path renames (`/mfa/*`, `/oauth/*`, `/account/*`) closed.
- All MISSING operations (DELETE/PUT `/admin/users/{id}`, POST
  `/oauth/{provider}/callback`, PUT `/webhooks/{id}`) added.
- All SHAPE divergences resolved — see `MIGRATION_v0.1.0.md` at the repo
  root for the per-endpoint old → new mapping.

The "removed" list below is the residual Go-only superset; everything
else now matches the Rust client surface.

## Go-only routes (superset, not in Rust)

- `/admin/audit`, `/admin/users/{id}/sessions`
- `/oauth2/clients`, `/oauth2/clients/{id}`, `/oauth2/consent` —
  yauth-go's admin client CRUD lives under the legacy `/oauth2/`
  namespace; Rust manages clients out-of-band via DCR
  (`POST /oauth/register`, now also exposed in yauth-go).
- `/lockout/state` — admin overview endpoint.
- `/status` — diagnostic plugin list (Rust uses only `/config`).
- `/webhooks/{id}/deliveries` — paginated history beyond the
  `recent_deliveries` field returned by `GET /webhooks/{id}`.
- `PATCH /admin/users/{id}` — kept alongside Rust's `PUT`.
- `PATCH /webhooks/{id}` — kept alongside Rust's `PUT`.
- `GET /oauth/{provider}/callback` — kept alongside Rust's `POST`-only
  callback for browsers that follow the redirect rather than form-post.

## Renamed function names (operationId-driven)

| Old (Rust)            | New (Go)                |
| --------------------- | ----------------------- |
| `bearerGetToken`      | `bearerIssueToken`      |
| `getSession`          | `emailPasswordSession`  |
| `logout`              | `emailPasswordLogout`   |
| `mfaSetup`            | `mfaTOTPSetup`          |
| `mfaConfirm`          | `mfaTOTPConfirm`        |
| `mfaDisable`          | `mfaTOTPDelete`         |
| `mfaGetBackupCodeCount` | `mfaBackupCodesCount` |
| `oidcOpenidConfiguration` | `oidcDiscovery`     |
| `oidcUserinfo`        | `oidcUserInfo`          |
| `oidcJwks`            | `asymJWKS`              |
| `apiKeysCreate/List/Delete` | `apiKeyCreate/List/Delete` |
| `webhooksCreate/...`  | `webhookCreate/...`     |
| `accountLockout*`     | `lockout*`              |

The wrapper `createYAuthClient(...)` shape (e.g. `client.mfa.setup()`) was
preserved where possible so existing front-end code that relied on the
grouped surface needs minimal changes.

## Schema renames

Rust used names like `LoginRequest`, `BanRequest`, `TokenRequest`. yauth-go
prefixes types with the plugin name to keep the root namespace flat and
unambiguous, e.g.:

| Old (Rust)               | New (Go)                          |
| ------------------------ | --------------------------------- |
| `LoginRequest`           | `EmailPasswordLoginRequest`       |
| `RegisterRequest`        | `EmailPasswordRegisterRequest`    |
| `ChangePasswordRequest`  | `EmailPasswordChangePasswordRequest` |
| `TokenRequest`           | `BearerTokenRequest`              |
| `RefreshRequest`         | `BearerRefreshRequest`            |
| `RevokeRequest`          | `BearerRevokeRequest`             |
| `BanRequest`             | `AdminBanRequest`                 |
| `CreateApiKeyRequest`    | `ApiKeyCreateRequest`             |
| `CreateWebhookRequest`   | `WebhookCreateRequest`            |
| `UpdateWebhookRequest`   | `WebhookUpdateRequest`            |
| `ConfirmTotpRequest`     | `MfaConfirmRequest`               |
| `VerifyMfaRequest`       | `MfaVerifyRequest`                |
| `RequestUnlockRequest`   | `LockoutUnlockReqRequest`         |
| `UnlockAccountRequest`   | `LockoutUnlockRequest`            |

## ui-vue / ui-solidjs typecheck status

The `bun build` step succeeds for both UI packages — they bundle and
ship. The `bun typecheck` step (`vue-tsc --noEmit` / `tsc --noEmit`)
surfaces a small number of errors in components that reference
Rust-only flows: forgot/reset password, email verification, and
`updateProfile`. Those components (`ResetPasswordForm.vue`,
`VerifyEmail.vue`, `reset-password-form.tsx`, `verify-email.tsx`,
`register-form.tsx`) are still copied verbatim; they exist as scaffolding
for when the Go side adds those flows. Until then, embedders that use
the UI packages should import only the components for flows that exist
today (login, MFA challenge, passkey, OAuth provider buttons, session
provider).

