# Client Divergences from `@yackey-labs/yauth-client`

These TS packages were copied from the Rust yauth tree on 2026-04-30 and
adjusted to fit the yauth-go OpenAPI surface. Below is the
delta between the two clients so consumers migrating from the Rust client
know what to expect.

## Removed (yauth-go does not implement these endpoints today)

- `emailPassword.verify` / `verifyEmail` — email verification flow.
- `emailPassword.resendVerification`.
- `emailPassword.forgotPassword` / `resetPassword`.
- `updateProfile` (PATCH /me).
- `admin.deleteUser` — admin can ban a user; hard-delete is intentionally
  not exposed because issued tokens still reference the row.
- `admin.listSessions` / `admin.deleteSession` — single-session admin
  endpoint not yet wired (use `admin.deleteUserSessions` to revoke all).
- `accountLockoutAdminUnlock` — replaced by the user-facing `lockout.unlock`
  + admin `lockout.state` pair.
- `oauth2Server.register` (DCR — RFC 7591) — clients are registered via
  the admin endpoint `oauth2Server.createClient` instead.
- `oauth2Server.deviceApprove` is folded into `oauth2Server.deviceVerify`
  in the Go server.
- `oauth2Server.metadata` — yauth-go advertises OAuth2 endpoints through
  the OIDC discovery doc (`oidc.discovery`) rather than a separate
  `/oauth2/metadata` route.

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

