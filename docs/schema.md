# Database Schema

All tables are prefixed with `yauth_`. Generated migrations are feature-gated — only tables for enabled plugins are included.

Generate migrations with `cargo yauth generate`, then apply with your ORM's CLI:

```bash
# Generate migration files
cargo yauth generate

# Apply with your ORM
diesel migration run        # Diesel
sqlx migrate run            # sqlx
sea-orm-cli migrate up      # SeaORM
```

## Schema by Plugin

Only the tables for your enabled features are created. Core tables are always present.

### Core (always)

| Table | Description |
|-------|-------------|
| `yauth_users` | `id` (uuid), `email`, `display_name`, `email_verified`, `role`, `banned`, `banned_reason`, `banned_until`, `created_at`, `updated_at` |
| `yauth_sessions` | `id` (uuid), `user_id` -> users, `token_hash`, `ip_address`, `user_agent`, `expires_at`, `created_at` |
| `yauth_audit_log` | `id` (uuid), `user_id` -> users, `event_type`, `metadata` (json), `ip_address`, `created_at` |

### email-password

| Table | Description |
|-------|-------------|
| `yauth_passwords` | `user_id` -> users (pk), `password_hash` |
| `yauth_email_verifications` | `id`, `user_id` -> users, `token_hash`, `expires_at`, `created_at` |
| `yauth_password_resets` | `id`, `user_id` -> users, `token_hash`, `expires_at`, `used_at`, `created_at` |

### passkey

| Table | Description |
|-------|-------------|
| `yauth_webauthn_credentials` | `id`, `user_id` -> users, `name`, `aaguid`, `device_name`, `credential` (json), `created_at`, `last_used_at` |

### mfa

| Table | Description |
|-------|-------------|
| `yauth_totp_secrets` | `id`, `user_id` -> users (unique), `encrypted_secret`, `verified`, `created_at` |
| `yauth_backup_codes` | `id`, `user_id` -> users, `code_hash`, `used`, `created_at` |

### oauth

| Table | Description |
|-------|-------------|
| `yauth_oauth_accounts` | `id`, `user_id` -> users, `provider`, `provider_user_id`, `access_token_enc`, `refresh_token_enc`, `expires_at`, `updated_at`, `created_at` |
| `yauth_oauth_states` | `state` (pk), `provider`, `redirect_url`, `expires_at`, `created_at` |

### bearer

| Table | Description |
|-------|-------------|
| `yauth_refresh_tokens` | `id`, `user_id` -> users, `token_hash`, `family_id` (token rotation), `expires_at`, `revoked`, `created_at` |

### api-key

| Table | Description |
|-------|-------------|
| `yauth_api_keys` | `id`, `user_id` -> users, `key_prefix`, `key_hash`, `name`, `scopes` (json), `last_used_at`, `expires_at`, `created_at` |

### magic-link

| Table | Description |
|-------|-------------|
| `yauth_magic_links` | `id`, `email`, `token_hash`, `expires_at`, `used`, `created_at` |

### oauth2-server

| Table | Description |
|-------|-------------|
| `yauth_oauth2_clients` | `id`, `client_id`, `client_secret_hash`, `redirect_uris` (json), `client_name`, `grant_types` (json), `scopes` (json), `is_public`, `created_at` |
| `yauth_authorization_codes` | `id`, `code_hash`, `client_id`, `user_id` -> users, `scopes` (json), `redirect_uri`, `code_challenge`, `code_challenge_method`, `nonce`, `expires_at`, `used`, `created_at` |
| `yauth_consents` | `id`, `user_id` -> users, `client_id`, `scopes` (json), `created_at` -- unique (user_id, client_id) |
| `yauth_device_codes` | `id`, `device_code_hash`, `user_code`, `client_id`, `scopes` (json), `user_id` -> users, `status`, `interval`, `expires_at`, `last_polled_at`, `created_at` |

### account-lockout

| Table | Description |
|-------|-------------|
| `yauth_account_locks` | `id`, `user_id` -> users (unique), `failed_count`, `locked_until`, `lock_count`, `locked_reason`, `created_at`, `updated_at` |
| `yauth_unlock_tokens` | `id`, `user_id` -> users, `token_hash`, `expires_at`, `created_at` |

### webhooks

| Table | Description |
|-------|-------------|
| `yauth_webhooks` | `id`, `url`, `secret`, `events` (json), `active`, `created_at`, `updated_at` |
| `yauth_webhook_deliveries` | `id`, `webhook_id` -> webhooks, `event_type`, `payload` (json), `status_code`, `response_body`, `success`, `attempt`, `created_at` |

### oidc

| Table | Description |
|-------|-------------|
| `yauth_oidc_nonces` | `id`, `nonce_hash`, `authorization_code_id`, `created_at` |

Also adds a `nonce` column to `yauth_authorization_codes`.

Plugins without tables: `admin`, `status`, `telemetry`.
