//! Schema definitions for each built-in plugin.
//!
//! These functions are called by each plugin's `schema()` method.
//! Centralizing them here makes it easy to verify they match the existing SQL.

use super::types::*;

/// Email-password plugin: passwords, email_verifications, password_resets.
pub fn email_password_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_passwords")
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .primary_key()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("password_hash", ColumnType::Varchar)),
        TableDef::new("yauth_email_verifications")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("token_hash", ColumnType::VarcharN(64)).unique())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_password_resets")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("token_hash", ColumnType::VarcharN(64)).unique())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("used_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Passkey plugin: webauthn_credentials.
pub fn passkey_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_webauthn_credentials")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("name", ColumnType::Varchar))
            .column(ColumnDef::new("aaguid", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("device_name", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("credential", ColumnType::Json))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("last_used_at", ColumnType::DateTime).nullable()),
    ]
}

/// MFA plugin: totp_secrets, backup_codes.
pub fn mfa_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_totp_secrets")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .unique()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("encrypted_secret", ColumnType::Varchar))
            .column(ColumnDef::new("verified", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_backup_codes")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("code_hash", ColumnType::VarcharN(64)))
            .column(ColumnDef::new("used", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// OAuth plugin: oauth_accounts, oauth_states.
/// Includes the oauth_token_refresh columns (expires_at, updated_at) merged in.
pub fn oauth_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_oauth_accounts")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("provider", ColumnType::Varchar))
            .column(ColumnDef::new("provider_user_id", ColumnType::Varchar))
            .column(ColumnDef::new("access_token_enc", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("refresh_token_enc", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            // From migration 009 (oauth_token_refresh)
            .column(ColumnDef::new("expires_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_oauth_states")
            .column(ColumnDef::new("state", ColumnType::Varchar).primary_key())
            .column(ColumnDef::new("provider", ColumnType::Varchar))
            .column(ColumnDef::new("redirect_url", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Bearer plugin: refresh_tokens.
pub fn bearer_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_refresh_tokens")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("token_hash", ColumnType::VarcharN(64)).unique())
            .column(ColumnDef::new("family_id", ColumnType::Uuid))
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("revoked", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// API key plugin: api_keys.
pub fn api_key_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_api_keys")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("key_prefix", ColumnType::VarcharN(12)).unique())
            .column(ColumnDef::new("key_hash", ColumnType::VarcharN(64)))
            .column(ColumnDef::new("name", ColumnType::Varchar))
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(ColumnDef::new("last_used_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Magic link plugin: magic_links.
pub fn magic_link_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_magic_links")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("email", ColumnType::Varchar))
            .column(ColumnDef::new("token_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("used", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// OAuth2 server plugin: oauth2_clients, authorization_codes, consents, device_codes.
pub fn oauth2_server_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_oauth2_clients")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("client_id", ColumnType::Varchar).unique())
            .column(ColumnDef::new("client_secret_hash", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("redirect_uris", ColumnType::Json))
            .column(ColumnDef::new("client_name", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("grant_types", ColumnType::Json))
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(ColumnDef::new("is_public", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_authorization_codes")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("code_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("client_id", ColumnType::Varchar))
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(ColumnDef::new("redirect_uri", ColumnType::Varchar))
            .column(ColumnDef::new("code_challenge", ColumnType::Varchar))
            .column(ColumnDef::new("code_challenge_method", ColumnType::Varchar))
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("used", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("nonce", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_consents")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("client_id", ColumnType::Varchar))
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_device_codes")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("device_code_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("user_code", ColumnType::Varchar).unique())
            .column(ColumnDef::new("client_id", ColumnType::Varchar))
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("status", ColumnType::Varchar).default("'pending'"))
            .column(ColumnDef::new("interval", ColumnType::Int).default("5"))
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("last_polled_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Account lockout plugin: account_locks, unlock_tokens.
pub fn account_lockout_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_account_locks")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .unique()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("failed_count", ColumnType::Int).default("0"))
            .column(ColumnDef::new("locked_until", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("lock_count", ColumnType::Int).default("0"))
            .column(ColumnDef::new("locked_reason", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_unlock_tokens")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("token_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Webhooks plugin: webhooks, webhook_deliveries.
pub fn webhooks_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_webhooks")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("url", ColumnType::Varchar))
            .column(ColumnDef::new("secret", ColumnType::Varchar))
            .column(ColumnDef::new("events", ColumnType::Json))
            .column(ColumnDef::new("active", ColumnType::Boolean).default("true"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_webhook_deliveries")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("webhook_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_webhooks", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("event_type", ColumnType::Varchar))
            .column(ColumnDef::new("payload", ColumnType::Json))
            .column(ColumnDef::new("status_code", ColumnType::SmallInt).nullable())
            .column(ColumnDef::new("response_body", ColumnType::Text).nullable())
            .column(ColumnDef::new("success", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("attempt", ColumnType::Int).default("1"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// OIDC plugin: oidc_nonces.
pub fn oidc_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_oidc_nonces")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("nonce_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("authorization_code_id", ColumnType::Uuid))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}
