use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::schema::*;

// ──────────────────────────────────────────────
// Core: yauth_users
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
pub struct NewUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub display_name: Option<Option<String>>,
    pub email_verified: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub banned_reason: Option<Option<String>>,
    pub banned_until: Option<Option<NaiveDateTime>>,
    pub updated_at: Option<NaiveDateTime>,
}

// ──────────────────────────────────────────────
// Core: yauth_sessions
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_sessions)]
pub struct NewSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// Core: yauth_audit_log
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_audit_log)]
pub struct NewAuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub metadata: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// Postgres store: yauth_challenges
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub key: String,
    pub value: serde_json::Value,
    pub expires_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// email-password: yauth_passwords
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_passwords)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Password {
    pub user_id: Uuid,
    pub password_hash: String,
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_passwords)]
pub struct NewPassword {
    pub user_id: Uuid,
    pub password_hash: String,
}

// ──────────────────────────────────────────────
// email-password: yauth_email_verifications
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_email_verifications)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct EmailVerification {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_email_verifications)]
pub struct NewEmailVerification {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// email-password: yauth_password_resets
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_password_resets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct PasswordReset {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub used_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_password_resets)]
pub struct NewPasswordReset {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// passkey: yauth_webauthn_credentials
// ──────────────────────────────────────────────

#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webauthn_credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct WebauthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,
    pub credential: serde_json::Value,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}

#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webauthn_credentials)]
pub struct NewWebauthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,
    pub credential: serde_json::Value,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// mfa: yauth_totp_secrets
// ──────────────────────────────────────────────

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_totp_secrets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct TotpSecret {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_totp_secrets)]
pub struct NewTotpSecret {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// mfa: yauth_backup_codes
// ──────────────────────────────────────────────

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_backup_codes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct BackupCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_backup_codes)]
pub struct NewBackupCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used: bool,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// oauth: yauth_oauth_accounts
// ──────────────────────────────────────────────

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OauthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_accounts)]
pub struct NewOauthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// oauth: yauth_oauth_states
// ──────────────────────────────────────────────

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_states)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OauthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_states)]
pub struct NewOauthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// api-key: yauth_api_keys
// ──────────────────────────────────────────────

#[cfg(feature = "api-key")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_api_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Option<serde_json::Value>,
    pub last_used_at: Option<NaiveDateTime>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "api-key")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_api_keys)]
pub struct NewApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Option<serde_json::Value>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// bearer: yauth_refresh_tokens
// ──────────────────────────────────────────────

#[cfg(feature = "bearer")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_refresh_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub family_id: Uuid,
    pub expires_at: NaiveDateTime,
    pub revoked: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "bearer")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_refresh_tokens)]
pub struct NewRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub family_id: Uuid,
    pub expires_at: NaiveDateTime,
    pub revoked: bool,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// magic-link: yauth_magic_links
// ──────────────────────────────────────────────

#[cfg(feature = "magic-link")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_magic_links)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct MagicLink {
    pub id: Uuid,
    pub email: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "magic-link")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_magic_links)]
pub struct NewMagicLink {
    pub id: Uuid,
    pub email: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// oauth2-server: yauth_oauth2_clients
// ──────────────────────────────────────────────

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth2_clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Oauth2Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: serde_json::Value,
    pub client_name: Option<String>,
    pub grant_types: serde_json::Value,
    pub scopes: Option<serde_json::Value>,
    pub is_public: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth2_clients)]
pub struct NewOauth2Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: serde_json::Value,
    pub client_name: Option<String>,
    pub grant_types: serde_json::Value,
    pub scopes: Option<serde_json::Value>,
    pub is_public: bool,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// oauth2-server: yauth_authorization_codes
// ──────────────────────────────────────────────

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_authorization_codes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub code_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Option<serde_json::Value>,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
    pub nonce: Option<String>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_authorization_codes)]
pub struct NewAuthorizationCode {
    pub id: Uuid,
    pub code_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Option<serde_json::Value>,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
    pub nonce: Option<String>,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// oauth2-server: yauth_consents
// ──────────────────────────────────────────────

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_consents)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Consent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_consents)]
pub struct NewConsent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// oauth2-server: yauth_device_codes
// ──────────────────────────────────────────────

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_device_codes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DeviceCode {
    pub id: Uuid,
    pub device_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub user_id: Option<Uuid>,
    pub status: String,
    pub interval: i32,
    pub expires_at: NaiveDateTime,
    pub last_polled_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_device_codes)]
pub struct NewDeviceCode {
    pub id: Uuid,
    pub device_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub user_id: Option<Uuid>,
    pub status: String,
    pub interval: i32,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// account-lockout: yauth_account_locks
// ──────────────────────────────────────────────

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_account_locks)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AccountLock {
    pub id: Uuid,
    pub user_id: Uuid,
    pub failed_count: i32,
    pub locked_until: Option<NaiveDateTime>,
    pub lock_count: i32,
    pub locked_reason: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_account_locks)]
pub struct NewAccountLock {
    pub id: Uuid,
    pub user_id: Uuid,
    pub failed_count: i32,
    pub locked_until: Option<NaiveDateTime>,
    pub lock_count: i32,
    pub locked_reason: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// account-lockout: yauth_unlock_tokens
// ──────────────────────────────────────────────

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_unlock_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UnlockToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_unlock_tokens)]
pub struct NewUnlockToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

// ──────────────────────────────────────────────
// webhooks: yauth_webhooks
// ──────────────────────────────────────────────

#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhooks)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Webhook {
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    pub events: serde_json::Value,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhooks)]
pub struct NewWebhook {
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    pub events: serde_json::Value,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhooks)]
pub struct UpdateWebhook {
    pub url: Option<String>,
    pub secret: Option<String>,
    pub events: Option<serde_json::Value>,
    pub active: Option<bool>,
    pub updated_at: Option<NaiveDateTime>,
}

// ──────────────────────────────────────────────
// webhooks: yauth_webhook_deliveries
// ──────────────────────────────────────────────

#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhook_deliveries)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status_code: Option<i16>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhook_deliveries)]
pub struct NewWebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status_code: Option<i16>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: NaiveDateTime,
}

