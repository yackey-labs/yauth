//! Diesel-annotated models for the MySQL backend.
//!
//! UUID fields are stored as CHAR(36) in MySQL and represented as String.
//! DateTime fields use native MySQL DATETIME and map directly to NaiveDateTime.
//! Boolean fields use TINYINT(1) and map to bool via Diesel's Bool type.

use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use super::schema::*;

// Re-export shared UUID/JSON converters from diesel_common.
pub(crate) use crate::backends::diesel_common::{
    json_to_str, opt_json_to_str, opt_uuid_to_str, str_to_json, str_to_uuid, uuid_to_str,
};

// ──────────────────────────────────────────────
// Core: yauth_users
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlUser {
    pub id: String,
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

impl MysqlUser {
    pub(crate) fn into_domain(self) -> crate::domain::User {
        crate::domain::User {
            id: str_to_uuid(&self.id),
            email: self.email,
            display_name: self.display_name,
            email_verified: self.email_verified,
            role: self.role,
            banned: self.banned,
            banned_reason: self.banned_reason,
            banned_until: self.banned_until,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
pub(crate) struct MysqlNewUser {
    pub id: String,
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

impl MysqlNewUser {
    pub(crate) fn from_domain(input: crate::domain::NewUser) -> Self {
        Self {
            id: uuid_to_str(input.id),
            email: input.email,
            display_name: input.display_name,
            email_verified: input.email_verified,
            role: input.role,
            banned: input.banned,
            banned_reason: input.banned_reason,
            banned_until: input.banned_until,
            created_at: input.created_at,
            updated_at: input.updated_at,
        }
    }
}

#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
pub(crate) struct MysqlUpdateUser {
    pub email: Option<String>,
    pub display_name: Option<Option<String>>,
    pub email_verified: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub banned_reason: Option<Option<String>>,
    pub banned_until: Option<Option<NaiveDateTime>>,
    pub updated_at: Option<NaiveDateTime>,
}

impl MysqlUpdateUser {
    pub(crate) fn from_domain(input: crate::domain::UpdateUser) -> Self {
        Self {
            email: input.email,
            display_name: input.display_name,
            email_verified: input.email_verified,
            role: input.role,
            banned: input.banned,
            banned_reason: input.banned_reason,
            banned_until: input.banned_until,
            updated_at: input.updated_at,
        }
    }
}

// ──────────────────────────────────────────────
// Core: yauth_sessions
// ──────────────────────────────────────────────

#[derive(Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_sessions)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlSession {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

impl MysqlSession {
    pub(crate) fn into_domain(self) -> crate::domain::Session {
        crate::domain::Session {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

#[derive(Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_sessions)]
pub(crate) struct MysqlNewSession {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

impl MysqlNewSession {
    pub(crate) fn from_domain(input: crate::domain::NewSession) -> Self {
        Self {
            id: uuid_to_str(input.id),
            user_id: uuid_to_str(input.user_id),
            token_hash: input.token_hash,
            ip_address: input.ip_address,
            user_agent: input.user_agent,
            expires_at: input.expires_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// Core: yauth_audit_log
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_audit_log)]
pub(crate) struct MysqlNewAuditLog {
    pub id: String,
    pub user_id: Option<String>,
    pub event_type: String,
    pub metadata: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: NaiveDateTime,
}

impl MysqlNewAuditLog {
    pub(crate) fn from_domain(input: crate::domain::NewAuditLog) -> Self {
        Self {
            id: uuid_to_str(input.id),
            user_id: opt_uuid_to_str(input.user_id),
            event_type: input.event_type,
            metadata: opt_json_to_str(input.metadata),
            ip_address: input.ip_address,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// email-password: yauth_passwords
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_passwords)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlPassword {
    pub user_id: String,
    pub password_hash: String,
}

#[cfg(feature = "email-password")]
impl MysqlPassword {
    pub(crate) fn into_domain(self) -> crate::domain::Password {
        crate::domain::Password {
            user_id: str_to_uuid(&self.user_id),
            password_hash: self.password_hash,
        }
    }
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_passwords)]
pub(crate) struct MysqlNewPassword {
    pub user_id: String,
    pub password_hash: String,
}

#[cfg(feature = "email-password")]
impl MysqlNewPassword {
    pub(crate) fn from_domain(input: crate::domain::NewPassword) -> Self {
        Self {
            user_id: uuid_to_str(input.user_id),
            password_hash: input.password_hash,
        }
    }
}

// ──────────────────────────────────────────────
// email-password: yauth_email_verifications
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_email_verifications)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlEmailVerification {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
impl MysqlEmailVerification {
    pub(crate) fn into_domain(self) -> crate::domain::EmailVerification {
        crate::domain::EmailVerification {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_email_verifications)]
pub(crate) struct MysqlNewEmailVerification {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
impl MysqlNewEmailVerification {
    pub(crate) fn from_domain(input: crate::domain::NewEmailVerification) -> Self {
        Self {
            id: uuid_to_str(input.id),
            user_id: uuid_to_str(input.user_id),
            token_hash: input.token_hash,
            expires_at: input.expires_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// email-password: yauth_password_resets
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_password_resets)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlPasswordReset {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub used_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
impl MysqlPasswordReset {
    pub(crate) fn into_domain(self) -> crate::domain::PasswordReset {
        crate::domain::PasswordReset {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            used_at: self.used_at,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_password_resets)]
pub(crate) struct MysqlNewPasswordReset {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
impl MysqlNewPasswordReset {
    pub(crate) fn from_domain(input: crate::domain::NewPasswordReset) -> Self {
        Self {
            id: uuid_to_str(input.id),
            user_id: uuid_to_str(input.user_id),
            token_hash: input.token_hash,
            expires_at: input.expires_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// passkey: yauth_webauthn_credentials
// ──────────────────────────────────────────────

#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webauthn_credentials)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlWebauthnCredential {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,
    pub credential: String,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}

#[cfg(feature = "passkey")]
impl MysqlWebauthnCredential {
    pub(crate) fn into_domain(self) -> crate::domain::WebauthnCredential {
        crate::domain::WebauthnCredential {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            name: self.name,
            aaguid: self.aaguid,
            device_name: self.device_name,
            credential: str_to_json(&self.credential),
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        }
    }
}

// ──────────────────────────────────────────────
// mfa: yauth_totp_secrets + yauth_backup_codes
// ──────────────────────────────────────────────

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_totp_secrets)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlTotpSecret {
    pub id: String,
    pub user_id: String,
    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "mfa")]
impl MysqlTotpSecret {
    pub(crate) fn into_domain(self) -> crate::domain::TotpSecret {
        crate::domain::TotpSecret {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            encrypted_secret: self.encrypted_secret,
            verified: self.verified,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_backup_codes)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlBackupCode {
    pub id: String,
    pub user_id: String,
    pub code_hash: String,
    pub used: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "mfa")]
impl MysqlBackupCode {
    pub(crate) fn into_domain(self) -> crate::domain::BackupCode {
        crate::domain::BackupCode {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            code_hash: self.code_hash,
            used: self.used,
            created_at: self.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// oauth: yauth_oauth_accounts + yauth_oauth_states
// ──────────────────────────────────────────────

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_accounts)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlOauthAccount {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "oauth")]
impl MysqlOauthAccount {
    pub(crate) fn into_domain(self) -> crate::domain::OauthAccount {
        crate::domain::OauthAccount {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            provider: self.provider,
            provider_user_id: self.provider_user_id,
            access_token_enc: self.access_token_enc,
            refresh_token_enc: self.refresh_token_enc,
            created_at: self.created_at,
            expires_at: self.expires_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_states)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlOauthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth")]
impl MysqlOauthState {
    pub(crate) fn into_domain(self) -> crate::domain::OauthState {
        crate::domain::OauthState {
            state: self.state,
            provider: self.provider,
            redirect_url: self.redirect_url,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// api-key: yauth_api_keys
// ──────────────────────────────────────────────

#[cfg(feature = "api-key")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_api_keys)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlApiKey {
    pub id: String,
    pub user_id: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Option<String>,
    pub last_used_at: Option<NaiveDateTime>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "api-key")]
impl MysqlApiKey {
    pub(crate) fn into_domain(self) -> crate::domain::ApiKey {
        crate::domain::ApiKey {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            key_prefix: self.key_prefix,
            key_hash: self.key_hash,
            name: self.name,
            scopes: self.scopes.map(|s| str_to_json(&s)),
            last_used_at: self.last_used_at,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// bearer: yauth_refresh_tokens
// ──────────────────────────────────────────────

#[cfg(feature = "bearer")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_refresh_tokens)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlRefreshToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub family_id: String,
    pub expires_at: NaiveDateTime,
    pub revoked: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "bearer")]
impl MysqlRefreshToken {
    pub(crate) fn into_domain(self) -> crate::domain::RefreshToken {
        crate::domain::RefreshToken {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            family_id: str_to_uuid(&self.family_id),
            expires_at: self.expires_at,
            revoked: self.revoked,
            created_at: self.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// magic-link: yauth_magic_links
// ──────────────────────────────────────────────

#[cfg(feature = "magic-link")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_magic_links)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlMagicLink {
    pub id: String,
    pub email: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "magic-link")]
impl MysqlMagicLink {
    pub(crate) fn into_domain(self) -> crate::domain::MagicLink {
        crate::domain::MagicLink {
            id: str_to_uuid(&self.id),
            email: self.email,
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            used: self.used,
            created_at: self.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// oauth2-server: yauth_oauth2_clients + related
// ──────────────────────────────────────────────

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth2_clients)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlOauth2Client {
    pub id: String,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: String,
    pub client_name: Option<String>,
    pub grant_types: String,
    pub scopes: Option<String>,
    pub is_public: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
impl MysqlOauth2Client {
    pub(crate) fn into_domain(self) -> crate::domain::Oauth2Client {
        crate::domain::Oauth2Client {
            id: str_to_uuid(&self.id),
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            redirect_uris: str_to_json(&self.redirect_uris),
            client_name: self.client_name,
            grant_types: str_to_json(&self.grant_types),
            scopes: self.scopes.map(|s| str_to_json(&s)),
            is_public: self.is_public,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_authorization_codes)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlAuthorizationCode {
    pub id: String,
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: Option<String>,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
    pub nonce: Option<String>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
impl MysqlAuthorizationCode {
    pub(crate) fn into_domain(self) -> crate::domain::AuthorizationCode {
        crate::domain::AuthorizationCode {
            id: str_to_uuid(&self.id),
            code_hash: self.code_hash,
            client_id: self.client_id,
            user_id: str_to_uuid(&self.user_id),
            scopes: self.scopes.map(|s| str_to_json(&s)),
            redirect_uri: self.redirect_uri,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            expires_at: self.expires_at,
            used: self.used,
            nonce: self.nonce,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_consents)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlConsent {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub scopes: Option<String>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
impl MysqlConsent {
    pub(crate) fn into_domain(self) -> crate::domain::Consent {
        crate::domain::Consent {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            client_id: self.client_id,
            scopes: self.scopes.map(|s| str_to_json(&s)),
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_device_codes)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlDeviceCode {
    pub id: String,
    pub device_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub scopes: Option<String>,
    pub user_id: Option<String>,
    pub status: String,
    pub interval: i32,
    pub expires_at: NaiveDateTime,
    pub last_polled_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
impl MysqlDeviceCode {
    pub(crate) fn into_domain(self) -> crate::domain::DeviceCode {
        crate::domain::DeviceCode {
            id: str_to_uuid(&self.id),
            device_code_hash: self.device_code_hash,
            user_code: self.user_code,
            client_id: self.client_id,
            scopes: self.scopes.map(|s| str_to_json(&s)),
            user_id: self.user_id.map(|s| str_to_uuid(&s)),
            status: self.status,
            interval: self.interval,
            expires_at: self.expires_at,
            last_polled_at: self.last_polled_at,
            created_at: self.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// account-lockout: yauth_account_locks + yauth_unlock_tokens
// ──────────────────────────────────────────────

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_account_locks)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlAccountLock {
    pub id: String,
    pub user_id: String,
    pub failed_count: i32,
    pub locked_until: Option<NaiveDateTime>,
    pub lock_count: i32,
    pub locked_reason: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "account-lockout")]
impl MysqlAccountLock {
    pub(crate) fn into_domain(self) -> crate::domain::AccountLock {
        crate::domain::AccountLock {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            failed_count: self.failed_count,
            locked_until: self.locked_until,
            lock_count: self.lock_count,
            locked_reason: self.locked_reason,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_unlock_tokens)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlUnlockToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "account-lockout")]
impl MysqlUnlockToken {
    pub(crate) fn into_domain(self) -> crate::domain::UnlockToken {
        crate::domain::UnlockToken {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// webhooks: yauth_webhooks + yauth_webhook_deliveries
// ──────────────────────────────────────────────

#[cfg(feature = "webhooks")]
#[derive(Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhooks)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlWebhook {
    pub id: String,
    pub url: String,
    pub secret: String,
    pub events: String,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "webhooks")]
impl MysqlWebhook {
    pub(crate) fn into_domain(self) -> crate::domain::Webhook {
        crate::domain::Webhook {
            id: str_to_uuid(&self.id),
            url: self.url,
            secret: self.secret,
            events: str_to_json(&self.events),
            active: self.active,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(feature = "webhooks")]
#[derive(Clone, AsChangeset)]
#[diesel(table_name = yauth_webhooks)]
pub(crate) struct MysqlUpdateWebhook {
    pub url: Option<String>,
    pub secret: Option<String>,
    pub events: Option<String>,
    pub active: Option<bool>,
    pub updated_at: Option<NaiveDateTime>,
}

#[cfg(feature = "webhooks")]
impl MysqlUpdateWebhook {
    pub(crate) fn from_domain(i: crate::domain::UpdateWebhook) -> Self {
        Self {
            url: i.url,
            secret: i.secret,
            events: i.events.map(json_to_str),
            active: i.active,
            updated_at: i.updated_at,
        }
    }
}

#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhook_deliveries)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub(crate) struct MysqlWebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub event_type: String,
    pub payload: String,
    pub status_code: Option<i16>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "webhooks")]
impl MysqlWebhookDelivery {
    pub(crate) fn into_domain(self) -> crate::domain::WebhookDelivery {
        crate::domain::WebhookDelivery {
            id: str_to_uuid(&self.id),
            webhook_id: str_to_uuid(&self.webhook_id),
            event_type: self.event_type,
            payload: str_to_json(&self.payload),
            status_code: self.status_code,
            response_body: self.response_body,
            success: self.success,
            attempt: self.attempt,
            created_at: self.created_at,
        }
    }
}
