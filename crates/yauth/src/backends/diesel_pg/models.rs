//! Diesel-annotated models — private to the Diesel backend.
//!
//! Each model has `into_domain()` and/or `from_domain()` methods for
//! converting to/from the ORM-agnostic domain types in `crate::domain`.

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
pub(crate) struct DieselUser {
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

impl DieselUser {
    pub(crate) fn into_domain(self) -> crate::domain::User {
        crate::domain::User {
            id: self.id,
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
pub(crate) struct DieselNewUser {
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

impl DieselNewUser {
    pub(crate) fn from_domain(input: crate::domain::NewUser) -> Self {
        Self {
            id: input.id,
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
pub(crate) struct DieselUpdateUser {
    pub email: Option<String>,
    pub display_name: Option<Option<String>>,
    pub email_verified: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub banned_reason: Option<Option<String>>,
    pub banned_until: Option<Option<NaiveDateTime>>,
    pub updated_at: Option<NaiveDateTime>,
}

impl DieselUpdateUser {
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
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

impl DieselSession {
    pub(crate) fn into_domain(self) -> crate::domain::Session {
        crate::domain::Session {
            id: self.id,
            user_id: self.user_id,
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
pub(crate) struct DieselNewSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

impl DieselNewSession {
    pub(crate) fn from_domain(input: crate::domain::NewSession) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
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
pub(crate) struct DieselNewAuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub metadata: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub created_at: NaiveDateTime,
}

impl DieselNewAuditLog {
    pub(crate) fn from_domain(input: crate::domain::NewAuditLog) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            event_type: input.event_type,
            metadata: input.metadata,
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
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselPassword {
    pub user_id: Uuid,
    pub password_hash: String,
}

#[cfg(feature = "email-password")]
impl DieselPassword {
    pub(crate) fn into_domain(self) -> crate::domain::Password {
        crate::domain::Password {
            user_id: self.user_id,
            password_hash: self.password_hash,
        }
    }
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_passwords)]
pub(crate) struct DieselNewPassword {
    pub user_id: Uuid,
    pub password_hash: String,
}

#[cfg(feature = "email-password")]
impl DieselNewPassword {
    pub(crate) fn from_domain(input: crate::domain::NewPassword) -> Self {
        Self {
            user_id: input.user_id,
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
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselEmailVerification {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
impl DieselEmailVerification {
    pub(crate) fn into_domain(self) -> crate::domain::EmailVerification {
        crate::domain::EmailVerification {
            id: self.id,
            user_id: self.user_id,
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_email_verifications)]
pub(crate) struct DieselNewEmailVerification {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
impl DieselNewEmailVerification {
    pub(crate) fn from_domain(input: crate::domain::NewEmailVerification) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
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
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselPasswordReset {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub used_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
impl DieselPasswordReset {
    pub(crate) fn into_domain(self) -> crate::domain::PasswordReset {
        crate::domain::PasswordReset {
            id: self.id,
            user_id: self.user_id,
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
pub(crate) struct DieselNewPasswordReset {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "email-password")]
impl DieselNewPasswordReset {
    pub(crate) fn from_domain(input: crate::domain::NewPasswordReset) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
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
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselWebauthnCredential {
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
impl DieselWebauthnCredential {
    pub(crate) fn into_domain(self) -> crate::domain::WebauthnCredential {
        crate::domain::WebauthnCredential {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            aaguid: self.aaguid,
            device_name: self.device_name,
            credential: self.credential,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        }
    }
}

#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webauthn_credentials)]
pub(crate) struct DieselNewWebauthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,
    pub credential: serde_json::Value,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "passkey")]
impl DieselNewWebauthnCredential {
    pub(crate) fn from_domain(input: crate::domain::NewWebauthnCredential) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            name: input.name,
            aaguid: input.aaguid,
            device_name: input.device_name,
            credential: input.credential,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// mfa: yauth_totp_secrets
// ──────────────────────────────────────────────

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_totp_secrets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselTotpSecret {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "mfa")]
impl DieselTotpSecret {
    pub(crate) fn into_domain(self) -> crate::domain::TotpSecret {
        crate::domain::TotpSecret {
            id: self.id,
            user_id: self.user_id,
            encrypted_secret: self.encrypted_secret,
            verified: self.verified,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_totp_secrets)]
pub(crate) struct DieselNewTotpSecret {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "mfa")]
impl DieselNewTotpSecret {
    pub(crate) fn from_domain(input: crate::domain::NewTotpSecret) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            encrypted_secret: input.encrypted_secret,
            verified: input.verified,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// mfa: yauth_backup_codes
// ──────────────────────────────────────────────

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_backup_codes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselBackupCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "mfa")]
impl DieselBackupCode {
    pub(crate) fn into_domain(self) -> crate::domain::BackupCode {
        crate::domain::BackupCode {
            id: self.id,
            user_id: self.user_id,
            code_hash: self.code_hash,
            used: self.used,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_backup_codes)]
pub(crate) struct DieselNewBackupCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "mfa")]
impl DieselNewBackupCode {
    pub(crate) fn from_domain(input: crate::domain::NewBackupCode) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            code_hash: input.code_hash,
            used: input.used,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// oauth: yauth_oauth_accounts
// ──────────────────────────────────────────────

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselOauthAccount {
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
impl DieselOauthAccount {
    pub(crate) fn into_domain(self) -> crate::domain::OauthAccount {
        crate::domain::OauthAccount {
            id: self.id,
            user_id: self.user_id,
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
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_accounts)]
pub(crate) struct DieselNewOauthAccount {
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
impl DieselNewOauthAccount {
    pub(crate) fn from_domain(input: crate::domain::NewOauthAccount) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            provider: input.provider,
            provider_user_id: input.provider_user_id,
            access_token_enc: input.access_token_enc,
            refresh_token_enc: input.refresh_token_enc,
            created_at: input.created_at,
            expires_at: input.expires_at,
            updated_at: input.updated_at,
        }
    }
}

// ──────────────────────────────────────────────
// oauth: yauth_oauth_states
// ──────────────────────────────────────────────

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_states)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselOauthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth")]
impl DieselOauthState {
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

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth_states)]
pub(crate) struct DieselNewOauthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth")]
impl DieselNewOauthState {
    pub(crate) fn from_domain(input: crate::domain::NewOauthState) -> Self {
        Self {
            state: input.state,
            provider: input.provider,
            redirect_url: input.redirect_url,
            expires_at: input.expires_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// api-key: yauth_api_keys
// ──────────────────────────────────────────────

#[cfg(feature = "api-key")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_api_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselApiKey {
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
impl DieselApiKey {
    pub(crate) fn into_domain(self) -> crate::domain::ApiKey {
        crate::domain::ApiKey {
            id: self.id,
            user_id: self.user_id,
            key_prefix: self.key_prefix,
            key_hash: self.key_hash,
            name: self.name,
            scopes: self.scopes,
            last_used_at: self.last_used_at,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "api-key")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_api_keys)]
pub(crate) struct DieselNewApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Option<serde_json::Value>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "api-key")]
impl DieselNewApiKey {
    pub(crate) fn from_domain(input: crate::domain::NewApiKey) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            key_prefix: input.key_prefix,
            key_hash: input.key_hash,
            name: input.name,
            scopes: input.scopes,
            expires_at: input.expires_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// bearer: yauth_refresh_tokens
// ──────────────────────────────────────────────

#[cfg(feature = "bearer")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_refresh_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub family_id: Uuid,
    pub expires_at: NaiveDateTime,
    pub revoked: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "bearer")]
impl DieselRefreshToken {
    pub(crate) fn into_domain(self) -> crate::domain::RefreshToken {
        crate::domain::RefreshToken {
            id: self.id,
            user_id: self.user_id,
            token_hash: self.token_hash,
            family_id: self.family_id,
            expires_at: self.expires_at,
            revoked: self.revoked,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "bearer")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_refresh_tokens)]
pub(crate) struct DieselNewRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub family_id: Uuid,
    pub expires_at: NaiveDateTime,
    pub revoked: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "bearer")]
impl DieselNewRefreshToken {
    pub(crate) fn from_domain(input: crate::domain::NewRefreshToken) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            token_hash: input.token_hash,
            family_id: input.family_id,
            expires_at: input.expires_at,
            revoked: input.revoked,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// magic-link: yauth_magic_links
// ──────────────────────────────────────────────

#[cfg(feature = "magic-link")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_magic_links)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselMagicLink {
    pub id: Uuid,
    pub email: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "magic-link")]
impl DieselMagicLink {
    pub(crate) fn into_domain(self) -> crate::domain::MagicLink {
        crate::domain::MagicLink {
            id: self.id,
            email: self.email,
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            used: self.used,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "magic-link")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_magic_links)]
pub(crate) struct DieselNewMagicLink {
    pub id: Uuid,
    pub email: String,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "magic-link")]
impl DieselNewMagicLink {
    pub(crate) fn from_domain(input: crate::domain::NewMagicLink) -> Self {
        Self {
            id: input.id,
            email: input.email,
            token_hash: input.token_hash,
            expires_at: input.expires_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// oauth2-server models
// ──────────────────────────────────────────────

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth2_clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselOauth2Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: serde_json::Value,
    pub client_name: Option<String>,
    pub grant_types: serde_json::Value,
    pub scopes: Option<serde_json::Value>,
    pub is_public: bool,
    pub created_at: NaiveDateTime,
    pub token_endpoint_auth_method: Option<String>,
    pub public_key_pem: Option<String>,
    pub jwks_uri: Option<String>,
    pub banned_at: Option<NaiveDateTime>,
    pub banned_reason: Option<String>,
}

#[cfg(feature = "oauth2-server")]
impl DieselOauth2Client {
    pub(crate) fn into_domain(self) -> crate::domain::Oauth2Client {
        crate::domain::Oauth2Client {
            id: self.id,
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            redirect_uris: self.redirect_uris,
            client_name: self.client_name,
            grant_types: self.grant_types,
            scopes: self.scopes,
            is_public: self.is_public,
            created_at: self.created_at,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            public_key_pem: self.public_key_pem,
            jwks_uri: self.jwks_uri,
            banned_at: self.banned_at,
            banned_reason: self.banned_reason,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_oauth2_clients)]
pub(crate) struct DieselNewOauth2Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: serde_json::Value,
    pub client_name: Option<String>,
    pub grant_types: serde_json::Value,
    pub scopes: Option<serde_json::Value>,
    pub is_public: bool,
    pub created_at: NaiveDateTime,
    pub token_endpoint_auth_method: Option<String>,
    pub public_key_pem: Option<String>,
    pub jwks_uri: Option<String>,
}

#[cfg(feature = "oauth2-server")]
impl DieselNewOauth2Client {
    pub(crate) fn from_domain(input: crate::domain::NewOauth2Client) -> Self {
        Self {
            id: input.id,
            client_id: input.client_id,
            client_secret_hash: input.client_secret_hash,
            redirect_uris: input.redirect_uris,
            client_name: input.client_name,
            grant_types: input.grant_types,
            scopes: input.scopes,
            is_public: input.is_public,
            created_at: input.created_at,
            token_endpoint_auth_method: input.token_endpoint_auth_method,
            public_key_pem: input.public_key_pem,
            jwks_uri: input.jwks_uri,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_authorization_codes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselAuthorizationCode {
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
impl DieselAuthorizationCode {
    pub(crate) fn into_domain(self) -> crate::domain::AuthorizationCode {
        crate::domain::AuthorizationCode {
            id: self.id,
            code_hash: self.code_hash,
            client_id: self.client_id,
            user_id: self.user_id,
            scopes: self.scopes,
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
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_authorization_codes)]
pub(crate) struct DieselNewAuthorizationCode {
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
impl DieselNewAuthorizationCode {
    pub(crate) fn from_domain(input: crate::domain::NewAuthorizationCode) -> Self {
        Self {
            id: input.id,
            code_hash: input.code_hash,
            client_id: input.client_id,
            user_id: input.user_id,
            scopes: input.scopes,
            redirect_uri: input.redirect_uri,
            code_challenge: input.code_challenge,
            code_challenge_method: input.code_challenge_method,
            expires_at: input.expires_at,
            used: input.used,
            nonce: input.nonce,
            created_at: input.created_at,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_consents)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselConsent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
impl DieselConsent {
    pub(crate) fn into_domain(self) -> crate::domain::Consent {
        crate::domain::Consent {
            id: self.id,
            user_id: self.user_id,
            client_id: self.client_id,
            scopes: self.scopes,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_consents)]
pub(crate) struct DieselNewConsent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "oauth2-server")]
impl DieselNewConsent {
    pub(crate) fn from_domain(input: crate::domain::NewConsent) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            client_id: input.client_id,
            scopes: input.scopes,
            created_at: input.created_at,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_device_codes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselDeviceCode {
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
impl DieselDeviceCode {
    pub(crate) fn into_domain(self) -> crate::domain::DeviceCode {
        crate::domain::DeviceCode {
            id: self.id,
            device_code_hash: self.device_code_hash,
            user_code: self.user_code,
            client_id: self.client_id,
            scopes: self.scopes,
            user_id: self.user_id,
            status: self.status,
            interval: self.interval,
            expires_at: self.expires_at,
            last_polled_at: self.last_polled_at,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_device_codes)]
pub(crate) struct DieselNewDeviceCode {
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

#[cfg(feature = "oauth2-server")]
impl DieselNewDeviceCode {
    pub(crate) fn from_domain(input: crate::domain::NewDeviceCode) -> Self {
        Self {
            id: input.id,
            device_code_hash: input.device_code_hash,
            user_code: input.user_code,
            client_id: input.client_id,
            scopes: input.scopes,
            user_id: input.user_id,
            status: input.status,
            interval: input.interval,
            expires_at: input.expires_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// account-lockout models
// ──────────────────────────────────────────────

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_account_locks)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselAccountLock {
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
impl DieselAccountLock {
    pub(crate) fn into_domain(self) -> crate::domain::AccountLock {
        crate::domain::AccountLock {
            id: self.id,
            user_id: self.user_id,
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
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_account_locks)]
pub(crate) struct DieselNewAccountLock {
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
impl DieselNewAccountLock {
    pub(crate) fn from_domain(input: crate::domain::NewAccountLock) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            failed_count: input.failed_count,
            locked_until: input.locked_until,
            lock_count: input.lock_count,
            locked_reason: input.locked_reason,
            created_at: input.created_at,
            updated_at: input.updated_at,
        }
    }
}

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_unlock_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselUnlockToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "account-lockout")]
impl DieselUnlockToken {
    pub(crate) fn into_domain(self) -> crate::domain::UnlockToken {
        crate::domain::UnlockToken {
            id: self.id,
            user_id: self.user_id,
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_unlock_tokens)]
pub(crate) struct DieselNewUnlockToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[cfg(feature = "account-lockout")]
impl DieselNewUnlockToken {
    pub(crate) fn from_domain(input: crate::domain::NewUnlockToken) -> Self {
        Self {
            id: input.id,
            user_id: input.user_id,
            token_hash: input.token_hash,
            expires_at: input.expires_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// webhooks models
// ──────────────────────────────────────────────

#[cfg(feature = "webhooks")]
#[derive(Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhooks)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselWebhook {
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    pub events: serde_json::Value,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "webhooks")]
impl DieselWebhook {
    pub(crate) fn into_domain(self) -> crate::domain::Webhook {
        crate::domain::Webhook {
            id: self.id,
            url: self.url,
            secret: self.secret,
            events: self.events,
            active: self.active,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(feature = "webhooks")]
#[derive(Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhooks)]
pub(crate) struct DieselNewWebhook {
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    pub events: serde_json::Value,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[cfg(feature = "webhooks")]
impl DieselNewWebhook {
    pub(crate) fn from_domain(input: crate::domain::NewWebhook) -> Self {
        Self {
            id: input.id,
            url: input.url,
            secret: input.secret,
            events: input.events,
            active: input.active,
            created_at: input.created_at,
            updated_at: input.updated_at,
        }
    }
}

#[cfg(feature = "webhooks")]
#[derive(Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhooks)]
pub(crate) struct DieselUpdateWebhook {
    pub url: Option<String>,
    pub secret: Option<String>,
    pub events: Option<serde_json::Value>,
    pub active: Option<bool>,
    pub updated_at: Option<NaiveDateTime>,
}

#[cfg(feature = "webhooks")]
impl DieselUpdateWebhook {
    pub(crate) fn from_domain(input: crate::domain::UpdateWebhook) -> Self {
        Self {
            url: input.url,
            secret: input.secret,
            events: input.events,
            active: input.active,
            updated_at: input.updated_at,
        }
    }
}

#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhook_deliveries)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct DieselWebhookDelivery {
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
impl DieselWebhookDelivery {
    pub(crate) fn into_domain(self) -> crate::domain::WebhookDelivery {
        crate::domain::WebhookDelivery {
            id: self.id,
            webhook_id: self.webhook_id,
            event_type: self.event_type,
            payload: self.payload,
            status_code: self.status_code,
            response_body: self.response_body,
            success: self.success,
            attempt: self.attempt,
            created_at: self.created_at,
        }
    }
}

#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_webhook_deliveries)]
pub(crate) struct DieselNewWebhookDelivery {
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
impl DieselNewWebhookDelivery {
    pub(crate) fn from_domain(input: crate::domain::NewWebhookDelivery) -> Self {
        Self {
            id: input.id,
            webhook_id: input.webhook_id,
            event_type: input.event_type,
            payload: input.payload,
            status_code: input.status_code,
            response_body: input.response_body,
            success: input.success,
            attempt: input.attempt,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// Store models (challenge) — used by challenge_repo.rs
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[allow(dead_code)]
pub(crate) struct DieselChallenge {
    pub key: String,
    pub value: serde_json::Value,
    pub expires_at: NaiveDateTime,
}
