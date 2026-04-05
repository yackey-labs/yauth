//! Diesel-annotated models for the libSQL backend.
//!
//! All UUID and DateTime fields are stored as TEXT in SQLite and represented
//! as String in these models. Conversion to/from domain types handles the
//! String <-> Uuid/NaiveDateTime parsing.

use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use super::schema::*;

// ── Helper functions ──

// Re-export shared UUID/JSON converters from diesel_common.
pub(crate) use crate::backends::diesel_common::{
    json_to_str, opt_json_to_str, opt_str_to_json, opt_str_to_uuid, opt_uuid_to_str, str_to_json,
    str_to_uuid, uuid_to_str,
};

pub(crate) fn dt_to_str(dt: NaiveDateTime) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.f").to_string()
}

pub(crate) fn str_to_dt(s: &str) -> NaiveDateTime {
    // Try multiple formats for flexibility
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
        .unwrap_or_else(|e| {
            log::error!(
                "Failed to parse NaiveDateTime from stored value '{}': {}",
                s,
                e
            );
            NaiveDateTime::default()
        })
}

pub(crate) fn opt_dt_to_str(dt: Option<NaiveDateTime>) -> Option<String> {
    dt.map(dt_to_str)
}

pub(crate) fn opt_str_to_dt(s: Option<String>) -> Option<NaiveDateTime> {
    s.map(|s| str_to_dt(&s))
}

// ──────────────────────────────────────────────
// Core: yauth_users
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LibsqlUser {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl LibsqlUser {
    pub(crate) fn into_domain(self) -> crate::domain::User {
        crate::domain::User {
            id: str_to_uuid(&self.id),
            email: self.email,
            display_name: self.display_name,
            email_verified: self.email_verified,
            role: self.role,
            banned: self.banned,
            banned_reason: self.banned_reason,
            banned_until: opt_str_to_dt(self.banned_until),
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
pub(crate) struct LibsqlNewUser {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl LibsqlNewUser {
    pub(crate) fn from_domain(input: crate::domain::NewUser) -> Self {
        Self {
            id: uuid_to_str(input.id),
            email: input.email,
            display_name: input.display_name,
            email_verified: input.email_verified,
            role: input.role,
            banned: input.banned,
            banned_reason: input.banned_reason,
            banned_until: opt_dt_to_str(input.banned_until),
            created_at: dt_to_str(input.created_at),
            updated_at: dt_to_str(input.updated_at),
        }
    }
}

#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = yauth_users)]
pub(crate) struct LibsqlUpdateUser {
    pub email: Option<String>,
    pub display_name: Option<Option<String>>,
    pub email_verified: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub banned_reason: Option<Option<String>>,
    pub banned_until: Option<Option<String>>,
    pub updated_at: Option<String>,
}

impl LibsqlUpdateUser {
    pub(crate) fn from_domain(input: crate::domain::UpdateUser) -> Self {
        Self {
            email: input.email,
            display_name: input.display_name,
            email_verified: input.email_verified,
            role: input.role,
            banned: input.banned,
            banned_reason: input.banned_reason,
            banned_until: input.banned_until.map(|opt| opt.map(dt_to_str)),
            updated_at: input.updated_at.map(dt_to_str),
        }
    }
}

/// `QueryableByName` variant of `LibsqlUser` for use with `diesel::sql_query()` RETURNING.
#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct LibsqlUserByName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub email: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub display_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub email_verified: bool,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub role: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub banned: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub banned_reason: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub banned_until: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub created_at: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub updated_at: String,
}

impl LibsqlUserByName {
    pub(crate) fn into_domain(self) -> crate::domain::User {
        crate::domain::User {
            id: str_to_uuid(&self.id),
            email: self.email,
            display_name: self.display_name,
            email_verified: self.email_verified,
            role: self.role,
            banned: self.banned,
            banned_reason: self.banned_reason,
            banned_until: opt_str_to_dt(self.banned_until),
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}

// ──────────────────────────────────────────────
// Core: yauth_sessions
// ──────────────────────────────────────────────

#[derive(Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_sessions)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LibsqlSession {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}

impl LibsqlSession {
    pub(crate) fn into_domain(self) -> crate::domain::Session {
        crate::domain::Session {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            expires_at: str_to_dt(&self.expires_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

#[derive(Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_sessions)]
pub(crate) struct LibsqlNewSession {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}

impl LibsqlNewSession {
    pub(crate) fn from_domain(input: crate::domain::NewSession) -> Self {
        Self {
            id: uuid_to_str(input.id),
            user_id: uuid_to_str(input.user_id),
            token_hash: input.token_hash,
            ip_address: input.ip_address,
            user_agent: input.user_agent,
            expires_at: dt_to_str(input.expires_at),
            created_at: dt_to_str(input.created_at),
        }
    }
}

// ──────────────────────────────────────────────
// Core: yauth_audit_log
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_audit_log)]
pub(crate) struct LibsqlNewAuditLog {
    pub id: String,
    pub user_id: Option<String>,
    pub event_type: String,
    pub metadata: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
}

impl LibsqlNewAuditLog {
    pub(crate) fn from_domain(input: crate::domain::NewAuditLog) -> Self {
        Self {
            id: uuid_to_str(input.id),
            user_id: opt_uuid_to_str(input.user_id),
            event_type: input.event_type,
            metadata: opt_json_to_str(input.metadata),
            ip_address: input.ip_address,
            created_at: dt_to_str(input.created_at),
        }
    }
}

// ──────────────────────────────────────────────
// email-password: yauth_passwords
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_passwords)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LibsqlPassword {
    pub user_id: String,
    pub password_hash: String,
}

#[cfg(feature = "email-password")]
impl LibsqlPassword {
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
pub(crate) struct LibsqlNewPassword {
    pub user_id: String,
    pub password_hash: String,
}

#[cfg(feature = "email-password")]
impl LibsqlNewPassword {
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
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LibsqlEmailVerification {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}

#[cfg(feature = "email-password")]
impl LibsqlEmailVerification {
    pub(crate) fn into_domain(self) -> crate::domain::EmailVerification {
        crate::domain::EmailVerification {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            expires_at: str_to_dt(&self.expires_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_email_verifications)]
pub(crate) struct LibsqlNewEmailVerification {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}

#[cfg(feature = "email-password")]
impl LibsqlNewEmailVerification {
    pub(crate) fn from_domain(input: crate::domain::NewEmailVerification) -> Self {
        Self {
            id: uuid_to_str(input.id),
            user_id: uuid_to_str(input.user_id),
            token_hash: input.token_hash,
            expires_at: dt_to_str(input.expires_at),
            created_at: dt_to_str(input.created_at),
        }
    }
}

// ──────────────────────────────────────────────
// email-password: yauth_password_resets
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = yauth_password_resets)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LibsqlPasswordReset {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub created_at: String,
}

#[cfg(feature = "email-password")]
impl LibsqlPasswordReset {
    pub(crate) fn into_domain(self) -> crate::domain::PasswordReset {
        crate::domain::PasswordReset {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            expires_at: str_to_dt(&self.expires_at),
            used_at: opt_str_to_dt(self.used_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = yauth_password_resets)]
pub(crate) struct LibsqlNewPasswordReset {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}

#[cfg(feature = "email-password")]
impl LibsqlNewPasswordReset {
    pub(crate) fn from_domain(input: crate::domain::NewPasswordReset) -> Self {
        Self {
            id: uuid_to_str(input.id),
            user_id: uuid_to_str(input.user_id),
            token_hash: input.token_hash,
            expires_at: dt_to_str(input.expires_at),
            created_at: dt_to_str(input.created_at),
        }
    }
}
