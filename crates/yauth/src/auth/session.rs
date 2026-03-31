use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::crypto;
use crate::config::BindingAction;
use crate::db::models::{NewSession, Session};
use crate::db::schema::yauth_sessions;
use crate::state::{DbPool, YAuthState};

pub fn session_set_cookie(state: &YAuthState, token: &str, ttl: std::time::Duration) -> String {
    let max_age = ttl.as_secs();
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        state.config.session_cookie_name, token, max_age
    );
    if state.config.secure_cookies {
        cookie.push_str("; Secure");
    }
    if let Some(domain) = state.config.cookie_domain.domain() {
        // Validate domain to prevent cookie attribute injection via semicolons,
        // newlines, or other control characters in the domain value.
        let is_safe = !domain.contains(';')
            && !domain.contains('\n')
            && !domain.contains('\r')
            && !domain.contains(' ');
        if is_safe {
            cookie.push_str(&format!("; Domain={}", domain));
        }
    }
    cookie
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

#[derive(Debug)]
pub struct SessionError(pub String);

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SessionError {}

impl From<diesel::result::Error> for SessionError {
    fn from(e: diesel::result::Error) -> Self {
        SessionError(e.to_string())
    }
}

impl From<diesel_async_crate::pooled_connection::deadpool::PoolError> for SessionError {
    fn from(e: diesel_async_crate::pooled_connection::deadpool::PoolError) -> Self {
        SessionError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Diesel-async implementations
// ---------------------------------------------------------------------------

pub async fn create_session(
    db: &DbPool,
    user_id: Uuid,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ttl: std::time::Duration,
) -> Result<(String, Uuid), SessionError> {
    use diesel_async_crate::RunQueryDsl;

    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let session_id = Uuid::new_v4();

    let now = Utc::now();
    let expires_at = now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7));

    let mut conn = db.get().await?;

    let new_session = NewSession {
        id: session_id,
        user_id,
        token_hash,
        ip_address,
        user_agent,
        expires_at: expires_at.naive_utc(),
        created_at: now.naive_utc(),
    };

    diesel::insert_into(yauth_sessions::table)
        .values(&new_session)
        .execute(&mut conn)
        .await?;

    Ok((token, session_id))
}

pub async fn validate_session(
    state: &YAuthState,
    token: &str,
    request_ip: Option<&str>,
    request_ua: Option<&str>,
) -> Result<Option<SessionUser>, SessionError> {
    use diesel::prelude::*;
    use diesel::result::OptionalExtension;
    use diesel_async_crate::RunQueryDsl;

    let token_hash = crypto::hash_token(token);
    let mut conn = state.db.get().await?;

    let session: Option<Session> = yauth_sessions::table
        .filter(yauth_sessions::token_hash.eq(&token_hash))
        .select(Session::as_select())
        .get_result(&mut conn)
        .await
        .optional()?;

    let span = tracing::Span::current();
    span.record("yauth.session_found", session.is_some());

    match session {
        Some(s) => {
            let now = Utc::now().naive_utc();
            if s.expires_at < now {
                diesel::delete(yauth_sessions::table.filter(yauth_sessions::id.eq(s.id)))
                    .execute(&mut conn)
                    .await?;
                return Ok(None);
            }

            let binding = &state.config.session_binding;

            if binding.bind_ip
                && let (Some(session_ip), Some(req_ip)) = (&s.ip_address, request_ip)
                && session_ip != req_ip
            {
                tracing::warn!(
                    event = "yauth.session.ip_mismatch",
                    session_id = %s.id,
                    session_ip = %session_ip,
                    request_ip = %req_ip,
                    "Session IP mismatch"
                );
                if binding.ip_mismatch_action == BindingAction::Invalidate {
                    diesel::delete(yauth_sessions::table.filter(yauth_sessions::id.eq(s.id)))
                        .execute(&mut conn)
                        .await?;
                    return Ok(None);
                }
            }

            if binding.bind_user_agent
                && let (Some(session_ua), Some(req_ua)) = (&s.user_agent, request_ua)
                && session_ua != req_ua
            {
                tracing::warn!(
                    event = "yauth.session.ua_mismatch",
                    session_id = %s.id,
                    "Session User-Agent mismatch"
                );
                if binding.ua_mismatch_action == BindingAction::Invalidate {
                    diesel::delete(yauth_sessions::table.filter(yauth_sessions::id.eq(s.id)))
                        .execute(&mut conn)
                        .await?;
                    return Ok(None);
                }
            }

            Ok(Some(SessionUser {
                user_id: s.user_id,
                session_id: s.id,
            }))
        }
        None => Ok(None),
    }
}

pub async fn delete_session(db: &DbPool, token: &str) -> Result<bool, SessionError> {
    use diesel::prelude::*;
    use diesel_async_crate::RunQueryDsl;

    let token_hash = crypto::hash_token(token);
    let mut conn = db.get().await?;
    let rows =
        diesel::delete(yauth_sessions::table.filter(yauth_sessions::token_hash.eq(&token_hash)))
            .execute(&mut conn)
            .await?;
    Ok(rows > 0)
}

pub async fn delete_all_user_sessions(db: &DbPool, user_id: Uuid) -> Result<u64, SessionError> {
    use diesel::prelude::*;
    use diesel_async_crate::RunQueryDsl;

    let mut conn = db.get().await?;
    let rows = diesel::delete(yauth_sessions::table.filter(yauth_sessions::user_id.eq(user_id)))
        .execute(&mut conn)
        .await?;
    Ok(rows as u64)
}

pub async fn delete_other_user_sessions(
    db: &DbPool,
    user_id: Uuid,
    keep_token_hash: &str,
) -> Result<u64, SessionError> {
    use diesel::prelude::*;
    use diesel_async_crate::RunQueryDsl;

    let mut conn = db.get().await?;
    let rows = diesel::delete(
        yauth_sessions::table
            .filter(yauth_sessions::user_id.eq(user_id))
            .filter(yauth_sessions::token_hash.ne(keep_token_hash)),
    )
    .execute(&mut conn)
    .await?;
    Ok(rows as u64)
}
