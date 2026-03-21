use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::crypto;
use crate::config::BindingAction;
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

    diesel::sql_query(
        "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind::<diesel::sql_types::Uuid, _>(session_id)
    .bind::<diesel::sql_types::Uuid, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(&token_hash)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ip_address)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&user_agent)
    .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(&mut conn)
    .await?;

    Ok((token, session_id))
}

#[derive(diesel::QueryableByName)]
struct SessionRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    ip_address: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    user_agent: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    expires_at: chrono::NaiveDateTime,
}

pub async fn validate_session(
    state: &YAuthState,
    token: &str,
    request_ip: Option<&str>,
    request_ua: Option<&str>,
) -> Result<Option<SessionUser>, SessionError> {
    use diesel::result::OptionalExtension;
    use diesel_async_crate::RunQueryDsl;

    let token_hash = crypto::hash_token(token);
    let mut conn = state.db.get().await?;

    let session: Option<SessionRow> = diesel::sql_query(
        "SELECT id, user_id, ip_address, user_agent, expires_at FROM yauth_sessions WHERE token_hash = $1",
    )
    .bind::<diesel::sql_types::Text, _>(&token_hash)
    .get_result(&mut conn)
    .await
    .optional()?;

    let span = tracing::Span::current();
    span.record("yauth.session_found", session.is_some());

    match session {
        Some(s) => {
            let now = Utc::now().naive_utc();
            if s.expires_at < now {
                diesel::sql_query("DELETE FROM yauth_sessions WHERE id = $1")
                    .bind::<diesel::sql_types::Uuid, _>(s.id)
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
                    diesel::sql_query("DELETE FROM yauth_sessions WHERE id = $1")
                        .bind::<diesel::sql_types::Uuid, _>(s.id)
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
                    diesel::sql_query("DELETE FROM yauth_sessions WHERE id = $1")
                        .bind::<diesel::sql_types::Uuid, _>(s.id)
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
    use diesel_async_crate::RunQueryDsl;

    let token_hash = crypto::hash_token(token);
    let mut conn = db.get().await?;
    let rows = diesel::sql_query("DELETE FROM yauth_sessions WHERE token_hash = $1")
        .bind::<diesel::sql_types::Text, _>(&token_hash)
        .execute(&mut conn)
        .await?;
    Ok(rows > 0)
}

pub async fn delete_all_user_sessions(db: &DbPool, user_id: Uuid) -> Result<u64, SessionError> {
    use diesel_async_crate::RunQueryDsl;

    let mut conn = db.get().await?;
    let rows = diesel::sql_query("DELETE FROM yauth_sessions WHERE user_id = $1")
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .execute(&mut conn)
        .await?;
    Ok(rows as u64)
}

pub async fn delete_other_user_sessions(
    db: &DbPool,
    user_id: Uuid,
    keep_token_hash: &str,
) -> Result<u64, SessionError> {
    use diesel_async_crate::RunQueryDsl;

    let mut conn = db.get().await?;
    let rows =
        diesel::sql_query("DELETE FROM yauth_sessions WHERE user_id = $1 AND token_hash != $2")
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(keep_token_hash)
            .execute(&mut conn)
            .await?;
    Ok(rows as u64)
}
