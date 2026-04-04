use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::crypto;
use crate::config::BindingAction;
use crate::state::YAuthState;

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

impl From<String> for SessionError {
    fn from(e: String) -> Self {
        SessionError(e)
    }
}

impl From<crate::repo::RepoError> for SessionError {
    fn from(e: crate::repo::RepoError) -> Self {
        SessionError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Session operations — delegate storage to state.repos.session_ops
// ---------------------------------------------------------------------------

pub async fn create_session(
    state: &YAuthState,
    user_id: Uuid,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ttl: std::time::Duration,
) -> Result<(String, Uuid), SessionError> {
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);

    let session_id = state
        .repos
        .session_ops
        .create_session(user_id, token_hash, ip_address, user_agent, ttl)
        .await?;

    Ok((token, session_id))
}

pub async fn validate_session(
    state: &YAuthState,
    token: &str,
    request_ip: Option<&str>,
    request_ua: Option<&str>,
) -> Result<Option<SessionUser>, SessionError> {
    let token_hash = crypto::hash_token(token);

    let session = state
        .repos
        .session_ops
        .validate_session(&token_hash)
        .await?;

    crate::otel::set_attribute("yauth.session_found", session.is_some());

    match session {
        Some(s) => {
            let binding = &state.config.session_binding;

            if binding.bind_ip
                && let (Some(session_ip), Some(req_ip)) = (&s.ip_address, request_ip)
                && session_ip != req_ip
            {
                crate::otel::add_event(
                    "session_ip_mismatch",
                    #[cfg(feature = "telemetry")]
                    vec![
                        opentelemetry::KeyValue::new("session_id", s.id.to_string()),
                        opentelemetry::KeyValue::new("session_ip", session_ip.clone()),
                        opentelemetry::KeyValue::new("request_ip", req_ip.to_string()),
                    ],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                if binding.ip_mismatch_action == BindingAction::Invalidate {
                    let _ = state.repos.session_ops.delete_session(&token_hash).await;
                    return Ok(None);
                }
            }

            if binding.bind_user_agent
                && let (Some(session_ua), Some(req_ua)) = (&s.user_agent, request_ua)
                && session_ua != req_ua
            {
                crate::otel::add_event(
                    "session_ua_mismatch",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("session_id", s.id.to_string())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                if binding.ua_mismatch_action == BindingAction::Invalidate {
                    let _ = state.repos.session_ops.delete_session(&token_hash).await;
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

pub async fn delete_session(state: &YAuthState, token: &str) -> Result<bool, SessionError> {
    let token_hash = crypto::hash_token(token);
    Ok(state.repos.session_ops.delete_session(&token_hash).await?)
}

pub async fn delete_all_user_sessions(
    state: &YAuthState,
    user_id: Uuid,
) -> Result<u64, SessionError> {
    Ok(state
        .repos
        .session_ops
        .delete_all_sessions_for_user(user_id)
        .await?)
}

pub async fn delete_other_user_sessions(
    state: &YAuthState,
    user_id: Uuid,
    keep_token: &str,
) -> Result<u64, SessionError> {
    let keep_hash = crypto::hash_token(keep_token);
    Ok(state
        .repos
        .session_ops
        .delete_other_sessions_for_user(user_id, &keep_hash)
        .await?)
}
