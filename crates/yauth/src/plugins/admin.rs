use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware as axum_mw,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{crypto, session};
use crate::error::{ApiError, api_err};
use crate::middleware::{AuthUser, require_admin};
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

pub struct AdminPlugin;

impl YAuthPlugin for AdminPlugin {
    fn name(&self) -> &'static str {
        "admin"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/admin/users", get(list_users))
                .route("/admin/users/{id}", get(get_user))
                .route("/admin/users/{id}", put(update_user))
                .route("/admin/users/{id}", delete(delete_user))
                .route("/admin/users/{id}/ban", post(ban_user))
                .route("/admin/users/{id}/unban", post(unban_user))
                .route("/admin/users/{id}/impersonate", post(impersonate_user))
                .route("/admin/sessions", get(list_sessions))
                .route("/admin/sessions/{id}", delete(delete_session))
                .layer(axum_mw::from_fn(require_admin)),
        )
    }
}

// ---------------------------------------------------------------------------
// Request / query types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListUsersQuery {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
    pub search: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListSessionsQuery {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub role: Option<String>,
    pub email_verified: Option<bool>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BanRequest {
    pub reason: Option<String>,
    pub until: Option<String>,
}

/// Response type for `GET /admin/users` (schema-only, used for OpenAPI spec).
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginatedUsersResponse {
    pub users: Vec<AdminUserInfo>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
}

/// User info returned by admin list endpoint.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AdminUserInfo {
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

impl From<crate::domain::User> for AdminUserInfo {
    fn from(u: crate::domain::User) -> Self {
        AdminUserInfo {
            id: u.id.to_string(),
            email: u.email,
            display_name: u.display_name,
            email_verified: u.email_verified,
            role: u.role,
            banned: u.banned,
            banned_reason: u.banned_reason,
            banned_until: u.banned_until.map(|t| t.to_string()),
            created_at: u.created_at.to_string(),
            updated_at: u.updated_at.to_string(),
        }
    }
}

/// Response type for `GET /admin/sessions` (schema-only, used for OpenAPI spec).
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginatedSessionsResponse {
    pub sessions: Vec<AdminSessionInfo>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
}

/// Session info returned by admin list endpoint.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AdminSessionInfo {
    pub id: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}

/// Serializable session info (excludes token_hash for admin listing).
#[derive(Serialize, Clone)]
struct SessionInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: chrono::NaiveDateTime,
    pub created_at: chrono::NaiveDateTime,
}

impl From<crate::domain::Session> for SessionInfo {
    fn from(s: crate::domain::Session) -> Self {
        Self {
            id: s.id,
            user_id: s.user_id,
            ip_address: s.ip_address,
            user_agent: s.user_agent,
            expires_at: s.expires_at,
            created_at: s.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn paginate_params(page: Option<u64>, per_page: Option<u64>) -> (u64, u64) {
    let per_page = per_page.unwrap_or(50).clamp(1, 100);
    let page = page.unwrap_or(1).max(1);
    (page, per_page)
}

// ---------------------------------------------------------------------------
// GET /admin/users
// ---------------------------------------------------------------------------

async fn list_users(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
    Query(params): Query<ListUsersQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let (page, per_page) = paginate_params(params.page, params.per_page);

    let offset = ((page - 1) * per_page) as i64;
    let limit = per_page as i64;

    let (users, total) = state
        .repos
        .users
        .list(params.search.as_deref(), limit, offset)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_db_list_users_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let user_infos: Vec<AdminUserInfo> = users.into_iter().map(AdminUserInfo::from).collect();

    Ok(Json(serde_json::json!({
        "users": user_infos,
        "total": total as u64,
        "page": page,
        "per_page": per_page,
    })))
}

// ---------------------------------------------------------------------------
// GET /admin/users/{id}
// ---------------------------------------------------------------------------

async fn get_user(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let user = state
        .repos
        .users
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_db_fetch_user_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    Ok(Json(AdminUserInfo::from(user)))
}

// ---------------------------------------------------------------------------
// PUT /admin/users/{id}
// ---------------------------------------------------------------------------

async fn update_user(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify user exists
    state
        .repos
        .users
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_db_fetch_user_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    let changeset = crate::domain::UpdateUser {
        email: None,
        display_name: input.display_name.map(Some),
        email_verified: input.email_verified,
        role: input.role,
        banned: None,
        banned_reason: None,
        banned_until: None,
        updated_at: Some(Utc::now().naive_utc()),
    };

    let updated = state.repos.users.update(id, changeset).await.map_err(|e| {
        crate::otel::record_error("admin_db_update_user_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    crate::otel::add_event(
        "admin_user_updated",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("target.id", id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(admin.id),
            "admin_update_user",
            Some(serde_json::json!({ "target_user_id": id })),
            None,
        )
        .await;

    Ok(Json(AdminUserInfo::from(updated)))
}

// ---------------------------------------------------------------------------
// DELETE /admin/users/{id}
// ---------------------------------------------------------------------------

async fn delete_user(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    if admin.id == id {
        return Err(api_err(StatusCode::BAD_REQUEST, "Cannot delete yourself"));
    }

    // Verify user exists
    state
        .repos
        .users
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_db_fetch_user_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    state.repos.users.delete(id).await.map_err(|e| {
        crate::otel::record_error("admin_db_delete_user_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    crate::otel::add_event(
        "admin_user_deleted",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("target.id", id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(admin.id),
            "admin_delete_user",
            Some(serde_json::json!({ "target_user_id": id })),
            None,
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /admin/users/{id}/ban
// ---------------------------------------------------------------------------

async fn ban_user(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(input): Json<BanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if admin.id == id {
        return Err(api_err(StatusCode::BAD_REQUEST, "Cannot ban yourself"));
    }

    let banned_until = match input.until {
        Some(ref ts) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(ts).map_err(|_| {
                api_err(
                    StatusCode::BAD_REQUEST,
                    "Invalid 'until' timestamp, expected RFC 3339 format",
                )
            })?;
            Some(parsed.naive_utc())
        }
        None => None,
    };

    // Verify user exists
    state
        .repos
        .users
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_db_fetch_user_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    let changeset = crate::domain::UpdateUser {
        email: None,
        display_name: None,
        email_verified: None,
        role: None,
        banned: Some(true),
        banned_reason: Some(input.reason.clone()),
        banned_until: Some(banned_until),
        updated_at: Some(Utc::now().naive_utc()),
    };

    let updated = state.repos.users.update(id, changeset).await.map_err(|e| {
        crate::otel::record_error("admin_db_ban_user_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Delete all active sessions for the banned user
    let deleted_sessions = session::delete_all_user_sessions(&state, id)
        .await
        .unwrap_or(0);

    crate::otel::add_event(
        "admin_user_banned",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("target.id", id.to_string()),
            opentelemetry::KeyValue::new("sessions_deleted", deleted_sessions.to_string()),
            opentelemetry::KeyValue::new("reason", format!("{:?}", input.reason)),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(admin.id),
            "admin_ban_user",
            Some(serde_json::json!({ "target_user_id": id, "reason": input.reason })),
            None,
        )
        .await;

    Ok(Json(AdminUserInfo::from(updated)))
}

// ---------------------------------------------------------------------------
// POST /admin/users/{id}/unban
// ---------------------------------------------------------------------------

async fn unban_user(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify user exists
    state
        .repos
        .users
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_db_fetch_user_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    let changeset = crate::domain::UpdateUser {
        email: None,
        display_name: None,
        email_verified: None,
        role: None,
        banned: Some(false),
        banned_reason: Some(None),
        banned_until: Some(None),
        updated_at: Some(Utc::now().naive_utc()),
    };

    let updated = state.repos.users.update(id, changeset).await.map_err(|e| {
        crate::otel::record_error("admin_db_unban_user_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    crate::otel::add_event(
        "admin_user_unbanned",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("target.id", id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(admin.id),
            "admin_unban_user",
            Some(serde_json::json!({ "target_user_id": id })),
            None,
        )
        .await;

    Ok(Json(AdminUserInfo::from(updated)))
}

// ---------------------------------------------------------------------------
// POST /admin/users/{id}/impersonate
// ---------------------------------------------------------------------------

async fn impersonate_user(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    if admin.id == id {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Cannot impersonate yourself",
        ));
    }

    // Verify target user exists
    state
        .repos
        .users
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_db_fetch_user_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    // Create a temporary session for the target user (max 1 hour)
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let session_id = Uuid::now_v7();
    let now = Utc::now();
    let expires_at = now + Duration::hours(1);

    let new_session = crate::domain::NewSession {
        id: session_id,
        user_id: id,
        token_hash: token_hash.clone(),
        ip_address: None,
        user_agent: Some("admin-impersonation".to_string()),
        expires_at: expires_at.naive_utc(),
        created_at: now.naive_utc(),
    };

    state
        .repos
        .sessions
        .create(new_session)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_impersonation_session_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    state
        .write_audit_log(
            Some(admin.id),
            "admin_impersonate",
            Some(serde_json::json!({
                "admin_user_id": admin.id,
                "target_user_id": id,
                "session_id": session_id,
            })),
            None,
        )
        .await;

    crate::otel::add_event(
        "admin_impersonated_user",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("target.id", id.to_string()),
            opentelemetry::KeyValue::new("session.id", session_id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    Ok(Json(serde_json::json!({
        "token": token,
        "session_id": session_id,
        "expires_at": expires_at,
    })))
}

// ---------------------------------------------------------------------------
// GET /admin/sessions
// ---------------------------------------------------------------------------

async fn list_sessions(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
    Query(params): Query<ListSessionsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let (page, per_page) = paginate_params(params.page, params.per_page);

    let offset = ((page - 1) * per_page) as i64;
    let limit = per_page as i64;

    let (sessions_raw, total) = state
        .repos
        .sessions
        .list(limit, offset)
        .await
        .map_err(|e| {
            crate::otel::record_error("admin_db_list_sessions_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let sessions: Vec<SessionInfo> = sessions_raw.into_iter().map(SessionInfo::from).collect();

    Ok(Json(serde_json::json!({
        "sessions": sessions,
        "total": total as u64,
        "page": page,
        "per_page": per_page,
    })))
}

// ---------------------------------------------------------------------------
// DELETE /admin/sessions/{id}
// ---------------------------------------------------------------------------

async fn delete_session(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let session_user_id = {
        let session = state
            .repos
            .sessions
            .find_by_id(id)
            .await
            .map_err(|e| {
                crate::otel::record_error("admin_db_fetch_session_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Session not found"))?;

        let uid = session.user_id;

        state.repos.sessions.delete(id).await.map_err(|e| {
            crate::otel::record_error("admin_db_delete_session_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        uid
    };

    crate::otel::add_event(
        "admin_session_deleted",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("session.id", id.to_string()),
            opentelemetry::KeyValue::new("session.user_id", session_user_id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(admin.id),
            "admin_delete_session",
            Some(serde_json::json!({ "session_id": id, "session_user_id": session_user_id })),
            None,
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}
