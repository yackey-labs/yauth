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
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{crypto, session};
use crate::db::models::{NewAuditLog, NewSession, Session, UpdateUser, User};
use crate::db::schema::{yauth_audit_log, yauth_sessions, yauth_users};
use crate::error::{ApiError, api_err};
use crate::middleware::{AuthUser, require_admin};
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;

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

impl From<Session> for SessionInfo {
    fn from(s: Session) -> Self {
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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    let offset = ((page - 1) * per_page) as i64;
    let limit = per_page as i64;

    let (total, users) = match params.search.as_deref() {
        Some(pattern) => {
            let like_pattern = format!("%{}%", pattern);
            let count: i64 = yauth_users::table
                .filter(
                    yauth_users::email
                        .ilike(&like_pattern)
                        .or(yauth_users::display_name.ilike(&like_pattern)),
                )
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| {
                    tracing::error!("DB error counting users: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

            let rows: Vec<User> = yauth_users::table
                .filter(
                    yauth_users::email
                        .ilike(&like_pattern)
                        .or(yauth_users::display_name.ilike(&like_pattern)),
                )
                .order(yauth_users::created_at.asc())
                .limit(limit)
                .offset(offset)
                .select(User::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| {
                    tracing::error!("DB error listing users: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

            (count as u64, rows)
        }
        None => {
            let count: i64 = yauth_users::table
                .count()
                .get_result(&mut conn)
                .await
                .map_err(|e| {
                    tracing::error!("DB error counting users: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

            let rows: Vec<User> = yauth_users::table
                .order(yauth_users::created_at.asc())
                .limit(limit)
                .offset(offset)
                .select(User::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| {
                    tracing::error!("DB error listing users: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

            (count as u64, rows)
        }
    };

    Ok(Json(serde_json::json!({
        "users": users,
        "total": total,
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
    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    let user: User = yauth_users::table
        .find(id)
        .select(User::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    Ok(Json(serde_json::json!(user)))
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
    let updated = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        // Verify user exists
        yauth_users::table
            .find(id)
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| {
                tracing::error!("DB error fetching user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

        let changeset = UpdateUser {
            email: None,
            display_name: input.display_name.map(Some),
            email_verified: input.email_verified,
            role: input.role,
            banned: None,
            banned_reason: None,
            banned_until: None,
            updated_at: Some(Utc::now().naive_utc()),
        };

        let updated: User = diesel::update(yauth_users::table.find(id))
            .set(&changeset)
            .returning(User::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("DB error updating user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        updated
    };

    info!(
        event = "yauth.admin.user_updated",
        admin_id = %admin.id,
        target_id = %id,
        "Admin updated user"
    );

    state
        .write_audit_log(
            Some(admin.id),
            "admin_update_user",
            Some(serde_json::json!({ "target_user_id": id })),
            None,
        )
        .await;

    Ok(Json(serde_json::json!(updated)))
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

    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        yauth_users::table
            .find(id)
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| {
                tracing::error!("DB error fetching user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

        diesel::delete(yauth_users::table.find(id))
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("DB error deleting user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    info!(
        event = "yauth.admin.user_deleted",
        admin_id = %admin.id,
        target_id = %id,
        "Admin deleted user"
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
            Some(parsed.fixed_offset())
        }
        None => None,
    };

    let updated = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        yauth_users::table
            .find(id)
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| {
                tracing::error!("DB error fetching user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

        let changeset = UpdateUser {
            email: None,
            display_name: None,
            email_verified: None,
            role: None,
            banned: Some(true),
            banned_reason: Some(input.reason.clone()),
            banned_until: Some(banned_until.map(|t| t.naive_utc())),
            updated_at: Some(Utc::now().naive_utc()),
        };

        let updated: User = diesel::update(yauth_users::table.find(id))
            .set(&changeset)
            .returning(User::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("DB error banning user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        updated
    };

    // Delete all active sessions for the banned user
    let deleted_sessions = session::delete_all_user_sessions(&state.db, id)
        .await
        .unwrap_or(0);

    info!(
        event = "yauth.admin.user_banned",
        admin_id = %admin.id,
        target_id = %id,
        sessions_deleted = deleted_sessions,
        reason = ?input.reason,
        "Admin banned user"
    );

    state
        .write_audit_log(
            Some(admin.id),
            "admin_ban_user",
            Some(serde_json::json!({ "target_user_id": id, "reason": input.reason })),
            None,
        )
        .await;

    Ok(Json(serde_json::json!(updated)))
}

// ---------------------------------------------------------------------------
// POST /admin/users/{id}/unban
// ---------------------------------------------------------------------------

async fn unban_user(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let updated = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        yauth_users::table
            .find(id)
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| {
                tracing::error!("DB error fetching user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

        let changeset = UpdateUser {
            email: None,
            display_name: None,
            email_verified: None,
            role: None,
            banned: Some(false),
            banned_reason: Some(None),
            banned_until: Some(None),
            updated_at: Some(Utc::now().naive_utc()),
        };

        let updated: User = diesel::update(yauth_users::table.find(id))
            .set(&changeset)
            .returning(User::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("DB error unbanning user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        updated
    };

    info!(
        event = "yauth.admin.user_unbanned",
        admin_id = %admin.id,
        target_id = %id,
        "Admin unbanned user"
    );

    state
        .write_audit_log(
            Some(admin.id),
            "admin_unban_user",
            Some(serde_json::json!({ "target_user_id": id })),
            None,
        )
        .await;

    Ok(Json(serde_json::json!(updated)))
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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Verify target user exists
    yauth_users::table
        .find(id)
        .select(User::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    // Create a temporary session for the target user (max 1 hour)
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let session_id = Uuid::new_v4();
    let now = Utc::now();
    let expires_at = now + Duration::hours(1);

    let new_session = NewSession {
        id: session_id,
        user_id: id,
        token_hash: token_hash.clone(),
        ip_address: None,
        user_agent: Some("admin-impersonation".to_string()),
        expires_at: expires_at.naive_utc(),
        created_at: now.naive_utc(),
    };

    diesel::insert_into(yauth_sessions::table)
        .values(&new_session)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("DB error creating impersonation session: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let new_audit = NewAuditLog {
        id: Uuid::new_v4(),
        user_id: Some(admin.id),
        event_type: "admin_impersonate".to_string(),
        metadata: Some(serde_json::json!({
            "admin_user_id": admin.id,
            "target_user_id": id,
            "session_id": session_id,
        })),
        ip_address: None,
        created_at: now.naive_utc(),
    };

    diesel::insert_into(yauth_audit_log::table)
        .values(&new_audit)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("DB error writing audit log: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    warn!(
        event = "yauth.admin.impersonate",
        admin_id = %admin.id,
        target_id = %id,
        session_id = %session_id,
        "Admin impersonated user"
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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    let offset = ((page - 1) * per_page) as i64;
    let limit = per_page as i64;

    let total: i64 = yauth_sessions::table
        .count()
        .get_result(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("DB error counting sessions: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let sessions: Vec<SessionInfo> = yauth_sessions::table
        .order(yauth_sessions::created_at.desc())
        .limit(limit)
        .offset(offset)
        .select(Session::as_select())
        .load(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("DB error listing sessions: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .into_iter()
        .map(SessionInfo::from)
        .collect();

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
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        let session: Session = yauth_sessions::table
            .find(id)
            .select(Session::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| {
                tracing::error!("DB error fetching session: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Session not found"))?;

        let uid = session.user_id;

        diesel::delete(yauth_sessions::table.find(id))
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("DB error deleting session: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        uid
    };

    info!(
        event = "yauth.admin.session_deleted",
        admin_id = %admin.id,
        session_id = %id,
        session_user_id = %session_user_id,
        "Admin deleted session"
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
