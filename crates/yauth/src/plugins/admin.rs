use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware as axum_mw,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use chrono::{Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    Set,
};
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{crypto, session};
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
struct ListUsersQuery {
    page: Option<u64>,
    per_page: Option<u64>,
    search: Option<String>,
}

#[derive(Deserialize)]
struct ListSessionsQuery {
    page: Option<u64>,
    per_page: Option<u64>,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    display_name: Option<String>,
    role: Option<String>,
    email_verified: Option<bool>,
}

#[derive(Deserialize)]
struct BanRequest {
    reason: Option<String>,
    until: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": msg })))
}

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

    let mut query =
        yauth_entity::users::Entity::find().order_by_asc(yauth_entity::users::Column::CreatedAt);

    if let Some(ref search) = params.search {
        let pattern = format!("%{}%", search);
        query = query.filter(
            Condition::any()
                .add(yauth_entity::users::Column::Email.like(&pattern))
                .add(yauth_entity::users::Column::DisplayName.like(&pattern)),
        );
    }

    let paginator = query.paginate(&state.db, per_page);

    let total = paginator.num_items().await.map_err(|e| {
        tracing::error!("DB error counting users: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // SeaORM pages are 0-indexed
    let users = paginator.fetch_page(page - 1).await.map_err(|e| {
        tracing::error!("DB error listing users: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

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
    let user = yauth_entity::users::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

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
    let user = yauth_entity::users::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    let mut active: yauth_entity::users::ActiveModel = user.into();

    if let Some(display_name) = input.display_name {
        active.display_name = Set(Some(display_name));
    }
    if let Some(role) = input.role {
        active.role = Set(role);
    }
    if let Some(email_verified) = input.email_verified {
        active.email_verified = Set(email_verified);
    }

    active.updated_at = Set(Utc::now().fixed_offset());

    let updated = active.update(&state.db).await.map_err(|e| {
        tracing::error!("DB error updating user: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    info!(
        event = "admin_update_user",
        admin_id = %admin.id,
        target_id = %id,
        "Admin updated user"
    );

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
        return Err(err(StatusCode::BAD_REQUEST, "Cannot delete yourself"));
    }

    let user = yauth_entity::users::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    yauth_entity::users::Entity::delete_by_id(user.id)
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error deleting user: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    info!(
        event = "admin_delete_user",
        admin_id = %admin.id,
        target_id = %id,
        "Admin deleted user"
    );

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
        return Err(err(StatusCode::BAD_REQUEST, "Cannot ban yourself"));
    }

    let user = yauth_entity::users::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    let banned_until = match input.until {
        Some(ref ts) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(ts).map_err(|_| {
                err(
                    StatusCode::BAD_REQUEST,
                    "Invalid 'until' timestamp, expected RFC 3339 format",
                )
            })?;
            Some(parsed.fixed_offset())
        }
        None => None,
    };

    let mut active: yauth_entity::users::ActiveModel = user.into();
    active.banned = Set(true);
    active.banned_reason = Set(input.reason.clone());
    active.banned_until = Set(banned_until);
    active.updated_at = Set(Utc::now().fixed_offset());

    let updated = active.update(&state.db).await.map_err(|e| {
        tracing::error!("DB error banning user: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Delete all active sessions for the banned user
    let deleted_sessions = session::delete_all_user_sessions(&state.db, id)
        .await
        .unwrap_or(0);

    info!(
        event = "admin_ban_user",
        admin_id = %admin.id,
        target_id = %id,
        sessions_deleted = deleted_sessions,
        reason = ?input.reason,
        "Admin banned user"
    );

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
    let user = yauth_entity::users::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    let mut active: yauth_entity::users::ActiveModel = user.into();
    active.banned = Set(false);
    active.banned_reason = Set(None);
    active.banned_until = Set(None);
    active.updated_at = Set(Utc::now().fixed_offset());

    let updated = active.update(&state.db).await.map_err(|e| {
        tracing::error!("DB error unbanning user: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    info!(
        event = "admin_unban_user",
        admin_id = %admin.id,
        target_id = %id,
        "Admin unbanned user"
    );

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
        return Err(err(StatusCode::BAD_REQUEST, "Cannot impersonate yourself"));
    }

    // Verify target user exists
    let _target = yauth_entity::users::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    // Create a temporary session for the target user (max 1 hour)
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let session_id = Uuid::new_v4();
    let now = Utc::now().fixed_offset();
    let expires_at = (Utc::now() + Duration::hours(1)).fixed_offset();

    let session_model = yauth_entity::sessions::ActiveModel {
        id: Set(session_id),
        user_id: Set(id),
        token_hash: Set(token_hash),
        ip_address: Set(None),
        user_agent: Set(Some("admin-impersonation".to_string())),
        expires_at: Set(expires_at),
        created_at: Set(now),
    };

    session_model.insert(&state.db).await.map_err(|e| {
        tracing::error!("DB error creating impersonation session: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Write audit log entry
    let audit_entry = yauth_entity::audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(Some(admin.id)),
        event_type: Set("admin_impersonate".to_string()),
        metadata: Set(Some(serde_json::json!({
            "admin_user_id": admin.id,
            "target_user_id": id,
            "session_id": session_id,
        }))),
        ip_address: Set(None),
        created_at: Set(now),
    };

    audit_entry.insert(&state.db).await.map_err(|e| {
        tracing::error!("DB error writing audit log: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    warn!(
        event = "admin_impersonate",
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

    let paginator = yauth_entity::sessions::Entity::find()
        .order_by_desc(yauth_entity::sessions::Column::CreatedAt)
        .paginate(&state.db, per_page);

    let total = paginator.num_items().await.map_err(|e| {
        tracing::error!("DB error counting sessions: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let sessions = paginator.fetch_page(page - 1).await.map_err(|e| {
        tracing::error!("DB error listing sessions: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    Ok(Json(serde_json::json!({
        "sessions": sessions,
        "total": total,
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
    let session = yauth_entity::sessions::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error fetching session: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Session not found"))?;

    yauth_entity::sessions::Entity::delete_by_id(session.id)
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error deleting session: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    info!(
        event = "admin_delete_session",
        admin_id = %admin.id,
        session_id = %id,
        session_user_id = %session.user_id,
        "Admin deleted session"
    );

    Ok(StatusCode::NO_CONTENT)
}
