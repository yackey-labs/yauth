use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware as axum_mw,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{crypto, session};
use crate::error::{ApiError, api_err};
use crate::middleware::{AuthUser, require_admin};
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Diesel-async helpers
// ---------------------------------------------------------------------------

mod diesel_db {
    use diesel::result::OptionalExtension;
    use diesel_async_crate::RunQueryDsl;
    use uuid::Uuid;

    type Conn = diesel_async_crate::AsyncPgConnection;
    type DbResult<T> = Result<T, String>;

    #[derive(diesel::QueryableByName, Clone, serde::Serialize)]
    #[allow(dead_code)]
    pub struct UserRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
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
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
        pub banned_until: Option<chrono::NaiveDateTime>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub updated_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone, serde::Serialize)]
    #[allow(dead_code)]
    pub struct SessionRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub user_id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub token_hash: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub ip_address: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub user_agent: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub expires_at: chrono::NaiveDateTime,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct CountRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        pub count: i64,
    }

    pub async fn find_user_by_id(conn: &mut Conn, id: Uuid) -> DbResult<Option<UserRow>> {
        diesel::sql_query(
            "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at FROM yauth_users WHERE id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn list_users(
        conn: &mut Conn,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> DbResult<Vec<UserRow>> {
        match search {
            Some(pattern) => {
                let like_pattern = format!("%{}%", pattern);
                diesel::sql_query(
                    "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at FROM yauth_users WHERE email ILIKE $1 OR display_name ILIKE $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3",
                )
                .bind::<diesel::sql_types::Text, _>(&like_pattern)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(conn)
                .await
                .map_err(|e| e.to_string())
            }
            None => {
                diesel::sql_query(
                    "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at FROM yauth_users ORDER BY created_at ASC LIMIT $1 OFFSET $2",
                )
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(conn)
                .await
                .map_err(|e| e.to_string())
            }
        }
    }

    pub async fn count_users(conn: &mut Conn, search: Option<&str>) -> DbResult<u64> {
        let row: CountRow = match search {
            Some(pattern) => {
                let like_pattern = format!("%{}%", pattern);
                diesel::sql_query(
                    "SELECT COUNT(*) AS count FROM yauth_users WHERE email ILIKE $1 OR display_name ILIKE $1",
                )
                .bind::<diesel::sql_types::Text, _>(&like_pattern)
                .get_result(conn)
                .await
                .map_err(|e| e.to_string())?
            }
            None => diesel::sql_query("SELECT COUNT(*) AS count FROM yauth_users")
                .get_result(conn)
                .await
                .map_err(|e| e.to_string())?,
        };
        Ok(row.count as u64)
    }

    pub async fn update_user(
        conn: &mut Conn,
        id: Uuid,
        display_name: Option<&str>,
        role: Option<&str>,
        email_verified: Option<bool>,
        updated_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<UserRow> {
        // Use COALESCE to keep existing values for NULL parameters
        diesel::sql_query(
            "UPDATE yauth_users SET display_name = COALESCE($1, display_name), role = COALESCE($2, role), email_verified = COALESCE($3, email_verified), updated_at = $4 WHERE id = $5 RETURNING id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(display_name)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(role)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Bool>, _>(email_verified)
        .bind::<diesel::sql_types::Timestamptz, _>(updated_at)
        .bind::<diesel::sql_types::Uuid, _>(id)
        .get_result(conn)
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn delete_user(conn: &mut Conn, id: Uuid) -> DbResult<()> {
        diesel::sql_query("DELETE FROM yauth_users WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn ban_user(
        conn: &mut Conn,
        id: Uuid,
        reason: Option<&str>,
        banned_until: Option<chrono::DateTime<chrono::FixedOffset>>,
        updated_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<UserRow> {
        diesel::sql_query(
            "UPDATE yauth_users SET banned = true, banned_reason = $1, banned_until = $2, updated_at = $3 WHERE id = $4 RETURNING id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(reason)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(banned_until)
        .bind::<diesel::sql_types::Timestamptz, _>(updated_at)
        .bind::<diesel::sql_types::Uuid, _>(id)
        .get_result(conn)
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn unban_user(
        conn: &mut Conn,
        id: Uuid,
        updated_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<UserRow> {
        diesel::sql_query(
            "UPDATE yauth_users SET banned = false, banned_reason = NULL, banned_until = NULL, updated_at = $1 WHERE id = $2 RETURNING id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at",
        )
        .bind::<diesel::sql_types::Timestamptz, _>(updated_at)
        .bind::<diesel::sql_types::Uuid, _>(id)
        .get_result(conn)
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn insert_session(
        conn: &mut Conn,
        id: Uuid,
        user_id: Uuid,
        token_hash: &str,
        user_agent: Option<&str>,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
        now: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) VALUES ($1, $2, $3, NULL, $4, $5, $6)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(token_hash)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(user_agent)
        .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn insert_audit_log(
        conn: &mut Conn,
        id: Uuid,
        user_id: Option<Uuid>,
        event_type: &str,
        metadata: Option<serde_json::Value>,
        now: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) VALUES ($1, $2, $3, $4, NULL, $5)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(event_type)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(metadata)
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_sessions(
        conn: &mut Conn,
        limit: i64,
        offset: i64,
    ) -> DbResult<Vec<SessionRow>> {
        diesel::sql_query(
            "SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at FROM yauth_sessions ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind::<diesel::sql_types::BigInt, _>(limit)
        .bind::<diesel::sql_types::BigInt, _>(offset)
        .load(conn)
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn count_sessions(conn: &mut Conn) -> DbResult<u64> {
        let row: CountRow = diesel::sql_query("SELECT COUNT(*) AS count FROM yauth_sessions")
            .get_result(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.count as u64)
    }

    pub async fn find_session_by_id(conn: &mut Conn, id: Uuid) -> DbResult<Option<SessionRow>> {
        diesel::sql_query(
            "SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at FROM yauth_sessions WHERE id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn delete_session(conn: &mut Conn, id: Uuid) -> DbResult<()> {
        diesel::sql_query("DELETE FROM yauth_sessions WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

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
pub struct ListUsersQuery {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
    pub search: Option<String>,
}

#[derive(Deserialize)]
pub struct ListSessionsQuery {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub role: Option<String>,
    pub email_verified: Option<bool>,
}

#[derive(Deserialize)]
pub struct BanRequest {
    pub reason: Option<String>,
    pub until: Option<String>,
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

    let total = diesel_db::count_users(&mut conn, params.search.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("DB error counting users: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let users = diesel_db::list_users(&mut conn, params.search.as_deref(), limit, offset)
        .await
        .map_err(|e| {
            tracing::error!("DB error listing users: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
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
    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    let user = diesel_db::find_user_by_id(&mut conn, id)
        .await
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
        diesel_db::find_user_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                tracing::error!("DB error fetching user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

        diesel_db::update_user(
            &mut conn,
            id,
            input.display_name.as_deref(),
            input.role.as_deref(),
            input.email_verified,
            Utc::now().fixed_offset(),
        )
        .await
        .map_err(|e| {
            tracing::error!("DB error updating user: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
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

        diesel_db::find_user_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                tracing::error!("DB error fetching user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

        diesel_db::delete_user(&mut conn, id).await.map_err(|e| {
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

        diesel_db::find_user_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                tracing::error!("DB error fetching user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

        diesel_db::ban_user(
            &mut conn,
            id,
            input.reason.as_deref(),
            banned_until,
            Utc::now().fixed_offset(),
        )
        .await
        .map_err(|e| {
            tracing::error!("DB error banning user: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
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

        diesel_db::find_user_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                tracing::error!("DB error fetching user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

        diesel_db::unban_user(&mut conn, id, Utc::now().fixed_offset())
            .await
            .map_err(|e| {
                tracing::error!("DB error unbanning user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
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
    diesel_db::find_user_by_id(&mut conn, id)
        .await
        .map_err(|e| {
            tracing::error!("DB error fetching user: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    // Create a temporary session for the target user (max 1 hour)
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let session_id = Uuid::new_v4();
    let now = Utc::now().fixed_offset();
    let expires_at = (Utc::now() + Duration::hours(1)).fixed_offset();

    diesel_db::insert_session(
        &mut conn,
        session_id,
        id,
        &token_hash,
        Some("admin-impersonation"),
        expires_at,
        now,
    )
    .await
    .map_err(|e| {
        tracing::error!("DB error creating impersonation session: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    diesel_db::insert_audit_log(
        &mut conn,
        Uuid::new_v4(),
        Some(admin.id),
        "admin_impersonate",
        Some(serde_json::json!({
            "admin_user_id": admin.id,
            "target_user_id": id,
            "session_id": session_id,
        })),
        now,
    )
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

    let total = diesel_db::count_sessions(&mut conn).await.map_err(|e| {
        tracing::error!("DB error counting sessions: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let sessions = diesel_db::list_sessions(&mut conn, limit, offset)
        .await
        .map_err(|e| {
            tracing::error!("DB error listing sessions: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
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
    let session_user_id = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        let session = diesel_db::find_session_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                tracing::error!("DB error fetching session: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Session not found"))?;

        let uid = session.user_id;

        diesel_db::delete_session(&mut conn, id)
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
