use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
#[cfg(feature = "seaorm")]
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::crypto;
use crate::middleware::{AuthMethod, AuthUser};
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Diesel-async helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "diesel-async")]
mod diesel_db {
    use diesel::result::OptionalExtension;
    use diesel_async_crate::RunQueryDsl;
    use uuid::Uuid;

    type Conn = diesel_async_crate::AsyncPgConnection;
    type DbResult<T> = Result<T, String>;

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct ApiKeyRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub user_id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub key_prefix: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub key_hash: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub name: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        pub scopes: Option<serde_json::Value>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
        pub last_used_at: Option<chrono::NaiveDateTime>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
        pub expires_at: Option<chrono::NaiveDateTime>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone)]
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
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_api_key(
        conn: &mut Conn,
        id: Uuid,
        user_id: Uuid,
        key_prefix: &str,
        key_hash: &str,
        name: &str,
        scopes: Option<serde_json::Value>,
        expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
        created_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_api_keys (id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(key_prefix)
        .bind::<diesel::sql_types::Text, _>(key_hash)
        .bind::<diesel::sql_types::Text, _>(name)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(scopes)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(created_at)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_api_keys_by_user(conn: &mut Conn, user_id: Uuid) -> DbResult<Vec<ApiKeyRow>> {
        diesel::sql_query(
            "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at FROM yauth_api_keys WHERE user_id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .load(conn)
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn find_api_key_by_id_and_user(
        conn: &mut Conn,
        id: Uuid,
        user_id: Uuid,
    ) -> DbResult<Option<ApiKeyRow>> {
        diesel::sql_query(
            "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at FROM yauth_api_keys WHERE id = $1 AND user_id = $2",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn delete_api_key(conn: &mut Conn, id: Uuid) -> DbResult<()> {
        diesel::sql_query("DELETE FROM yauth_api_keys WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn find_api_key_by_prefix(
        conn: &mut Conn,
        prefix: &str,
    ) -> DbResult<Option<ApiKeyRow>> {
        diesel::sql_query(
            "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at FROM yauth_api_keys WHERE key_prefix = $1",
        )
        .bind::<diesel::sql_types::Text, _>(prefix)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn update_api_key_last_used(
        conn: &mut Conn,
        id: Uuid,
        now: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query("UPDATE yauth_api_keys SET last_used_at = $1 WHERE id = $2")
            .bind::<diesel::sql_types::Timestamptz, _>(now)
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn find_user_by_id(conn: &mut Conn, id: Uuid) -> DbResult<Option<UserRow>> {
        diesel::sql_query(
            "SELECT id, email, display_name, email_verified, role, banned FROM yauth_users WHERE id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }
}

pub struct ApiKeyPlugin;

impl YAuthPlugin for ApiKeyPlugin {
    fn name(&self) -> &'static str {
        "api-key"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/api-keys", get(list_api_keys))
                .route("/api-keys", post(create_api_key))
                .route("/api-keys/{id}", delete(delete_api_key)),
        )
    }
}

#[derive(Deserialize, TS)]
#[ts(export)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<u32>,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub prefix: String,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    pub created_at: chrono::DateTime<chrono::FixedOffset>,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub scopes: Option<Vec<String>>,
    pub last_used_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    pub expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    pub created_at: chrono::DateTime<chrono::FixedOffset>,
}

async fn create_api_key(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Json(input): Json<CreateApiKeyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "API key name is required"));
    }

    let prefix = crypto::generate_token()[..8].to_string();
    let secret = crypto::generate_token();
    let full_key = format!("yauth_{}_{}", prefix, secret);
    let key_hash = crypto::hash_token(&full_key);

    let now = chrono::Utc::now().fixed_offset();

    let expires_at = input
        .expires_in_days
        .map(|days| (chrono::Utc::now() + chrono::Duration::days(i64::from(days))).fixed_offset());

    let scopes_json = input.scopes.as_ref().map(|s| serde_json::json!(s));

    let api_key_id = Uuid::new_v4();

    #[cfg(feature = "seaorm")]
    {
        let api_key = yauth_entity::api_keys::ActiveModel {
            id: Set(api_key_id),
            user_id: Set(user.id),
            key_prefix: Set(prefix.clone()),
            key_hash: Set(key_hash),
            name: Set(name.clone()),
            scopes: Set(scopes_json),
            last_used_at: Set(None),
            expires_at: Set(expires_at),
            created_at: Set(now),
        };

        api_key.insert(&state.db).await.map_err(|e| {
            tracing::error!("Failed to create API key: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        diesel_db::insert_api_key(
            &mut conn,
            api_key_id,
            user.id,
            &prefix,
            &key_hash,
            &name,
            scopes_json,
            expires_at,
            now,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create API key: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }

    info!(
        event = "yauth.api_key.created",
        user_id = %user.id,
        key_id = %api_key_id,
        prefix = %prefix,
        "API key created"
    );

    state
        .write_audit_log(
            Some(user.id),
            "api_key_created",
            Some(serde_json::json!({ "key_id": api_key_id, "name": name, "prefix": prefix })),
            None,
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id: api_key_id,
            key: full_key,
            name,
            prefix,
            scopes: input.scopes,
            expires_at,
            created_at: now,
        }),
    ))
}

async fn list_api_keys(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<ApiKeyResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    #[cfg(feature = "seaorm")]
    let response: Vec<ApiKeyResponse> = {
        let keys = yauth_entity::api_keys::Entity::find()
            .filter(yauth_entity::api_keys::Column::UserId.eq(user.id))
            .all(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to list API keys: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        keys.into_iter()
            .map(|k| {
                let scopes = k
                    .scopes
                    .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok());
                ApiKeyResponse {
                    id: k.id,
                    name: k.name,
                    prefix: k.key_prefix,
                    scopes,
                    last_used_at: k.last_used_at,
                    expires_at: k.expires_at,
                    created_at: k.created_at,
                }
            })
            .collect()
    };

    #[cfg(feature = "diesel-async")]
    let response: Vec<ApiKeyResponse> = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let keys = diesel_db::list_api_keys_by_user(&mut conn, user.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to list API keys: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        keys.into_iter()
            .map(|k| {
                let scopes = k
                    .scopes
                    .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok());
                ApiKeyResponse {
                    id: k.id,
                    name: k.name,
                    prefix: k.key_prefix,
                    scopes,
                    last_used_at: k.last_used_at.map(|t| t.and_utc().fixed_offset()),
                    expires_at: k.expires_at.map(|t| t.and_utc().fixed_offset()),
                    created_at: k.created_at.and_utc().fixed_offset(),
                }
            })
            .collect()
    };

    Ok(Json(response))
}

async fn delete_api_key(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    #[cfg(feature = "seaorm")]
    {
        let key = yauth_entity::api_keys::Entity::find_by_id(id)
            .filter(yauth_entity::api_keys::Column::UserId.eq(user.id))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find API key: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let key = key.ok_or_else(|| err(StatusCode::NOT_FOUND, "API key not found"))?;

        yauth_entity::api_keys::Entity::delete_by_id(key.id)
            .exec(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete API key: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let key = diesel_db::find_api_key_by_id_and_user(&mut conn, id, user.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find API key: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let key = key.ok_or_else(|| err(StatusCode::NOT_FOUND, "API key not found"))?;

        diesel_db::delete_api_key(&mut conn, key.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete API key: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    info!(
        event = "yauth.api_key.deleted",
        user_id = %user.id,
        key_id = %id,
        "API key deleted"
    );

    state
        .write_audit_log(
            Some(user.id),
            "api_key_deleted",
            Some(serde_json::json!({ "key_id": id })),
            None,
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Validate an API key from the `X-Api-Key` header. Called from the auth middleware.
pub async fn validate_api_key(key: &str, state: &YAuthState) -> Result<AuthUser, String> {
    // Parse the key format: yauth_<prefix>_<secret>
    let parts: Vec<&str> = key.splitn(3, '_').collect();
    if parts.len() != 3 || parts[0] != "yauth" {
        return Err("Invalid API key format".to_string());
    }

    let prefix = parts[1];
    let _secret = parts[2];

    if prefix.len() != 8 {
        return Err("Invalid API key format".to_string());
    }

    struct ApiKeyInfo {
        id: Uuid,
        user_id: Uuid,
        key_hash: String,
        scopes: Option<serde_json::Value>,
        expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    }
    struct UserInfo {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
        role: String,
        banned: bool,
    }

    #[cfg(feature = "diesel-async")]
    let mut conn = state
        .db
        .get()
        .await
        .map_err(|e| format!("Pool error: {}", e))?;

    // Look up by prefix
    #[cfg(feature = "seaorm")]
    let api_key_info = {
        let api_key = yauth_entity::api_keys::Entity::find()
            .filter(yauth_entity::api_keys::Column::KeyPrefix.eq(prefix))
            .one(&state.db)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "Invalid API key".to_string())?;
        ApiKeyInfo {
            id: api_key.id,
            user_id: api_key.user_id,
            key_hash: api_key.key_hash,
            scopes: api_key.scopes,
            expires_at: api_key.expires_at,
        }
    };
    #[cfg(feature = "diesel-async")]
    let api_key_info = {
        let api_key = diesel_db::find_api_key_by_prefix(&mut conn, prefix)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "Invalid API key".to_string())?;
        ApiKeyInfo {
            id: api_key.id,
            user_id: api_key.user_id,
            key_hash: api_key.key_hash,
            scopes: api_key.scopes,
            expires_at: api_key.expires_at.map(|t| t.and_utc().fixed_offset()),
        }
    };

    // Check expiration
    if let Some(expires_at) = api_key_info.expires_at {
        let now = chrono::Utc::now().fixed_offset();
        if expires_at < now {
            warn!(
                event = "yauth.api_key.expired",
                prefix = %prefix,
                "Expired API key used"
            );
            return Err("API key has expired".to_string());
        }
    }

    // Timing-safe comparison of the full key hash
    let computed_hash = crypto::hash_token(key);
    if !crypto::constant_time_eq(computed_hash.as_bytes(), api_key_info.key_hash.as_bytes()) {
        warn!(
            event = "yauth.api_key.invalid",
            prefix = %prefix,
            "API key secret mismatch"
        );
        return Err("Invalid API key".to_string());
    }

    // Update last_used_at (best-effort, don't fail auth if this errors)
    let now = chrono::Utc::now().fixed_offset();
    #[cfg(feature = "seaorm")]
    {
        let mut active: yauth_entity::api_keys::ActiveModel =
            yauth_entity::api_keys::Entity::find_by_id(api_key_info.id)
                .one(&state.db)
                .await
                .map_err(|e| format!("Database error: {}", e))?
                .ok_or_else(|| "API key not found".to_string())?
                .into();
        active.last_used_at = Set(Some(now));
        if let Err(e) = active.update(&state.db).await {
            tracing::error!("Failed to update API key last_used_at: {}", e);
        }
    }
    #[cfg(feature = "diesel-async")]
    {
        if let Err(e) = diesel_db::update_api_key_last_used(&mut conn, api_key_info.id, now).await {
            tracing::error!("Failed to update API key last_used_at: {}", e);
        }
    }

    // Look up the user
    #[cfg(feature = "seaorm")]
    let user_info = {
        let user = yauth_entity::users::Entity::find_by_id(api_key_info.user_id)
            .one(&state.db)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "User not found".to_string())?;
        UserInfo {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            email_verified: user.email_verified,
            role: user.role,
            banned: user.banned,
        }
    };
    #[cfg(feature = "diesel-async")]
    let user_info = {
        let user = diesel_db::find_user_by_id(&mut conn, api_key_info.user_id)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "User not found".to_string())?;
        UserInfo {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            email_verified: user.email_verified,
            role: user.role,
            banned: user.banned,
        }
    };

    if user_info.banned {
        warn!(
            event = "yauth.api_key.banned",
            user_id = %user_info.id,
            prefix = %prefix,
            "API key used by banned user"
        );
        return Err("Account suspended".to_string());
    }

    // Wire API key scopes into AuthUser
    let scopes: Option<Vec<String>> = api_key_info
        .scopes
        .and_then(|v| serde_json::from_value(v).ok());

    Ok(AuthUser {
        id: user_info.id,
        email: user_info.email,
        display_name: user_info.display_name,
        email_verified: user_info.email_verified,
        role: user_info.role,
        banned: user_info.banned,
        auth_method: AuthMethod::ApiKey,
        scopes,
    })
}
