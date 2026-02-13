use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::crypto;
use crate::middleware::{AuthMethod, AuthUser};
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

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

    info!(
        event = "api_key_created",
        user_id = %user.id,
        key_id = %api_key_id,
        prefix = %prefix,
        "API key created"
    );

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

    let keys = yauth_entity::api_keys::Entity::find()
        .filter(yauth_entity::api_keys::Column::UserId.eq(user.id))
        .all(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list API keys: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let response: Vec<ApiKeyResponse> = keys
        .into_iter()
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
        .collect();

    Ok(Json(response))
}

async fn delete_api_key(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

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

    info!(
        event = "api_key_deleted",
        user_id = %user.id,
        key_id = %id,
        "API key deleted"
    );

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

    // Look up by prefix
    let api_key = yauth_entity::api_keys::Entity::find()
        .filter(yauth_entity::api_keys::Column::KeyPrefix.eq(prefix))
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Invalid API key".to_string())?;

    // Check expiration
    if let Some(expires_at) = api_key.expires_at {
        let now = chrono::Utc::now().fixed_offset();
        if expires_at < now {
            warn!(
                event = "api_key_expired",
                prefix = %prefix,
                "Expired API key used"
            );
            return Err("API key has expired".to_string());
        }
    }

    // Timing-safe comparison of the full key hash
    let computed_hash = crypto::hash_token(key);
    if !crypto::constant_time_eq(computed_hash.as_bytes(), api_key.key_hash.as_bytes()) {
        warn!(
            event = "api_key_invalid_secret",
            prefix = %prefix,
            "API key secret mismatch"
        );
        return Err("Invalid API key".to_string());
    }

    // Update last_used_at (best-effort, don't fail auth if this errors)
    let now = chrono::Utc::now().fixed_offset();
    let mut active: yauth_entity::api_keys::ActiveModel = api_key.clone().into();
    active.last_used_at = Set(Some(now));
    if let Err(e) = active.update(&state.db).await {
        tracing::error!("Failed to update API key last_used_at: {}", e);
    }

    // Look up the user
    let user = yauth_entity::users::Entity::find_by_id(api_key.user_id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "User not found".to_string())?;

    if user.banned {
        warn!(
            event = "api_key_banned_user",
            user_id = %user.id,
            prefix = %prefix,
            "API key used by banned user"
        );
        return Err("Account suspended".to_string());
    }

    Ok(AuthUser {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        email_verified: user.email_verified,
        role: user.role,
        banned: user.banned,
        auth_method: AuthMethod::ApiKey,
    })
}
