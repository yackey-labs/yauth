use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
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

    fn schema(&self) -> Vec<crate::schema::TableDef> {
        crate::schema::plugin_schemas::api_key_schema()
    }
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<u32>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub prefix: String,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    pub created_at: chrono::DateTime<chrono::FixedOffset>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

    let now = chrono::Utc::now().naive_utc();

    let expires_at = input
        .expires_in_days
        .map(|days| (chrono::Utc::now() + chrono::Duration::days(i64::from(days))).naive_utc());

    let scopes_json = input.scopes.as_ref().map(|s| serde_json::json!(s));

    let api_key_id = Uuid::now_v7();

    let new_key = crate::domain::NewApiKey {
        id: api_key_id,
        user_id: user.id,
        key_prefix: prefix.clone(),
        key_hash,
        name: name.clone(),
        scopes: scopes_json,
        expires_at,
        created_at: now,
    };

    state.repos.api_keys.create(new_key).await.map_err(|e| {
        crate::otel::record_error("api_key_create_failed", &e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    crate::otel::add_event(
        "api_key_created",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user.id.to_string()),
            opentelemetry::KeyValue::new("key.id", api_key_id.to_string()),
            opentelemetry::KeyValue::new("key.prefix", prefix.clone()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user.id),
            "api_key_created",
            Some(serde_json::json!({ "key_id": api_key_id, "name": name, "prefix": prefix })),
            None,
        )
        .await;

    let expires_at_fixed = expires_at.map(|t| t.and_utc().fixed_offset());
    let created_at_fixed = now.and_utc().fixed_offset();

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id: api_key_id,
            key: full_key,
            name,
            prefix,
            scopes: input.scopes,
            expires_at: expires_at_fixed,
            created_at: created_at_fixed,
        }),
    ))
}

async fn list_api_keys(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<ApiKeyResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let keys = state
        .repos
        .api_keys
        .list_by_user_id(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("api_key_list_failed", &e);
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
                last_used_at: k.last_used_at.map(|t| t.and_utc().fixed_offset()),
                expires_at: k.expires_at.map(|t| t.and_utc().fixed_offset()),
                created_at: k.created_at.and_utc().fixed_offset(),
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

    let key = state
        .repos
        .api_keys
        .find_by_id_and_user(id, user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("api_key_find_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let key = key.ok_or_else(|| err(StatusCode::NOT_FOUND, "API key not found"))?;

    state.repos.api_keys.delete(key.id).await.map_err(|e| {
        crate::otel::record_error("api_key_delete_failed", &e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    crate::otel::add_event(
        "api_key_deleted",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user.id.to_string()),
            opentelemetry::KeyValue::new("key.id", id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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

    // Look up by prefix
    let api_key = state
        .repos
        .api_keys
        .find_by_prefix(prefix)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Invalid API key".to_string())?;

    // Check expiration (repo should already filter expired keys, but double-check)
    if let Some(expires_at) = api_key.expires_at {
        let now = chrono::Utc::now().naive_utc();
        if expires_at < now {
            crate::otel::add_event(
                "api_key_expired",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new(
                    "key.prefix",
                    prefix.to_string(),
                )],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return Err("API key has expired".to_string());
        }
    }

    // Timing-safe comparison of the full key hash
    let computed_hash = crypto::hash_token(key);
    if !crypto::constant_time_eq(computed_hash.as_bytes(), api_key.key_hash.as_bytes()) {
        crate::otel::add_event(
            "api_key_secret_mismatch",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new(
                "key.prefix",
                prefix.to_string(),
            )],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err("Invalid API key".to_string());
    }

    // Update last_used_at (best-effort, don't fail auth if this errors)
    if let Err(e) = state.repos.api_keys.update_last_used(api_key.id).await {
        crate::otel::record_error("api_key_last_used_update_failed", &e);
    }

    // Look up the user
    let user = state
        .repos
        .users
        .find_by_id(api_key.user_id)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "User not found".to_string())?;

    if user.banned {
        crate::otel::add_event(
            "api_key_banned_user",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("user.id", user.id.to_string()),
                opentelemetry::KeyValue::new("key.prefix", prefix.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err("Account suspended".to_string());
    }

    // Wire API key scopes into AuthUser
    let scopes: Option<Vec<String>> = api_key.scopes.and_then(|v| serde_json::from_value(v).ok());

    Ok(AuthUser {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        email_verified: user.email_verified,
        role: user.role,
        banned: user.banned,
        auth_method: AuthMethod::ApiKey,
        scopes,
    })
}
