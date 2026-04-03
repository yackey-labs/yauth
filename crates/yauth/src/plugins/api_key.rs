use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::crypto;
use crate::db::models::{ApiKey, NewApiKey};
use crate::db::schema::yauth_api_keys;
use crate::middleware::{AuthMethod, AuthUser};
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

type Conn = diesel_async_crate::AsyncPgConnection;
type DbResult<T> = Result<T, String>;

#[allow(clippy::too_many_arguments)]
async fn db_insert_api_key(
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
    let new_key = NewApiKey {
        id,
        user_id,
        key_prefix: key_prefix.to_string(),
        key_hash: key_hash.to_string(),
        name: name.to_string(),
        scopes,
        expires_at: expires_at.map(|t| t.naive_utc()),
        created_at: created_at.naive_utc(),
    };
    diesel::insert_into(yauth_api_keys::table)
        .values(&new_key)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_list_api_keys_by_user(conn: &mut Conn, user_id: Uuid) -> DbResult<Vec<ApiKey>> {
    // No pagination — API key count per user is naturally small
    yauth_api_keys::table
        .filter(yauth_api_keys::user_id.eq(user_id))
        .order(yauth_api_keys::created_at.desc())
        .select(ApiKey::as_select())
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

async fn db_find_api_key_by_id_and_user(
    conn: &mut Conn,
    id: Uuid,
    user_id: Uuid,
) -> DbResult<Option<ApiKey>> {
    yauth_api_keys::table
        .filter(
            yauth_api_keys::id
                .eq(id)
                .and(yauth_api_keys::user_id.eq(user_id)),
        )
        .select(ApiKey::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_delete_api_key(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::delete(yauth_api_keys::table.filter(yauth_api_keys::id.eq(id)))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_find_api_key_by_prefix(conn: &mut Conn, prefix: &str) -> DbResult<Option<ApiKey>> {
    yauth_api_keys::table
        .filter(yauth_api_keys::key_prefix.eq(prefix))
        .select(ApiKey::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_update_api_key_last_used(
    conn: &mut Conn,
    id: Uuid,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    diesel::update(yauth_api_keys::table.filter(yauth_api_keys::id.eq(id)))
        .set(yauth_api_keys::last_used_at.eq(now.naive_utc()))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

use crate::db::find_user_by_id;

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

    let now = chrono::Utc::now().fixed_offset();

    let expires_at = input
        .expires_in_days
        .map(|days| (chrono::Utc::now() + chrono::Duration::days(i64::from(days))).fixed_offset());

    let scopes_json = input.scopes.as_ref().map(|s| serde_json::json!(s));

    let api_key_id = Uuid::new_v4();

    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        db_insert_api_key(
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
            crate::otel::record_error("api_key_create_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }

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

    let response: Vec<ApiKeyResponse> = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let keys = db_list_api_keys_by_user(&mut conn, user.id)
            .await
            .map_err(|e| {
                crate::otel::record_error("api_key_list_failed", &e);
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

    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let key = db_find_api_key_by_id_and_user(&mut conn, id, user.id)
            .await
            .map_err(|e| {
                crate::otel::record_error("api_key_find_failed", &e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let key = key.ok_or_else(|| err(StatusCode::NOT_FOUND, "API key not found"))?;

        db_delete_api_key(&mut conn, key.id).await.map_err(|e| {
            crate::otel::record_error("api_key_delete_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }

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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|e| format!("Pool error: {}", e))?;

    // Look up by prefix
    let api_key = db_find_api_key_by_prefix(&mut conn, prefix)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Invalid API key".to_string())?;

    // Check expiration
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
    let now = chrono::Utc::now().fixed_offset();
    {
        if let Err(e) = db_update_api_key_last_used(&mut conn, api_key.id, now).await {
            crate::otel::record_error("api_key_last_used_update_failed", &e);
        }
    }

    // Look up the user
    let user = find_user_by_id(&mut conn, api_key.user_id)
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
