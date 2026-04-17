//! Admin routes for OAuth2 client management: ban/unban + rotate-public-key.
//!
//! Mounted by the admin plugin when both `admin` and `oauth2-server` are
//! enabled. Each route writes an audit_log entry with the calling
//! principal (human admin or opted-in machine caller) so ops can answer
//! "who banned this client".

#![cfg(all(feature = "admin", feature = "oauth2-server"))]

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::state::YAuthState;

#[derive(Deserialize)]
pub struct BanRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct BannedClient {
    pub client_id: String,
    pub reason: Option<String>,
    pub banned_at: chrono::DateTime<Utc>,
}

fn actor_from_extensions(
    user: Option<&AuthUser>,
    machine: Option<&crate::middleware::MachineCaller>,
) -> serde_json::Value {
    if let Some(u) = user {
        return serde_json::json!({
            "actor_type": "user",
            "actor_id": u.id.to_string(),
        });
    }
    if let Some(m) = machine {
        return serde_json::json!({
            "actor_type": "machine",
            "actor_client_id": m.client_id,
        });
    }
    serde_json::json!({ "actor_type": "system" })
}

async fn write_admin_audit(
    state: &YAuthState,
    user: Option<&AuthUser>,
    machine: Option<&crate::middleware::MachineCaller>,
    event_type: &str,
    metadata: serde_json::Value,
) {
    let actor = actor_from_extensions(user, machine);
    let mut merged = metadata;
    if let (Some(obj), Some(actor_obj)) = (merged.as_object_mut(), actor.as_object()) {
        for (k, v) in actor_obj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let user_id = user.map(|u| u.id);
    state
        .write_audit_log(user_id, event_type, Some(merged), None)
        .await;
}

pub async fn ban_oauth2_client(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
    Json(req): Json<BanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let updated = state
        .repos
        .oauth2_clients
        .set_banned(
            &client_id,
            Some((req.reason.clone(), Utc::now().naive_utc())),
        )
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_ban_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Ban failed")
        })?;
    if !updated {
        return Err(api_err(StatusCode::NOT_FOUND, "Client not found"));
    }

    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_banned",
        serde_json::json!({ "target_client_id": client_id, "reason": req.reason }),
    )
    .await;

    Ok((StatusCode::OK, Json(serde_json::json!({ "banned": true }))))
}

pub async fn unban_oauth2_client(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
) -> Result<impl IntoResponse, ApiError> {
    let updated = state
        .repos
        .oauth2_clients
        .set_banned(&client_id, None)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_unban_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Unban failed")
        })?;

    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_unbanned",
        serde_json::json!({ "target_client_id": client_id, "was_banned": updated }),
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "unbanned": updated })),
    ))
}

pub async fn list_banned_clients(
    State(state): State<YAuthState>,
) -> Result<Json<Vec<BannedClient>>, ApiError> {
    let rows = state
        .repos
        .oauth2_clients
        .list_banned()
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_list_banned_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "List failed")
        })?;
    Ok(Json(
        rows.into_iter()
            .filter_map(|c| {
                c.banned_at.map(|at| BannedClient {
                    client_id: c.client_id,
                    reason: c.banned_reason,
                    banned_at: at.and_utc(),
                })
            })
            .collect(),
    ))
}

#[cfg(feature = "asymmetric-jwt")]
#[derive(Deserialize)]
pub struct RotateKeyRequest {
    pub public_key_pem: String,
}

#[cfg(feature = "asymmetric-jwt")]
pub async fn rotate_public_key(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    crate::auth::client_keys::ClientKey::from_pem(&req.public_key_pem)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e))?;
    let key_source = if req.public_key_pem.contains("BEGIN PUBLIC KEY") {
        "spki_pem"
    } else {
        "pem"
    };

    let updated = state
        .repos
        .oauth2_clients
        .rotate_public_key(&client_id, Some(req.public_key_pem.clone()))
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_rotate_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Rotate failed")
        })?;
    if !updated {
        return Err(api_err(StatusCode::NOT_FOUND, "Client not found"));
    }

    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_public_key_rotated",
        serde_json::json!({ "target_client_id": client_id, "key_source": key_source }),
    )
    .await;

    Ok((StatusCode::OK, Json(serde_json::json!({ "rotated": true }))))
}
