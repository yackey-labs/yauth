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
use crate::state::{BannedClientInfo, YAuthState};

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

/// Audit actor: either a human admin or a machine caller admitted via
/// `allow_machine_callers`. Embedded in the audit_log `metadata` JSON so the
/// event is traceable without a schema change.
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
    let client = state
        .repos
        .oauth2_clients
        .find_by_client_id(&client_id)
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Lookup failed"))?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Client not found"))?;

    let _ = client;
    state
        .banned_clients
        .write()
        .expect("banned_clients poisoned")
        .insert(
            client_id.clone(),
            BannedClientInfo {
                reason: req.reason.clone(),
                banned_at: Utc::now(),
            },
        );

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
    let removed = state
        .banned_clients
        .write()
        .expect("banned_clients poisoned")
        .remove(&client_id)
        .is_some();

    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_unbanned",
        serde_json::json!({ "target_client_id": client_id, "was_banned": removed }),
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "unbanned": removed })),
    ))
}

pub async fn list_banned_clients(State(state): State<YAuthState>) -> Json<Vec<BannedClient>> {
    let registry = state
        .banned_clients
        .read()
        .expect("banned_clients poisoned");
    let mut out: Vec<BannedClient> = registry
        .iter()
        .map(|(client_id, info)| BannedClient {
            client_id: client_id.clone(),
            reason: info.reason.clone(),
            banned_at: info.banned_at,
        })
        .collect();
    out.sort_by(|a, b| b.banned_at.cmp(&a.banned_at));
    Json(out)
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
    let new_key = crate::auth::client_keys::ClientKey::from_pem(&req.public_key_pem)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e))?;
    let key_source = if req.public_key_pem.contains("BEGIN PUBLIC KEY") {
        "spki_pem"
    } else {
        "pem"
    };

    let existed = {
        let mut keys = state.client_keys.write().expect("client_keys poisoned");
        let existed = keys.contains_key(&client_id);
        keys.insert(client_id.clone(), new_key);
        existed
    };
    if !existed {
        return Err(api_err(
            StatusCode::NOT_FOUND,
            "Client is not registered for private_key_jwt",
        ));
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
