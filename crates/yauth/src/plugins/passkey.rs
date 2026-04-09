use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::*;

use crate::auth::session;
use crate::config::PasskeyConfig;
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

use std::sync::Arc;

const CHALLENGE_TTL_SECS: u64 = 300; // 5 minutes

pub struct PasskeyPlugin {
    webauthn: Arc<Webauthn>,
}

impl PasskeyPlugin {
    pub fn new(config: PasskeyConfig, _state: &YAuthState) -> Self {
        let rp_id = config.rp_id.clone();
        let rp_origin = Url::parse(&config.rp_origin).expect("Invalid passkey rp_origin URL");
        let builder = webauthn_rs::WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("Failed to create WebauthnBuilder")
            .rp_name(&config.rp_name);

        let webauthn = Arc::new(builder.build().expect("Failed to build Webauthn"));
        Self { webauthn }
    }
}

impl YAuthPlugin for PasskeyPlugin {
    fn name(&self) -> &'static str {
        "passkey"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        let webauthn = self.webauthn.clone();
        Some(
            Router::new()
                .route(
                    "/passkey/login/begin",
                    post({
                        let wn = webauthn.clone();
                        move |state: State<YAuthState>, body: Json<PasskeyLoginBeginRequest>| {
                            login_begin(state, body, wn)
                        }
                    }),
                )
                .route(
                    "/passkey/login/finish",
                    post({
                        let wn = webauthn.clone();
                        move |state: State<YAuthState>, body: Json<PasskeyLoginFinishRequest>| {
                            login_finish(state, body, wn)
                        }
                    }),
                ),
        )
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        let webauthn = self.webauthn.clone();
        Some(
            Router::new()
                .route(
                    "/passkeys/register/begin",
                    post({
                        let wn = webauthn.clone();
                        move |state: State<YAuthState>, user: Extension<AuthUser>| {
                            register_begin(state, user, wn)
                        }
                    }),
                )
                .route(
                    "/passkeys/register/finish",
                    post({
                        let wn = webauthn.clone();
                        move |state: State<YAuthState>,
                              user: Extension<AuthUser>,
                              body: Json<RegisterFinishRequest>| {
                            register_finish(state, user, body, wn)
                        }
                    }),
                )
                .route("/passkeys", get(list_passkeys))
                .route("/passkeys/{id}", delete(delete_passkey)),
        )
    }
}

use crate::auth::session::session_set_cookie;

// --- Registration ---

async fn register_begin(
    State(state): State<YAuthState>,
    Extension(auth_user): Extension<AuthUser>,
    webauthn: Arc<Webauthn>,
) -> Result<impl IntoResponse, ApiError> {
    let user = state
        .repos
        .users
        .find_by_id(auth_user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    let existing_creds = state
        .repos
        .passkeys
        .find_by_user_id(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let existing_passkeys: Vec<Passkey> = existing_creds
        .into_iter()
        .filter_map(|c| serde_json::from_value(c.credential).ok())
        .collect();

    let exclude_opt = if existing_passkeys.is_empty() {
        None
    } else {
        Some(
            existing_passkeys
                .iter()
                .map(|p| p.cred_id().clone())
                .collect(),
        )
    };

    let display_name = user.display_name.as_deref().unwrap_or(&user.email);
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user.id, &user.email, display_name, exclude_opt)
        .map_err(|e| {
            crate::otel::record_error("passkey_registration_start_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "WebAuthn error")
        })?;

    let reg_state_json = serde_json::to_value(&reg_state).map_err(|e| {
        crate::otel::record_error("serialize_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let challenge_key = format!("passkey_reg:{}", user.id);
    state
        .repos
        .challenges
        .set_challenge(&challenge_key, reg_state_json, CHALLENGE_TTL_SECS)
        .await
        .map_err(|e| {
            crate::otel::record_error("passkey_challenge_repo_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    Ok(Json(ccr))
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegisterFinishRequest {
    pub name: String,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub credential: RegisterPublicKeyCredential,
}

async fn register_finish(
    State(state): State<YAuthState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(input): Json<RegisterFinishRequest>,
    webauthn: Arc<Webauthn>,
) -> Result<impl IntoResponse, ApiError> {
    let challenge_key = format!("passkey_reg:{}", auth_user.id);
    let reg_state_json = state
        .repos
        .challenges
        .get_challenge(&challenge_key)
        .await
        .map_err(|e| {
            crate::otel::record_error("passkey_challenge_repo_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "No pending registration"))?;

    let _ = state
        .repos
        .challenges
        .delete_challenge(&challenge_key)
        .await;

    let reg_state: PasskeyRegistration = serde_json::from_value(reg_state_json).map_err(|e| {
        crate::otel::record_error("deserialize_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let passkey = webauthn
        .finish_passkey_registration(&input.credential, &reg_state)
        .map_err(|e| {
            crate::otel::record_error("passkey_registration_finish_error", &e);
            api_err(StatusCode::BAD_REQUEST, "Registration verification failed")
        })?;

    let credential_json = serde_json::to_value(&passkey).map_err(|e| {
        crate::otel::record_error("serialize_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let passkey_name = input.name;

    let new_cred = crate::domain::NewWebauthnCredential {
        id: Uuid::now_v7(),
        user_id: auth_user.id,
        name: passkey_name.clone(),
        aaguid: None,
        device_name: None,
        credential: credential_json,
        created_at: chrono::Utc::now().naive_utc(),
    };

    state.repos.passkeys.create(new_cred).await.map_err(|e| {
        crate::otel::record_error("passkey_credential_save_failed", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    crate::otel::add_event(
        "passkey_registered",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new(
            "user.id",
            auth_user.id.to_string(),
        )],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(auth_user.id),
            "passkey_registered",
            Some(serde_json::json!({ "name": passkey_name })),
            None,
        )
        .await;

    Ok(StatusCode::CREATED)
}

// --- Authentication ---

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PasskeyLoginBeginRequest {
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Serialize)]
pub struct PasskeyLoginBeginResponse {
    pub challenge_id: Uuid,
    pub options: RequestChallengeResponse,
}

async fn login_begin(
    State(state): State<YAuthState>,
    Json(input): Json<PasskeyLoginBeginRequest>,
    webauthn: Arc<Webauthn>,
) -> Result<Json<PasskeyLoginBeginResponse>, ApiError> {
    let challenge_id = Uuid::now_v7();

    let (rcr, challenge_data) = if let Some(ref email_raw) = input.email {
        let email = email_raw.trim().to_lowercase();

        if !state
            .repos
            .rate_limits
            .check_rate_limit(&format!("passkey_login:{}", email), 10, 60)
            .await
            .map(|r| r.allowed)
            .unwrap_or(true)
        {
            crate::otel::add_event(
                "passkey_login_rate_limited",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new("user.email", email.clone())],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
        }

        let user = state
            .repos
            .users
            .find_by_email(&email)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| {
                api_err(
                    StatusCode::BAD_REQUEST,
                    "No passkeys registered for this email",
                )
            })?;

        let creds = state
            .repos
            .passkeys
            .find_by_user_id(user.id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        if creds.is_empty() {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "No passkeys registered for this email",
            ));
        }

        let passkeys: Vec<Passkey> = creds
            .into_iter()
            .filter_map(|c| serde_json::from_value(c.credential).ok())
            .collect();

        if passkeys.is_empty() {
            return Err(api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to deserialize credentials",
            ));
        }

        let (rcr, auth_state) = webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| {
                crate::otel::record_error("passkey_auth_start_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "WebAuthn error")
            })?;

        let auth_state_json = serde_json::to_value(&auth_state).map_err(|e| {
            crate::otel::record_error("serialize_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        let data = serde_json::json!({
            "discoverable": false,
            "user_id": user.id,
            "auth_state": auth_state_json,
        });

        (rcr, data)
    } else {
        if !state
            .repos
            .rate_limits
            .check_rate_limit("passkey_login:discoverable", 10, 60)
            .await
            .map(|r| r.allowed)
            .unwrap_or(true)
        {
            crate::otel::add_event("passkey_discoverable_login_rate_limited", vec![]);
            return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
        }

        let (rcr, auth_state) = webauthn.start_discoverable_authentication().map_err(|e| {
            crate::otel::record_error("passkey_discoverable_auth_start_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "WebAuthn error")
        })?;

        let auth_state_json = serde_json::to_value(&auth_state).map_err(|e| {
            crate::otel::record_error("serialize_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        let data = serde_json::json!({
            "discoverable": true,
            "auth_state": auth_state_json,
        });

        (rcr, data)
    };

    let challenge_key = format!("passkey_auth:{}", challenge_id);
    state
        .repos
        .challenges
        .set_challenge(&challenge_key, challenge_data, CHALLENGE_TTL_SECS)
        .await
        .map_err(|e| {
            crate::otel::record_error("passkey_challenge_repo_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    Ok(Json(PasskeyLoginBeginResponse {
        challenge_id,
        options: rcr,
    }))
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PasskeyLoginFinishRequest {
    pub challenge_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub credential: PublicKeyCredential,
}

async fn login_finish(
    State(state): State<YAuthState>,
    Json(input): Json<PasskeyLoginFinishRequest>,
    webauthn: Arc<Webauthn>,
) -> Result<impl IntoResponse, ApiError> {
    let challenge_key = format!("passkey_auth:{}", input.challenge_id);
    let challenge_data = state
        .repos
        .challenges
        .get_challenge(&challenge_key)
        .await
        .map_err(|e| {
            crate::otel::record_error("passkey_challenge_repo_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "No pending authentication"))?;

    let _ = state
        .repos
        .challenges
        .delete_challenge(&challenge_key)
        .await;

    let discoverable = challenge_data
        .get("discoverable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let auth_state_json = challenge_data
        .get("auth_state")
        .cloned()
        .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    let user_id = if discoverable {
        let auth_state: DiscoverableAuthentication = serde_json::from_value(auth_state_json)
            .map_err(|e| {
                crate::otel::record_error("deserialize_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let (uid, _cred_id) = webauthn
            .identify_discoverable_authentication(&input.credential)
            .map_err(|e| {
                crate::otel::record_error("passkey_identify_error", &e);
                api_err(StatusCode::UNAUTHORIZED, "Authentication failed")
            })?;

        let creds = state
            .repos
            .passkeys
            .find_by_user_id(uid)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        if creds.is_empty() {
            return Err(api_err(StatusCode::UNAUTHORIZED, "Authentication failed"));
        }

        let passkeys: Vec<Passkey> = creds
            .into_iter()
            .filter_map(|c| serde_json::from_value(c.credential).ok())
            .collect();

        let discoverable_keys: Vec<DiscoverableKey> =
            passkeys.into_iter().map(DiscoverableKey::from).collect();

        let _auth_result = webauthn
            .finish_discoverable_authentication(&input.credential, auth_state, &discoverable_keys)
            .map_err(|e| {
                crate::otel::record_error("passkey_discoverable_auth_finish_error", &e);
                api_err(StatusCode::UNAUTHORIZED, "Authentication failed")
            })?;

        uid
    } else {
        let user_id: Uuid = serde_json::from_value(
            challenge_data
                .get("user_id")
                .cloned()
                .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?,
        )
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        let auth_state: PasskeyAuthentication =
            serde_json::from_value(auth_state_json).map_err(|e| {
                crate::otel::record_error("deserialize_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let _auth_result = webauthn
            .finish_passkey_authentication(&input.credential, &auth_state)
            .map_err(|e| {
                crate::otel::record_error("passkey_auth_finish_error", &e);
                api_err(StatusCode::UNAUTHORIZED, "Authentication failed")
            })?;

        user_id
    };

    // Update last_used_at (best-effort)
    let _ = state.repos.passkeys.update_last_used(user_id).await;

    let (token, _session_id) =
        session::create_session(&state, user_id, None, None, state.config.session_ttl)
            .await
            .map_err(|e| {
                crate::otel::record_error("session_create_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

    let user = state
        .repos
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "User not found"))?;

    crate::otel::add_event(
        "passkey_login_succeeded",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user.id.to_string()),
            opentelemetry::KeyValue::new("user.email", user.email.clone()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user.id),
            "login_succeeded",
            Some(serde_json::json!({ "method": "passkey" })),
            None,
        )
        .await;

    Ok((
        [(
            SET_COOKIE,
            session_set_cookie(&state, &token, state.config.session_ttl),
        )],
        Json(serde_json::json!({
            "user_id": user.id.to_string(),
            "email": user.email,
            "display_name": user.display_name,
            "email_verified": user.email_verified,
        })),
    ))
}

// --- Passkey Management ---

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PasskeyInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::FixedOffset>,
    pub last_used_at: Option<chrono::DateTime<chrono::FixedOffset>>,
}

async fn list_passkeys(
    State(state): State<YAuthState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<PasskeyInfo>>, ApiError> {
    let creds = state
        .repos
        .passkeys
        .find_by_user_id(auth_user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let passkeys = creds
        .into_iter()
        .map(|c| {
            use chrono::TimeZone;
            PasskeyInfo {
                id: c.id,
                name: c.name,
                created_at: chrono::Utc.from_utc_datetime(&c.created_at).fixed_offset(),
                last_used_at: c
                    .last_used_at
                    .map(|dt| chrono::Utc.from_utc_datetime(&dt).fixed_offset()),
            }
        })
        .collect::<Vec<_>>();

    Ok(Json(passkeys))
}

async fn delete_passkey(
    State(state): State<YAuthState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let cred = state
        .repos
        .passkeys
        .find_by_id_and_user(id, auth_user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Passkey not found"))?;

    state.repos.passkeys.delete(cred.id).await.map_err(|e| {
        crate::otel::record_error("passkey_delete_failed", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    crate::otel::add_event(
        "passkey_deleted",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", auth_user.id.to_string()),
            opentelemetry::KeyValue::new("passkey.id", id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(auth_user.id),
            "passkey_deleted",
            Some(serde_json::json!({ "passkey_id": id })),
            None,
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}
