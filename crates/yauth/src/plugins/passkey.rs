use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::{delete, get, post},
};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::*;

use crate::auth::session;
use crate::config::PasskeyConfig;
use crate::db::models::{NewWebauthnCredential, User, WebauthnCredential};
use crate::db::schema::{yauth_users, yauth_webauthn_credentials};
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

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

type Conn = diesel_async_crate::AsyncPgConnection;
type DbResult<T> = Result<T, String>;

async fn db_find_user_by_id(conn: &mut Conn, id: Uuid) -> DbResult<Option<User>> {
    yauth_users::table
        .find(id)
        .select(User::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_find_user_by_email(conn: &mut Conn, email: &str) -> DbResult<Option<User>> {
    yauth_users::table
        .filter(yauth_users::email.eq(email))
        .select(User::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_find_credentials_by_user(
    conn: &mut Conn,
    user_id: Uuid,
) -> DbResult<Vec<WebauthnCredential>> {
    yauth_webauthn_credentials::table
        .filter(yauth_webauthn_credentials::user_id.eq(user_id))
        .select(WebauthnCredential::as_select())
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

async fn db_insert_credential(
    conn: &mut Conn,
    id: Uuid,
    user_id: Uuid,
    name: &str,
    credential: &serde_json::Value,
) -> DbResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let new_cred = NewWebauthnCredential {
        id,
        user_id,
        name: name.to_string(),
        aaguid: None,
        device_name: None,
        credential: credential.clone(),
        created_at: now,
    };
    diesel::insert_into(yauth_webauthn_credentials::table)
        .values(&new_cred)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_update_credentials_last_used(conn: &mut Conn, user_id: Uuid) -> DbResult<()> {
    diesel::update(
        yauth_webauthn_credentials::table.filter(yauth_webauthn_credentials::user_id.eq(user_id)),
    )
    .set(yauth_webauthn_credentials::last_used_at.eq(chrono::Utc::now().naive_utc()))
    .execute(conn)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_find_credential_by_id_and_user(
    conn: &mut Conn,
    id: Uuid,
    user_id: Uuid,
) -> DbResult<Option<WebauthnCredential>> {
    yauth_webauthn_credentials::table
        .filter(
            yauth_webauthn_credentials::id
                .eq(id)
                .and(yauth_webauthn_credentials::user_id.eq(user_id)),
        )
        .select(WebauthnCredential::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_delete_credential(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::delete(yauth_webauthn_credentials::table.filter(yauth_webauthn_credentials::id.eq(id)))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

// --- Registration ---

async fn register_begin(
    State(state): State<YAuthState>,
    Extension(auth_user): Extension<AuthUser>,
    webauthn: Arc<Webauthn>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut conn = state.db.get().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error".to_string(),
        )
    })?;

    let user = db_find_user_by_id(&mut conn, auth_user.id)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // Get existing credentials to exclude
    let existing_passkeys: Vec<Passkey> = {
        let existing_creds = db_find_credentials_by_user(&mut conn, user.id)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;
        existing_creds
            .into_iter()
            .filter_map(|c| serde_json::from_value(c.credential).ok())
            .collect()
    };

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
            tracing::error!("WebAuthn registration start error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "WebAuthn error".to_string(),
            )
        })?;

    // Store registration state in challenge store
    let reg_state_json = serde_json::to_value(&reg_state).map_err(|e| {
        tracing::error!("Serialize error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error".to_string(),
        )
    })?;

    let challenge_key = format!("passkey_reg:{}", user.id);
    state
        .challenge_store
        .set(&challenge_key, reg_state_json, CHALLENGE_TTL_SECS)
        .await
        .map_err(|e| {
            tracing::error!("Challenge store error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;

    Ok(Json(ccr))
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegisterFinishRequest {
    pub name: String,
    #[schema(value_type = Object)]
    pub credential: RegisterPublicKeyCredential,
}

async fn register_finish(
    State(state): State<YAuthState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(input): Json<RegisterFinishRequest>,
    webauthn: Arc<Webauthn>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let challenge_key = format!("passkey_reg:{}", auth_user.id);
    let reg_state_json = state
        .challenge_store
        .get(&challenge_key)
        .await
        .map_err(|e| {
            tracing::error!("Challenge store error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            "No pending registration".to_string(),
        ))?;

    // Clean up challenge
    let _ = state.challenge_store.delete(&challenge_key).await;

    let reg_state: PasskeyRegistration = serde_json::from_value(reg_state_json).map_err(|e| {
        tracing::error!("Deserialize error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error".to_string(),
        )
    })?;

    let passkey = webauthn
        .finish_passkey_registration(&input.credential, &reg_state)
        .map_err(|e| {
            tracing::error!("WebAuthn registration finish error: {}", e);
            (
                StatusCode::BAD_REQUEST,
                "Registration verification failed".to_string(),
            )
        })?;

    let credential_json = serde_json::to_value(&passkey).map_err(|e| {
        tracing::error!("Serialize error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error".to_string(),
        )
    })?;

    let passkey_name = input.name;

    {
        let mut conn = state.db.get().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;
        db_insert_credential(
            &mut conn,
            Uuid::new_v4(),
            auth_user.id,
            &passkey_name,
            &credential_json,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to save credential: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;
    }

    info!(event = "yauth.passkey.registered", user_id = %auth_user.id, "Passkey registered");

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
) -> Result<Json<PasskeyLoginBeginResponse>, (StatusCode, String)> {
    let challenge_id = Uuid::new_v4();

    let mut conn = state.db.get().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error".to_string(),
        )
    })?;

    let (rcr, challenge_data) = if let Some(ref email_raw) = input.email {
        // --- Email-based flow ---
        let email = email_raw.trim().to_lowercase();

        if !state
            .rate_limiter
            .check(&format!("passkey_login:{}", email))
            .await
        {
            warn!(event = "yauth.passkey.login.rate_limited", email = %email, "Passkey login rate limited");
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests".to_string(),
            ));
        }

        let user = {
            db_find_user_by_email(&mut conn, &email)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error".to_string(),
                    )
                })?
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "No passkeys registered for this email".to_string(),
                ))?
        };

        let creds: Vec<WebauthnCredential> = {
            db_find_credentials_by_user(&mut conn, user.id)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error".to_string(),
                    )
                })?
        };

        if creds.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "No passkeys registered for this email".to_string(),
            ));
        }

        let passkeys: Vec<Passkey> = creds
            .into_iter()
            .filter_map(|c| serde_json::from_value(c.credential).ok())
            .collect();

        if passkeys.is_empty() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to deserialize credentials".to_string(),
            ));
        }

        let (rcr, auth_state) = webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| {
                tracing::error!("WebAuthn auth start error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "WebAuthn error".to_string(),
                )
            })?;

        let auth_state_json = serde_json::to_value(&auth_state).map_err(|e| {
            tracing::error!("Serialize error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;

        let data = serde_json::json!({
            "discoverable": false,
            "user_id": user.id,
            "auth_state": auth_state_json,
        });

        (rcr, data)
    } else {
        // --- Discoverable (usernameless) flow ---
        if !state.rate_limiter.check("passkey_login:discoverable").await {
            warn!(
                event = "yauth.passkey.login.rate_limited",
                "Discoverable passkey login rate limited"
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests".to_string(),
            ));
        }

        let (rcr, auth_state) = webauthn.start_discoverable_authentication().map_err(|e| {
            tracing::error!("WebAuthn discoverable auth start error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "WebAuthn error".to_string(),
            )
        })?;

        let auth_state_json = serde_json::to_value(&auth_state).map_err(|e| {
            tracing::error!("Serialize error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;

        let data = serde_json::json!({
            "discoverable": true,
            "auth_state": auth_state_json,
        });

        (rcr, data)
    };

    let challenge_key = format!("passkey_auth:{}", challenge_id);
    state
        .challenge_store
        .set(&challenge_key, challenge_data, CHALLENGE_TTL_SECS)
        .await
        .map_err(|e| {
            tracing::error!("Challenge store error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
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
    #[schema(value_type = Object)]
    pub credential: PublicKeyCredential,
}

async fn login_finish(
    State(state): State<YAuthState>,
    Json(input): Json<PasskeyLoginFinishRequest>,
    webauthn: Arc<Webauthn>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let challenge_key = format!("passkey_auth:{}", input.challenge_id);
    let challenge_data = state
        .challenge_store
        .get(&challenge_key)
        .await
        .map_err(|e| {
            tracing::error!("Challenge store error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?
        .ok_or((
            StatusCode::BAD_REQUEST,
            "No pending authentication".to_string(),
        ))?;

    // Clean up challenge
    let _ = state.challenge_store.delete(&challenge_key).await;

    let discoverable = challenge_data
        .get("discoverable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let auth_state_json = challenge_data.get("auth_state").cloned().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal error".to_string(),
    ))?;

    let mut conn = state.db.get().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error".to_string(),
        )
    })?;

    let user_id = if discoverable {
        // --- Discoverable flow ---
        let auth_state: DiscoverableAuthentication = serde_json::from_value(auth_state_json)
            .map_err(|e| {
                tracing::error!("Deserialize error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;

        // Identify which user owns this credential
        let (uid, _cred_id) = webauthn
            .identify_discoverable_authentication(&input.credential)
            .map_err(|e| {
                tracing::error!("WebAuthn identify error: {}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    "Authentication failed".to_string(),
                )
            })?;

        // Load user's passkeys from DB
        let creds = db_find_credentials_by_user(&mut conn, uid)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;
        if creds.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Authentication failed".to_string(),
            ));
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
                tracing::error!("WebAuthn discoverable auth finish error: {}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    "Authentication failed".to_string(),
                )
            })?;

        uid
    } else {
        // --- Email-based flow ---
        let user_id: Uuid =
            serde_json::from_value(challenge_data.get("user_id").cloned().ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            ))?)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;

        let auth_state: PasskeyAuthentication =
            serde_json::from_value(auth_state_json).map_err(|e| {
                tracing::error!("Deserialize error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;

        let _auth_result = webauthn
            .finish_passkey_authentication(&input.credential, &auth_state)
            .map_err(|e| {
                tracing::error!("WebAuthn auth finish error: {}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    "Authentication failed".to_string(),
                )
            })?;

        user_id
    };

    // Update last_used_at for credentials (best-effort)
    let _ = update_credential_last_used(&state, user_id).await;

    let (token, _session_id) =
        session::create_session(&state.db, user_id, None, None, state.config.session_ttl)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create session: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;

    let user = db_find_user_by_id(&mut conn, user_id)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    info!(event = "yauth.passkey.login", user_id = %user.id, email = %user.email, "Passkey login successful");

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

async fn update_credential_last_used(state: &YAuthState, user_id: Uuid) -> Result<(), ()> {
    let mut conn = state.db.get().await.map_err(|_| ())?;
    db_update_credentials_last_used(&mut conn, user_id)
        .await
        .map_err(|_| ())?;
    Ok(())
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
) -> Result<Json<Vec<PasskeyInfo>>, (StatusCode, String)> {
    let passkeys = {
        let mut conn = state.db.get().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;
        let creds = db_find_credentials_by_user(&mut conn, auth_user.id)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;
        creds
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
            .collect::<Vec<_>>()
    };

    Ok(Json(passkeys))
}

async fn delete_passkey(
    State(state): State<YAuthState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    {
        let mut conn = state.db.get().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;
        let cred = db_find_credential_by_id_and_user(&mut conn, id, auth_user.id)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?
            .ok_or((StatusCode::NOT_FOUND, "Passkey not found".to_string()))?;

        db_delete_credential(&mut conn, cred.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete passkey: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;
    }

    info!(event = "yauth.passkey.deleted", user_id = %auth_user.id, passkey_id = %id, "Passkey deleted");

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
