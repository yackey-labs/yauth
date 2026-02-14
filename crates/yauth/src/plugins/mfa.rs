use axum::{
    Extension, Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::{delete, get, post},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ts_rs::TS;
use uuid::Uuid;

use totp_rs::{Algorithm, Secret, TOTP};

use crate::auth::{crypto, session};
use crate::config::MfaConfig;
use crate::middleware::AuthUser;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

pub struct MfaPlugin;

impl MfaPlugin {
    pub fn new(_config: MfaConfig) -> Self {
        // Config is stored in YAuthState for handler access
        Self
    }
}

impl YAuthPlugin for MfaPlugin {
    fn name(&self) -> &'static str {
        "mfa"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(Router::new().route("/mfa/verify", post(verify_mfa)))
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/mfa/totp/setup", post(setup_totp))
                .route("/mfa/totp/confirm", post(confirm_totp))
                .route("/mfa/totp", delete(disable_totp))
                .route("/mfa/backup-codes", get(get_backup_code_count))
                .route(
                    "/mfa/backup-codes/regenerate",
                    post(regenerate_backup_codes),
                ),
        )
    }

    fn on_event(&self, event: &AuthEvent, ctx: &PluginContext) -> EventResponse {
        match event {
            AuthEvent::LoginSucceeded { user_id, .. } => {
                let user_id = *user_id;
                let db = ctx.state.db.clone();
                let challenge_store = ctx.state.challenge_store.clone();

                // Run the async DB lookup synchronously within the current runtime.
                // `on_event` is called from an async context, so Handle::current() is
                // available. We use block_in_place + block_on to avoid nesting runtimes.
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        // Check if user has a verified TOTP secret
                        let totp_secret = yauth_entity::totp_secrets::Entity::find()
                            .filter(yauth_entity::totp_secrets::Column::UserId.eq(user_id))
                            .filter(yauth_entity::totp_secrets::Column::Verified.eq(true))
                            .one(&db)
                            .await;

                        match totp_secret {
                            Ok(Some(_)) => {
                                // User has MFA enabled — create a pending session
                                let pending_id = Uuid::new_v4();
                                let key = format!("mfa_pending:{}", pending_id);
                                let value = serde_json::json!({ "user_id": user_id.to_string() });

                                if let Err(e) = challenge_store.set(&key, value, 300).await {
                                    tracing::error!("Failed to store MFA pending session: {}", e);
                                    return EventResponse::Block {
                                        status: 500,
                                        message: "Internal error".to_string(),
                                    };
                                }

                                info!(
                                    event = "mfa_required",
                                    user_id = %user_id,
                                    pending_session_id = %pending_id,
                                    "MFA verification required"
                                );

                                EventResponse::RequireMfa {
                                    user_id,
                                    pending_session_id: pending_id,
                                }
                            }
                            Ok(None) => EventResponse::Continue,
                            Err(e) => {
                                tracing::error!("DB error checking MFA status: {}", e);
                                EventResponse::Continue
                            }
                        }
                    })
                })
            }
            _ => EventResponse::Continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize, TS)]
#[ts(export)]
pub struct ConfirmTotpRequest {
    pub code: String,
}

#[derive(Deserialize, TS)]
#[ts(export)]
pub struct VerifyMfaRequest {
    pub pending_session_id: Uuid,
    pub code: String,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct SetupTotpResponse {
    pub otpauth_url: String,
    pub secret: String,
    pub backup_codes: Vec<String>,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct MfaMessageResponse {
    pub message: String,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct BackupCodeCountResponse {
    pub remaining: usize,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct MfaAuthResponse {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use crate::auth::session::session_set_cookie;

fn generate_backup_codes(count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let token = crypto::generate_token();
            // Use first 8 hex chars, formatted as XXXX-XXXX
            format!("{}-{}", &token[..4], &token[4..8])
        })
        .collect()
}

/// Build a `TOTP` instance from the stored base32 secret and config.
fn build_totp(
    secret_base32: &str,
    issuer: &str,
    user_email: &str,
) -> Result<TOTP, (StatusCode, Json<serde_json::Value>)> {
    let secret = Secret::Encoded(secret_base32.to_string());
    let secret_bytes = secret.to_bytes().map_err(|e| {
        tracing::error!("Failed to decode TOTP secret: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Internal error" })),
        )
    })?;

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        user_email.to_string(),
    )
    .map_err(|e| {
        tracing::error!("Failed to build TOTP: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Internal error" })),
        )
    })
}

/// Store backup codes in the database for a user, returning the plaintext codes.
async fn store_backup_codes(
    state: &YAuthState,
    user_id: Uuid,
    count: usize,
) -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let codes = generate_backup_codes(count);
    let now = chrono::Utc::now().fixed_offset();

    for code in &codes {
        let code_hash = crypto::hash_token(code);
        let backup = yauth_entity::backup_codes::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            code_hash: Set(code_hash),
            used: Set(false),
            created_at: Set(now),
        };
        backup.insert(&state.db).await.map_err(|e| {
            tracing::error!("Failed to store backup code: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }

    Ok(codes)
}

/// Delete all backup codes for a user.
async fn delete_all_backup_codes(
    state: &YAuthState,
    user_id: Uuid,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    yauth_entity::backup_codes::Entity::delete_many()
        .filter(yauth_entity::backup_codes::Column::UserId.eq(user_id))
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete backup codes: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Internal error" })),
            )
        })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /mfa/totp/setup (protected)
///
/// Generate a TOTP secret, store it unverified, and return the otpauth URI,
/// the base32 secret, and a fresh set of backup codes.
async fn setup_totp(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Check if user already has a verified TOTP secret
    let existing = yauth_entity::totp_secrets::Entity::find()
        .filter(yauth_entity::totp_secrets::Column::UserId.eq(user.id))
        .filter(yauth_entity::totp_secrets::Column::Verified.eq(true))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if existing.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "TOTP MFA is already enabled. Disable it first to set up a new secret.",
        ));
    }

    // Delete any existing unverified secret for this user (e.g. abandoned setup)
    yauth_entity::totp_secrets::Entity::delete_many()
        .filter(yauth_entity::totp_secrets::Column::UserId.eq(user.id))
        .filter(yauth_entity::totp_secrets::Column::Verified.eq(false))
        .exec(&state.db)
        .await
        .ok();

    // Generate TOTP secret
    let secret = Secret::generate_secret();
    let issuer = &state.mfa_config.issuer;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|e| {
            tracing::error!("Failed to get secret bytes: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?,
        Some(issuer.to_string()),
        user.email.clone(),
    )
    .map_err(|e| {
        tracing::error!("Failed to create TOTP: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let otpauth_url = totp.get_url();
    let secret_base32 = secret.to_encoded().to_string();

    // Store unverified TOTP secret
    let now = chrono::Utc::now().fixed_offset();
    let totp_record = yauth_entity::totp_secrets::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        encrypted_secret: Set(secret_base32.clone()),
        verified: Set(false),
        created_at: Set(now),
    };

    totp_record.insert(&state.db).await.map_err(|e| {
        tracing::error!("Failed to store TOTP secret: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Delete any existing backup codes and generate fresh ones
    delete_all_backup_codes(&state, user.id).await?;
    let backup_codes =
        store_backup_codes(&state, user.id, state.mfa_config.backup_code_count).await?;

    info!(
        event = "mfa_totp_setup_initiated",
        user_id = %user.id,
        "TOTP setup initiated, awaiting confirmation"
    );

    Ok(Json(SetupTotpResponse {
        otpauth_url,
        secret: secret_base32,
        backup_codes,
    }))
}

/// POST /mfa/totp/confirm (protected)
///
/// Verify the initial TOTP code provided by the user after scanning the QR code.
/// If valid, mark the TOTP secret as verified (MFA is now active).
async fn confirm_totp(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Json(input): Json<ConfirmTotpRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Find the unverified TOTP secret for this user
    let totp_record = yauth_entity::totp_secrets::Entity::find()
        .filter(yauth_entity::totp_secrets::Column::UserId.eq(user.id))
        .filter(yauth_entity::totp_secrets::Column::Verified.eq(false))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "No pending TOTP setup found. Call POST /mfa/totp/setup first.",
            )
        })?;

    // Build TOTP from stored secret and verify the code
    let totp = build_totp(
        &totp_record.encrypted_secret,
        &state.mfa_config.issuer,
        &user.email,
    )?;

    let is_valid = totp.check_current(&input.code).unwrap_or(false);

    if !is_valid {
        warn!(
            event = "mfa_totp_confirm_failed",
            user_id = %user.id,
            "Invalid TOTP code during confirmation"
        );
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Invalid TOTP code. Please try again.",
        ));
    }

    // Mark the secret as verified
    let mut active: yauth_entity::totp_secrets::ActiveModel = totp_record.into();
    active.verified = Set(true);
    active.update(&state.db).await.map_err(|e| {
        tracing::error!("Failed to verify TOTP secret: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    info!(
        event = "mfa_totp_enabled",
        user_id = %user.id,
        "TOTP MFA enabled successfully"
    );

    state
        .write_audit_log(
            Some(user.id),
            "mfa_enabled",
            Some(serde_json::json!({ "method": "totp" })),
            None,
        )
        .await;

    Ok(Json(MfaMessageResponse {
        message: "TOTP MFA enabled successfully".to_string(),
    }))
}

/// DELETE /mfa/totp (protected)
///
/// Disable TOTP MFA — deletes the TOTP secret and all backup codes.
async fn disable_totp(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Delete TOTP secret (verified or not)
    let delete_result = yauth_entity::totp_secrets::Entity::delete_many()
        .filter(yauth_entity::totp_secrets::Column::UserId.eq(user.id))
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete TOTP secret: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if delete_result.rows_affected == 0 {
        return Err(err(StatusCode::NOT_FOUND, "TOTP MFA is not enabled"));
    }

    // Delete all backup codes
    delete_all_backup_codes(&state, user.id).await?;

    info!(
        event = "mfa_totp_disabled",
        user_id = %user.id,
        "TOTP MFA disabled, backup codes deleted"
    );

    state
        .write_audit_log(
            Some(user.id),
            "mfa_disabled",
            Some(serde_json::json!({ "method": "totp" })),
            None,
        )
        .await;

    Ok(Json(MfaMessageResponse {
        message: "TOTP MFA disabled successfully".to_string(),
    }))
}

/// POST /mfa/verify (public)
///
/// Verify a TOTP or backup code during the login MFA challenge.
/// On success, creates a real session and returns a session cookie.
async fn verify_mfa(
    State(state): State<YAuthState>,
    Json(input): Json<VerifyMfaRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Look up the pending MFA session from the challenge store
    let key = format!("mfa_pending:{}", input.pending_session_id);
    let pending = state
        .challenge_store
        .get(&key)
        .await
        .map_err(|e| {
            tracing::error!("Challenge store error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "Invalid or expired MFA session. Please log in again.",
            )
        })?;

    let user_id_str = pending["user_id"].as_str().ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid pending session data",
        )
    })?;
    let user_id: Uuid = user_id_str.parse().map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid pending session data",
        )
    })?;

    // Load the user's verified TOTP secret
    let totp_record = yauth_entity::totp_secrets::Entity::find()
        .filter(yauth_entity::totp_secrets::Column::UserId.eq(user_id))
        .filter(yauth_entity::totp_secrets::Column::Verified.eq(true))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Load the user for the email (needed to build the TOTP)
    let user = yauth_entity::users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;

    let mut verified = false;

    // 1. Try TOTP verification first
    if let Some(ref totp_secret) = totp_record {
        let totp = build_totp(
            &totp_secret.encrypted_secret,
            &state.mfa_config.issuer,
            &user.email,
        )?;
        if totp.check_current(&input.code).unwrap_or(false) {
            verified = true;
        }
    }

    // 2. If TOTP didn't match, try backup codes
    if !verified {
        let code_hash = crypto::hash_token(&input.code);

        let backup = yauth_entity::backup_codes::Entity::find()
            .filter(yauth_entity::backup_codes::Column::UserId.eq(user_id))
            .filter(yauth_entity::backup_codes::Column::Used.eq(false))
            .all(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        for bc in backup {
            if crypto::constant_time_eq(bc.code_hash.as_bytes(), code_hash.as_bytes()) {
                // Mark backup code as used
                let mut active: yauth_entity::backup_codes::ActiveModel = bc.into();
                active.used = Set(true);
                active.update(&state.db).await.map_err(|e| {
                    tracing::error!("Failed to mark backup code as used: {}", e);
                    err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

                verified = true;
                info!(
                    event = "mfa_backup_code_used",
                    user_id = %user_id,
                    "Backup code used for MFA verification"
                );
                break;
            }
        }
    }

    if !verified {
        warn!(
            event = "mfa_verify_failed",
            user_id = %user_id,
            "MFA verification failed — invalid code"
        );
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid MFA code"));
    }

    // MFA passed — delete the pending session and create a real session
    state.challenge_store.delete(&key).await.ok();

    let (token, _session_id) = session::create_session(&state.db, user_id, None, None)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create session: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    info!(
        event = "mfa_verify_success",
        user_id = %user_id,
        "MFA verification successful, session created"
    );

    state
        .write_audit_log(
            Some(user_id),
            "mfa_verified",
            Some(serde_json::json!({ "method": "totp" })),
            None,
        )
        .await;

    Ok((
        [(SET_COOKIE, session_set_cookie(&state, &token))],
        Json(MfaAuthResponse {
            user_id: user.id.to_string(),
            email: user.email.clone(),
            display_name: user.display_name.clone(),
            email_verified: user.email_verified,
        }),
    ))
}

/// GET /mfa/backup-codes (protected)
///
/// Returns the count of remaining (unused) backup codes.
async fn get_backup_code_count(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<BackupCodeCountResponse>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let codes = yauth_entity::backup_codes::Entity::find()
        .filter(yauth_entity::backup_codes::Column::UserId.eq(user.id))
        .filter(yauth_entity::backup_codes::Column::Used.eq(false))
        .all(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    Ok(Json(BackupCodeCountResponse {
        remaining: codes.len(),
    }))
}

/// POST /mfa/backup-codes/regenerate (protected)
///
/// Delete all existing backup codes and generate a fresh set.
/// Requires TOTP MFA to be enabled (verified).
async fn regenerate_backup_codes(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<BackupCodesResponse>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Ensure MFA is enabled
    let has_mfa = yauth_entity::totp_secrets::Entity::find()
        .filter(yauth_entity::totp_secrets::Column::UserId.eq(user.id))
        .filter(yauth_entity::totp_secrets::Column::Verified.eq(true))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if has_mfa.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "TOTP MFA must be enabled before regenerating backup codes",
        ));
    }

    // Delete old backup codes
    delete_all_backup_codes(&state, user.id).await?;

    // Generate and store fresh backup codes
    let codes = store_backup_codes(&state, user.id, state.mfa_config.backup_code_count).await?;

    info!(
        event = "mfa_backup_codes_regenerated",
        user_id = %user.id,
        count = codes.len(),
        "Backup codes regenerated"
    );

    Ok(Json(BackupCodesResponse {
        backup_codes: codes,
    }))
}
