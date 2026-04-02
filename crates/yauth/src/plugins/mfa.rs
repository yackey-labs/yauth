use axum::{
    Extension, Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use totp_rs::{Algorithm, Secret, TOTP};

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;

use crate::auth::{crypto, session};
use crate::config::MfaConfig;
use crate::db::models::{BackupCode, NewBackupCode, NewTotpSecret, TotpSecret};
use crate::db::schema::{yauth_backup_codes, yauth_totp_secrets};
use crate::middleware::AuthUser;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

type Conn = diesel_async_crate::AsyncPgConnection;
type DbResult<T> = Result<T, String>;

use crate::db::find_user_by_id;

async fn db_find_totp_secret(
    conn: &mut Conn,
    user_id: Uuid,
    verified: bool,
) -> DbResult<Option<TotpSecret>> {
    yauth_totp_secrets::table
        .filter(
            yauth_totp_secrets::user_id
                .eq(user_id)
                .and(yauth_totp_secrets::verified.eq(verified)),
        )
        .select(TotpSecret::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_insert_totp_secret(
    conn: &mut Conn,
    id: Uuid,
    user_id: Uuid,
    encrypted_secret: &str,
    verified: bool,
) -> DbResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let new_secret = NewTotpSecret {
        id,
        user_id,
        encrypted_secret: encrypted_secret.to_string(),
        verified,
        created_at: now,
    };
    diesel::insert_into(yauth_totp_secrets::table)
        .values(&new_secret)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_delete_totp_secrets_by_user(
    conn: &mut Conn,
    user_id: Uuid,
    verified_filter: Option<bool>,
) -> DbResult<u64> {
    if let Some(v) = verified_filter {
        let result = diesel::delete(
            yauth_totp_secrets::table.filter(
                yauth_totp_secrets::user_id
                    .eq(user_id)
                    .and(yauth_totp_secrets::verified.eq(v)),
            ),
        )
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(result as u64)
    } else {
        let result = diesel::delete(
            yauth_totp_secrets::table.filter(yauth_totp_secrets::user_id.eq(user_id)),
        )
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(result as u64)
    }
}

async fn db_update_totp_secret_verified(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::update(yauth_totp_secrets::table.find(id))
        .set(yauth_totp_secrets::verified.eq(true))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_find_unused_backup_codes(conn: &mut Conn, user_id: Uuid) -> DbResult<Vec<BackupCode>> {
    yauth_backup_codes::table
        .filter(
            yauth_backup_codes::user_id
                .eq(user_id)
                .and(yauth_backup_codes::used.eq(false)),
        )
        .select(BackupCode::as_select())
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

async fn db_insert_backup_code(
    conn: &mut Conn,
    id: Uuid,
    user_id: Uuid,
    code_hash: &str,
) -> DbResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let new_code = NewBackupCode {
        id,
        user_id,
        code_hash: code_hash.to_string(),
        used: false,
        created_at: now,
    };
    diesel::insert_into(yauth_backup_codes::table)
        .values(&new_code)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_delete_all_backup_codes(conn: &mut Conn, user_id: Uuid) -> DbResult<()> {
    diesel::delete(yauth_backup_codes::table.filter(yauth_backup_codes::user_id.eq(user_id)))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_mark_backup_code_used(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::update(yauth_backup_codes::table.find(id))
        .set(yauth_backup_codes::used.eq(true))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

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
                        let has_mfa = {
                            let mut conn = match db.get().await {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::error!("Pool error checking MFA status: {}", e);
                                    return EventResponse::Continue;
                                }
                            };
                            match db_find_totp_secret(&mut conn, user_id, true).await {
                                Ok(Some(_)) => true,
                                Ok(None) => false,
                                Err(e) => {
                                    tracing::error!("DB error checking MFA status: {}", e);
                                    return EventResponse::Continue;
                                }
                            }
                        };

                        if has_mfa {
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
                                event = "yauth.mfa.required",
                                user_id = %user_id,
                                pending_session_id = %pending_id,
                                "MFA verification required"
                            );

                            EventResponse::RequireMfa {
                                user_id,
                                pending_session_id: pending_id,
                            }
                        } else {
                            EventResponse::Continue
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

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConfirmTotpRequest {
    pub code: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyMfaRequest {
    pub pending_session_id: Uuid,
    pub code: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SetupTotpResponse {
    pub otpauth_url: String,
    pub secret: String,
    pub backup_codes: Vec<String>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MfaMessageResponse {
    pub message: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BackupCodeCountResponse {
    pub remaining: usize,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
    conn: &mut diesel_async_crate::AsyncPgConnection,
    user_id: Uuid,
    count: usize,
) -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let codes = generate_backup_codes(count);

    for code in &codes {
        let code_hash = crypto::hash_token(code);
        db_insert_backup_code(conn, Uuid::new_v4(), user_id, &code_hash)
            .await
            .map_err(|e| {
                tracing::error!("Failed to store backup code: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    Ok(codes)
}

/// Delete all backup codes for a user.
async fn delete_all_backup_codes(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    user_id: Uuid,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    db_delete_all_backup_codes(conn, user_id)
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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Check if user already has a verified TOTP secret
    let existing = {
        db_find_totp_secret(&mut conn, user.id, true)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
    };

    if existing.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "TOTP MFA is already enabled. Disable it first to set up a new secret.",
        ));
    }

    // Delete any existing unverified secret for this user (e.g. abandoned setup)
    {
        let _ = db_delete_totp_secrets_by_user(&mut conn, user.id, Some(false)).await;
    }

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
    {
        db_insert_totp_secret(&mut conn, Uuid::new_v4(), user.id, &secret_base32, false)
            .await
            .map_err(|e| {
                tracing::error!("Failed to store TOTP secret: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    // Delete any existing backup codes and generate fresh ones
    {
        delete_all_backup_codes(&mut conn, user.id).await?;
    }

    let backup_codes =
        store_backup_codes(&mut conn, user.id, state.mfa_config.backup_code_count).await?;

    info!(
        event = "yauth.mfa.totp_setup",
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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Find the unverified TOTP secret for this user
    let totp_record = {
        db_find_totp_secret(&mut conn, user.id, false)
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
            })?
    };

    // Build TOTP from stored secret and verify the code
    let totp = build_totp(
        &totp_record.encrypted_secret,
        &state.mfa_config.issuer,
        &user.email,
    )?;

    let is_valid = totp.check_current(&input.code).unwrap_or(false);

    if !is_valid {
        warn!(
            event = "yauth.mfa.totp_confirm_failed",
            user_id = %user.id,
            "Invalid TOTP code during confirmation"
        );
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Invalid TOTP code. Please try again.",
        ));
    }

    // Mark the secret as verified
    {
        db_update_totp_secret_verified(&mut conn, totp_record.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to verify TOTP secret: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    info!(
        event = "yauth.mfa.totp_enabled",
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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Delete TOTP secret (verified or not)
    let rows_affected = {
        db_delete_totp_secrets_by_user(&mut conn, user.id, None)
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete TOTP secret: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
    };

    if rows_affected == 0 {
        return Err(err(StatusCode::NOT_FOUND, "TOTP MFA is not enabled"));
    }

    // Delete all backup codes
    {
        delete_all_backup_codes(&mut conn, user.id).await?;
    }

    info!(
        event = "yauth.mfa.totp_disabled",
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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Load the user's verified TOTP secret
    let totp_record = {
        db_find_totp_secret(&mut conn, user_id, true)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
    };

    // Load the user for the email (needed to build the TOTP)
    struct UserData {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
    }

    let user = {
        let u = find_user_by_id(&mut conn, user_id)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;
        UserData {
            id: u.id,
            email: u.email,
            display_name: u.display_name,
            email_verified: u.email_verified,
        }
    };

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

        let backup_codes = {
            db_find_unused_backup_codes(&mut conn, user_id)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
        };

        for bc in backup_codes {
            if crypto::constant_time_eq(bc.code_hash.as_bytes(), code_hash.as_bytes()) {
                // Mark backup code as used
                {
                    db_mark_backup_code_used(&mut conn, bc.id)
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to mark backup code as used: {}", e);
                            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                        })?;
                }

                verified = true;
                info!(
                    event = "yauth.mfa.backup_code_used",
                    user_id = %user_id,
                    "Backup code used for MFA verification"
                );
                break;
            }
        }
    }

    if !verified {
        warn!(
            event = "yauth.mfa.verify_failed",
            user_id = %user_id,
            "MFA verification failed — invalid code"
        );
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid MFA code"));
    }

    // MFA passed — delete the pending session and create a real session
    state.challenge_store.delete(&key).await.ok();

    let (token, _session_id) =
        session::create_session(&state, user_id, None, None, state.config.session_ttl)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create session: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

    info!(
        event = "yauth.mfa.verified",
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
        [(
            SET_COOKIE,
            session_set_cookie(&state, &token, state.config.session_ttl),
        )],
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

    let remaining = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let codes = db_find_unused_backup_codes(&mut conn, user.id)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        codes.len()
    };

    Ok(Json(BackupCodeCountResponse { remaining }))
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

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Ensure MFA is enabled
    let has_mfa = {
        db_find_totp_secret(&mut conn, user.id, true)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
    };

    if has_mfa.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "TOTP MFA must be enabled before regenerating backup codes",
        ));
    }

    // Delete old backup codes
    {
        delete_all_backup_codes(&mut conn, user.id).await?;
    }

    // Generate and store fresh backup codes
    let codes = store_backup_codes(&mut conn, user.id, state.mfa_config.backup_code_count).await?;

    info!(
        event = "yauth.mfa.backup_codes_regenerated",
        user_id = %user.id,
        count = codes.len(),
        "Backup codes regenerated"
    );

    Ok(Json(BackupCodesResponse {
        backup_codes: codes,
    }))
}
