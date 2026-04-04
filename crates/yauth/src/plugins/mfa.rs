use axum::{
    Extension, Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
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
                let repos = ctx.state.repos.clone();

                // Run the async DB lookup synchronously within the current runtime.
                // `on_event` is called from an async context, so Handle::current() is
                // available. We use block_in_place + block_on to avoid nesting runtimes.
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        // Check if user has a verified TOTP secret
                        let has_mfa = match repos.totp.find_by_user_id(user_id, Some(true)).await {
                            Ok(Some(_)) => true,
                            Ok(None) => false,
                            Err(e) => {
                                crate::otel::record_error("mfa_db_status_check_error", &e);
                                return EventResponse::Continue;
                            }
                        };

                        if has_mfa {
                            // User has MFA enabled — create a pending session
                            let pending_id = Uuid::new_v4();
                            let key = format!("mfa_pending:{}", pending_id);
                            let value = serde_json::json!({ "user_id": user_id.to_string() });

                            if let Err(e) = repos.challenges.set_challenge(&key, value, 300).await {
                                crate::otel::record_error("mfa_pending_session_store_failed", &e);
                                return EventResponse::Block {
                                    status: 500,
                                    message: "Internal error".to_string(),
                                };
                            }

                            crate::otel::add_event(
                                "mfa_required",
                                #[cfg(feature = "telemetry")]
                                vec![
                                    opentelemetry::KeyValue::new("user.id", user_id.to_string()),
                                    opentelemetry::KeyValue::new(
                                        "pending_session.id",
                                        pending_id.to_string(),
                                    ),
                                ],
                                #[cfg(not(feature = "telemetry"))]
                                vec![],
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

    fn schema(&self) -> Vec<crate::schema::TableDef> {
        crate::schema::plugin_schemas::mfa_schema()
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
        crate::otel::record_error("totp_secret_decode_failed", &e);
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
        crate::otel::record_error("totp_build_failed", &e);
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
    let codes = generate_backup_codes(count);

    for code in &codes {
        let code_hash = crypto::hash_token(code);
        let now = chrono::Utc::now().naive_utc();
        let new_code = crate::domain::NewBackupCode {
            id: Uuid::new_v4(),
            user_id,
            code_hash,
            used: false,
            created_at: now,
        };
        state
            .repos
            .backup_codes
            .create(new_code)
            .await
            .map_err(|e| {
                crate::otel::record_error("mfa_backup_code_store_failed", &e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "Internal error" })),
                )
            })?;
    }

    Ok(codes)
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
    let existing = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(true))
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if existing.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "TOTP MFA is already enabled. Disable it first to set up a new secret.",
        ));
    }

    // Delete any existing unverified secret for this user (e.g. abandoned setup)
    let _ = state.repos.totp.delete_for_user(user.id, Some(false)).await;

    // Generate TOTP secret
    let secret = Secret::generate_secret();
    let issuer = &state.mfa_config.issuer;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|e| {
            crate::otel::record_error("totp_secret_bytes_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?,
        Some(issuer.to_string()),
        user.email.clone(),
    )
    .map_err(|e| {
        crate::otel::record_error("totp_create_failed", &e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let otpauth_url = totp.get_url();
    let secret_base32 = secret.to_encoded().to_string();

    // Store unverified TOTP secret
    let now = chrono::Utc::now().naive_utc();
    let new_secret = crate::domain::NewTotpSecret {
        id: Uuid::new_v4(),
        user_id: user.id,
        encrypted_secret: secret_base32.clone(),
        verified: false,
        created_at: now,
    };
    state.repos.totp.create(new_secret).await.map_err(|e| {
        crate::otel::record_error("totp_secret_store_failed", &e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Delete any existing backup codes and generate fresh ones
    let _ = state.repos.backup_codes.delete_all_for_user(user.id).await;

    let backup_codes =
        store_backup_codes(&state, user.id, state.mfa_config.backup_code_count).await?;

    crate::otel::add_event(
        "mfa_totp_setup",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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
    let totp_record = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(false))
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
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
        crate::otel::add_event(
            "mfa_totp_confirm_failed",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Invalid TOTP code. Please try again.",
        ));
    }

    // Mark the secret as verified
    state
        .repos
        .totp
        .mark_verified(totp_record.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("totp_verify_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    crate::otel::add_event(
        "mfa_totp_enabled",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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

    // Check if user has any TOTP secret (verified or not) before trying to delete
    let has_verified = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(true))
        .await
        .map_err(|e| {
            crate::otel::record_error("totp_secret_check_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let has_unverified = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(false))
        .await
        .map_err(|e| {
            crate::otel::record_error("totp_secret_check_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if has_verified.is_none() && has_unverified.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "TOTP MFA is not enabled"));
    }

    // Delete TOTP secret (verified or not)
    state
        .repos
        .totp
        .delete_for_user(user.id, None)
        .await
        .map_err(|e| {
            crate::otel::record_error("totp_secret_delete_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Delete all backup codes
    state
        .repos
        .backup_codes
        .delete_all_for_user(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("mfa_backup_codes_delete_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    crate::otel::add_event(
        "mfa_totp_disabled",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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

    // Look up the pending MFA session from the challenge repo
    let key = format!("mfa_pending:{}", input.pending_session_id);
    let pending = state
        .repos
        .challenges
        .get_challenge(&key)
        .await
        .map_err(|e| {
            crate::otel::record_error("mfa_challenge_repo_error", &e);
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
    let totp_record = state
        .repos
        .totp
        .find_by_user_id(user_id, Some(true))
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Load the user for the email (needed to build the TOTP)
    struct UserData {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
    }

    let user = {
        let u = state
            .repos
            .users
            .find_by_id(user_id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
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

        let backup_codes = state
            .repos
            .backup_codes
            .find_unused_by_user_id(user_id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        for bc in backup_codes {
            if crypto::constant_time_eq(bc.code_hash.as_bytes(), code_hash.as_bytes()) {
                // Mark backup code as used
                state
                    .repos
                    .backup_codes
                    .mark_used(bc.id)
                    .await
                    .map_err(|e| {
                        crate::otel::record_error("mfa_backup_code_mark_used_failed", &e);
                        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })?;

                verified = true;
                crate::otel::add_event(
                    "mfa_backup_code_used",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("user.id", user_id.to_string())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                break;
            }
        }
    }

    if !verified {
        crate::otel::add_event(
            "mfa_verify_failed",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.id", user_id.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid MFA code"));
    }

    // MFA passed — delete the pending session and create a real session
    let _ = state.repos.challenges.delete_challenge(&key).await;

    let (token, _session_id) =
        session::create_session(&state, user_id, None, None, state.config.session_ttl)
            .await
            .map_err(|e| {
                crate::otel::record_error("session_create_failed", &e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

    crate::otel::add_event(
        "mfa_verified",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user_id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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
    let codes = state
        .repos
        .backup_codes
        .find_unused_by_user_id(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Internal error" })),
            )
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
    let has_mfa = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(true))
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if has_mfa.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "TOTP MFA must be enabled before regenerating backup codes",
        ));
    }

    // Delete old backup codes
    state
        .repos
        .backup_codes
        .delete_all_for_user(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("mfa_backup_codes_delete_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Generate and store fresh backup codes
    let codes = store_backup_codes(&state, user.id, state.mfa_config.backup_code_count).await?;

    crate::otel::add_event(
        "mfa_backup_codes_regenerated",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user.id.to_string()),
            opentelemetry::KeyValue::new("count", codes.len() as i64),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    Ok(Json(BackupCodesResponse {
        backup_codes: codes,
    }))
}
