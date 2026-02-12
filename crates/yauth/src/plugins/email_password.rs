use axum::{
    Extension, Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
    routing::post,
};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{crypto, hibp, password, session};
use crate::middleware::AuthUser;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

use crate::config::EmailPasswordConfig;

const VERIFICATION_TOKEN_EXPIRY_HOURS: i64 = 24;
const RESET_TOKEN_EXPIRY_HOURS: i64 = 1;

pub struct EmailPasswordPlugin;

impl EmailPasswordPlugin {
    pub fn new(_config: EmailPasswordConfig) -> Self {
        // Config is stored in YAuthState for handler access
        Self
    }
}

impl YAuthPlugin for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email-password"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/register", post(register))
                .route("/login", post(login))
                .route("/verify-email", post(verify_email))
                .route("/resend-verification", post(resend_verification))
                .route("/forgot-password", post(forgot_password))
                .route("/reset-password", post(reset_password)),
        )
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(Router::new().route("/change-password", post(change_password)))
    }
}

fn session_set_cookie(state: &YAuthState, token: &str) -> String {
    let max_age = state.config.session_ttl.as_secs();
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        state.config.session_cookie_name, token, max_age
    );
    if state.config.secure_cookies {
        cookie.push_str("; Secure");
    }
    if let Some(ref domain) = state.config.cookie_domain {
        cookie.push_str(&format!("; Domain={}", domain));
    }
    cookie
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct MessageResponse {
    message: String,
}

#[derive(Deserialize)]
struct VerifyEmailRequest {
    token: String,
}

#[derive(Deserialize)]
struct ResendVerificationRequest {
    email: String,
}

#[derive(Deserialize)]
struct ForgotPasswordRequest {
    email: String,
}

#[derive(Deserialize)]
struct ResetPasswordRequest {
    token: String,
    password: String,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn register(
    State(state): State<YAuthState>,
    Json(input): Json<RegisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Rate limit registration
    if !state.rate_limiter.check("register").await {
        warn!(event = "register_rate_limited", "Registration rate limited");
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let email = input.email.trim().to_lowercase();
    if email.is_empty() || input.password.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Email and password are required",
        ));
    }

    // Use config min password length
    let ep_config = &state.email_password_config;
    if input.password.len() < ep_config.min_password_length {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Password must be at least {} characters",
                ep_config.min_password_length
            ),
        ));
    }

    // Check HaveIBeenPwned for breached passwords
    if ep_config.hibp_check
        && let Some(breach_msg) = hibp::validate_password_not_breached(&input.password).await
    {
        warn!(event = "register_breached_password", email = %email, "Breached password rejected");
        return Err(err(StatusCode::BAD_REQUEST, &breach_msg));
    }

    // Check if user already exists
    let existing = yauth_entity::users::Entity::find()
        .filter(yauth_entity::users::Column::Email.eq(&email))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if existing.is_some() {
        warn!(event = "register_duplicate", email = %email, "Registration attempt with existing email");
        return Err(err(StatusCode::CONFLICT, "Registration failed"));
    }

    let password_hash = password::hash_password(&input.password).map_err(|e| {
        tracing::error!("Password hash error: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let now = chrono::Utc::now().fixed_offset();
    let user_id = Uuid::new_v4();

    let user = yauth_entity::users::ActiveModel {
        id: Set(user_id),
        email: Set(email.clone()),
        display_name: Set(input.display_name.map(|n| n.trim().to_string())),
        email_verified: Set(!ep_config.require_email_verification),
        role: Set("user".to_string()),
        banned: Set(false),
        banned_reason: Set(None),
        banned_until: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    user.insert(&state.db).await.map_err(|e| {
        tracing::error!("Failed to create user: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Store password in separate table
    let pwd = yauth_entity::passwords::ActiveModel {
        user_id: Set(user_id),
        password_hash: Set(password_hash),
    };
    pwd.insert(&state.db).await.map_err(|e| {
        tracing::error!("Failed to store password: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Create email verification token (if verification required)
    if ep_config.require_email_verification {
        let token = crypto::generate_token();
        let token_hash = crypto::hash_token(&token);
        let expires_at = (chrono::Utc::now()
            + chrono::Duration::hours(VERIFICATION_TOKEN_EXPIRY_HOURS))
        .fixed_offset();

        let verification = yauth_entity::email_verifications::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            token_hash: Set(token_hash),
            expires_at: Set(expires_at),
            created_at: Set(now),
        };

        verification.insert(&state.db).await.map_err(|e| {
            tracing::error!("Failed to create email verification: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        // Send verification email (non-blocking failure)
        if let Some(ref email_service) = state.email_service
            && let Err(e) = email_service.send_verification_email(&email, &token)
        {
            tracing::error!("Failed to send verification email: {}", e);
        }
    }

    info!(
        event = "register_success",
        email = %email,
        user_id = %user_id,
        "User registered, verification email sent"
    );

    Ok((
        StatusCode::CREATED,
        Json(MessageResponse {
            message: "Account created. Please check your email to verify your address.".to_string(),
        }),
    ))
}

async fn login(
    State(state): State<YAuthState>,
    Json(input): Json<LoginRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let email = input.email.trim().to_lowercase();

    // Rate limit login attempts per email
    if !state.rate_limiter.check(&format!("login:{}", email)).await {
        warn!(event = "login_rate_limited", email = %email, "Login rate limited");
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    // Look up user
    let user = yauth_entity::users::Entity::find()
        .filter(yauth_entity::users::Column::Email.eq(&email))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Get password hash — from passwords table or use dummy
    let (user_opt, hash) = match &user {
        Some(u) => {
            let pwd = yauth_entity::passwords::Entity::find_by_id(u.id)
                .one(&state.db)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;
            let h = pwd
                .map(|p| p.password_hash)
                .unwrap_or_else(|| state.dummy_hash.clone());
            (Some(u), h)
        }
        None => (None, state.dummy_hash.clone()),
    };

    let valid = password::verify_password(&input.password, &hash).unwrap_or(false);

    match (user_opt, valid) {
        (Some(u), true) => {
            // Check banned
            if u.banned {
                warn!(event = "login_banned", email = %u.email, "Login attempt by banned user");
                return Err(err(StatusCode::FORBIDDEN, "Account suspended"));
            }

            // Check email verification (only if verification is required)
            if state.email_password_config.require_email_verification && !u.email_verified {
                warn!(event = "login_email_not_verified", email = %u.email, "Login attempt with unverified email");
                return Err(err(
                    StatusCode::FORBIDDEN,
                    "Email not verified. Please check your inbox or request a new verification email.",
                ));
            }

            // Emit LoginSucceeded event — plugins (e.g., MFA) can intercept
            let event_response = state.emit_event(&AuthEvent::LoginSucceeded {
                user_id: u.id,
                method: "email-password".to_string(),
            });

            match event_response {
                EventResponse::RequireMfa {
                    pending_session_id, ..
                } => {
                    info!(
                        event = "login_mfa_required",
                        email = %u.email,
                        user_id = %u.id,
                        pending_session_id = %pending_session_id,
                        "Login requires MFA verification"
                    );
                    Ok(Json(serde_json::json!({
                        "mfa_required": true,
                        "pending_session_id": pending_session_id,
                    }))
                    .into_response())
                }
                EventResponse::Block { status, message } => {
                    warn!(
                        event = "login_blocked_by_plugin",
                        email = %u.email,
                        status = status,
                        message = %message,
                        "Login blocked by plugin"
                    );
                    let status_code =
                        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    Err(err(status_code, &message))
                }
                EventResponse::Continue => {
                    let (token, _session_id) = session::create_session(&state.db, u.id, None, None)
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to create session: {}", e);
                            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                        })?;

                    info!(event = "login_success", email = %u.email, user_id = %u.id, "User logged in");

                    Ok((
                        [(SET_COOKIE, session_set_cookie(&state, &token))],
                        Json(serde_json::json!({
                            "user_id": u.id.to_string(),
                            "email": u.email,
                            "display_name": u.display_name,
                            "email_verified": u.email_verified,
                        })),
                    )
                        .into_response())
                }
            }
        }
        _ => {
            warn!(event = "login_failure", email = %email, "Failed login attempt");
            Err(err(StatusCode::UNAUTHORIZED, "Invalid email or password"))
        }
    }
}

async fn verify_email(
    State(state): State<YAuthState>,
    Json(input): Json<VerifyEmailRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let token = input.token.trim();
    if token.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Verification token is required",
        ));
    }

    let token_hash = crypto::hash_token(token);

    // Find the verification token
    let verification = yauth_entity::email_verifications::Entity::find()
        .filter(yauth_entity::email_verifications::Column::TokenHash.eq(&token_hash))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "Invalid or expired verification link",
            )
        })?;

    // Check expiry
    let now = chrono::Utc::now().fixed_offset();
    if verification.expires_at < now {
        yauth_entity::email_verifications::Entity::delete_by_id(verification.id)
            .exec(&state.db)
            .await
            .ok();
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Verification link has expired. Please request a new one.",
        ));
    }

    // Mark user as verified
    let user = yauth_entity::users::Entity::find_by_id(verification.user_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;

    let mut user_active: yauth_entity::users::ActiveModel = user.into();
    user_active.email_verified = Set(true);
    user_active.updated_at = Set(now);
    user_active.update(&state.db).await.map_err(|e| {
        tracing::error!("Failed to update user: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Delete all verification tokens for this user
    yauth_entity::email_verifications::Entity::delete_many()
        .filter(yauth_entity::email_verifications::Column::UserId.eq(verification.user_id))
        .exec(&state.db)
        .await
        .ok();

    info!(
        event = "email_verified",
        user_id = %verification.user_id,
        "Email verified successfully"
    );

    Ok(Json(MessageResponse {
        message: "Email verified successfully. You can now sign in.".to_string(),
    }))
}

async fn resend_verification(
    State(state): State<YAuthState>,
    Json(input): Json<ResendVerificationRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let email = input.email.trim().to_lowercase();

    // Rate limit
    if !state.rate_limiter.check(&format!("resend:{}", email)).await {
        warn!(event = "resend_rate_limited", email = %email, "Resend verification rate limited");
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    // Always return success to prevent email enumeration
    let success_msg = Json(MessageResponse {
        message: "If an account exists with that email, a verification link has been sent."
            .to_string(),
    });

    let user = yauth_entity::users::Entity::find()
        .filter(yauth_entity::users::Column::Email.eq(&email))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let user = match user {
        Some(u) if !u.email_verified => u,
        _ => return Ok(success_msg),
    };

    // Delete old verification tokens
    yauth_entity::email_verifications::Entity::delete_many()
        .filter(yauth_entity::email_verifications::Column::UserId.eq(user.id))
        .exec(&state.db)
        .await
        .ok();

    // Create new token
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let now = chrono::Utc::now().fixed_offset();
    let expires_at = (chrono::Utc::now()
        + chrono::Duration::hours(VERIFICATION_TOKEN_EXPIRY_HOURS))
    .fixed_offset();

    let verification = yauth_entity::email_verifications::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        token_hash: Set(token_hash),
        expires_at: Set(expires_at),
        created_at: Set(now),
    };

    verification.insert(&state.db).await.map_err(|e| {
        tracing::error!("Failed to create verification: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_verification_email(&email, &token)
    {
        tracing::error!("Failed to send verification email: {}", e);
    }

    info!(event = "verification_resent", email = %email, "Verification email resent");

    Ok(success_msg)
}

async fn forgot_password(
    State(state): State<YAuthState>,
    Json(input): Json<ForgotPasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let email = input.email.trim().to_lowercase();

    // Rate limit
    if !state.rate_limiter.check(&format!("forgot:{}", email)).await {
        warn!(event = "forgot_password_rate_limited", email = %email, "Forgot password rate limited");
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    // Always return success to prevent email enumeration
    let success_msg = Json(MessageResponse {
        message: "If an account exists with that email, a password reset link has been sent."
            .to_string(),
    });

    let user = yauth_entity::users::Entity::find()
        .filter(yauth_entity::users::Column::Email.eq(&email))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let user = match user {
        Some(u) => u,
        None => {
            info!(event = "forgot_password_no_user", email = %email, "Forgot password for non-existent email");
            return Ok(success_msg);
        }
    };

    // Delete old unused reset tokens for this user
    yauth_entity::password_resets::Entity::delete_many()
        .filter(yauth_entity::password_resets::Column::UserId.eq(user.id))
        .filter(yauth_entity::password_resets::Column::UsedAt.is_null())
        .exec(&state.db)
        .await
        .ok();

    // Create reset token
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let now = chrono::Utc::now().fixed_offset();
    let expires_at =
        (chrono::Utc::now() + chrono::Duration::hours(RESET_TOKEN_EXPIRY_HOURS)).fixed_offset();

    let reset = yauth_entity::password_resets::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        token_hash: Set(token_hash),
        expires_at: Set(expires_at),
        created_at: Set(now),
        used_at: Set(None),
    };

    reset.insert(&state.db).await.map_err(|e| {
        tracing::error!("Failed to create password reset: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Send reset email
    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_password_reset_email(&user.email, &token)
    {
        tracing::error!("Failed to send password reset email: {}", e);
    }

    info!(
        event = "forgot_password_sent",
        email = %email,
        user_id = %user.id,
        "Password reset email sent"
    );

    Ok(success_msg)
}

async fn reset_password(
    State(state): State<YAuthState>,
    Json(input): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let token = input.token.trim();
    if token.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "Reset token is required"));
    }

    let ep_config = &state.email_password_config;
    if input.password.len() < ep_config.min_password_length {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Password must be at least {} characters",
                ep_config.min_password_length
            ),
        ));
    }

    // Check HaveIBeenPwned for breached passwords
    if ep_config.hibp_check
        && let Some(breach_msg) = hibp::validate_password_not_breached(&input.password).await
    {
        warn!(
            event = "reset_breached_password",
            "Breached password rejected on reset"
        );
        return Err(err(StatusCode::BAD_REQUEST, &breach_msg));
    }

    let token_hash = crypto::hash_token(token);

    // Find the reset token
    let reset = yauth_entity::password_resets::Entity::find()
        .filter(yauth_entity::password_resets::Column::TokenHash.eq(&token_hash))
        .filter(yauth_entity::password_resets::Column::UsedAt.is_null())
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Invalid or expired reset link"))?;

    // Check expiry
    let now = chrono::Utc::now().fixed_offset();
    if reset.expires_at < now {
        yauth_entity::password_resets::Entity::delete_by_id(reset.id)
            .exec(&state.db)
            .await
            .ok();
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Reset link has expired. Please request a new one.",
        ));
    }

    // Hash new password
    let new_hash = password::hash_password(&input.password).map_err(|e| {
        tracing::error!("Password hash error: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let reset_user_id = reset.user_id;

    // Update password in passwords table (upsert)
    let existing_pwd = yauth_entity::passwords::Entity::find_by_id(reset_user_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if let Some(existing) = existing_pwd {
        let mut pwd_active: yauth_entity::passwords::ActiveModel = existing.into();
        pwd_active.password_hash = Set(new_hash);
        pwd_active.update(&state.db).await.map_err(|e| {
            tracing::error!("Failed to update password: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    } else {
        let pwd = yauth_entity::passwords::ActiveModel {
            user_id: Set(reset_user_id),
            password_hash: Set(new_hash),
        };
        pwd.insert(&state.db).await.map_err(|e| {
            tracing::error!("Failed to insert password: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }

    // Also verify email if not already
    let user = yauth_entity::users::Entity::find_by_id(reset_user_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;

    let mut user_active: yauth_entity::users::ActiveModel = user.into();
    user_active.email_verified = Set(true);
    user_active.updated_at = Set(now);
    user_active.update(&state.db).await.map_err(|e| {
        tracing::error!("Failed to update user: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Mark reset token as used
    let mut reset_active: yauth_entity::password_resets::ActiveModel = reset.into();
    reset_active.used_at = Set(Some(now));
    reset_active.update(&state.db).await.ok();

    // Invalidate all existing sessions for this user
    session::delete_all_user_sessions(&state.db, reset_user_id)
        .await
        .ok();

    info!(
        event = "password_reset_success",
        user_id = %reset_user_id,
        "Password reset successfully, all sessions invalidated"
    );

    Ok(Json(MessageResponse {
        message: "Password reset successfully. You can now sign in with your new password."
            .to_string(),
    }))
}

async fn change_password(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    jar: CookieJar,
    Json(input): Json<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Rate limit on user id
    if !state
        .rate_limiter
        .check(&format!("change-pwd:{}", user.id))
        .await
    {
        warn!(
            event = "change_password_rate_limited",
            user_id = %user.id,
            "Change password rate limited"
        );
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let ep_config = &state.email_password_config;

    // Validate new password length
    if input.new_password.len() < ep_config.min_password_length {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Password must be at least {} characters",
                ep_config.min_password_length
            ),
        ));
    }

    // Lookup current password hash (use dummy hash if not found for timing safety)
    let pwd_record = yauth_entity::passwords::Entity::find_by_id(user.id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let current_hash = pwd_record
        .as_ref()
        .map(|p| p.password_hash.as_str())
        .unwrap_or(&state.dummy_hash);

    // Verify current password (timing-safe)
    let valid = password::verify_password(&input.current_password, current_hash).unwrap_or(false);
    if !valid || pwd_record.is_none() {
        warn!(
            event = "change_password_wrong_current",
            user_id = %user.id,
            "Change password failed: wrong current password"
        );
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "Current password is incorrect",
        ));
    }

    // HIBP check on new password
    if ep_config.hibp_check
        && let Some(breach_msg) = hibp::validate_password_not_breached(&input.new_password).await
    {
        warn!(
            event = "change_password_breached",
            user_id = %user.id,
            "Breached password rejected on change"
        );
        return Err(err(StatusCode::BAD_REQUEST, &breach_msg));
    }

    // Hash new password
    let new_hash = password::hash_password(&input.new_password).map_err(|e| {
        tracing::error!("Password hash error: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Update password
    let existing = pwd_record.unwrap();
    let mut pwd_active: yauth_entity::passwords::ActiveModel = existing.into();
    pwd_active.password_hash = Set(new_hash);
    pwd_active.update(&state.db).await.map_err(|e| {
        tracing::error!("Failed to update password: {}", e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Invalidate all OTHER sessions (keep current session via cookie match)
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let current_token_hash = crypto::hash_token(cookie.value());
        session::delete_other_user_sessions(&state.db, user.id, &current_token_hash)
            .await
            .ok();
    } else {
        // No session cookie (e.g., bearer auth) — invalidate all sessions
        session::delete_all_user_sessions(&state.db, user.id)
            .await
            .ok();
    }

    // Emit event
    state.emit_event(&AuthEvent::PasswordChanged { user_id: user.id });

    info!(
        event = "password_changed",
        user_id = %user.id,
        "Password changed successfully, other sessions invalidated"
    );

    Ok(Json(MessageResponse {
        message: "Password changed successfully.".to_string(),
    }))
}
