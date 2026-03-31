use axum::{
    Extension, Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
    routing::post,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{crypto, hibp, input, password, password_policy, session};
use crate::db::models::{
    EmailVerification, NewEmailVerification, NewPassword, NewPasswordReset, NewUser, Password,
    PasswordReset, UpdateUser, User,
};
use crate::db::schema::{
    yauth_email_verifications, yauth_password_resets, yauth_passwords, yauth_users,
};
use crate::error::api_err;
use crate::middleware::AuthUser;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

use crate::config::EmailPasswordConfig;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;

const VERIFICATION_TOKEN_EXPIRY_HOURS: i64 = 24;
const RESET_TOKEN_EXPIRY_HOURS: i64 = 1;

pub struct EmailPasswordPlugin;

impl EmailPasswordPlugin {
    pub fn new(_config: EmailPasswordConfig) -> Self {
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

use crate::auth::session::session_set_cookie;

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub remember_me: Option<bool>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

async fn register(
    State(state): State<YAuthState>,
    Json(input): Json<RegisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if !state.config.allow_signups {
        warn!(
            event = "yauth.register.disabled",
            "Registration attempted while signups are disabled"
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Registration is currently disabled",
        ));
    }

    if !state.rate_limiter.check("register").await {
        warn!(
            event = "yauth.register.rate_limited",
            "Registration rate limited"
        );
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let email = input::sanitize(&input.email).to_lowercase();
    let pwd = input::sanitize_password(&input.password);
    if email.is_empty() || pwd.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Email and password are required",
        ));
    }

    if !input::is_valid_email(&email) {
        return Err(api_err(StatusCode::BAD_REQUEST, "Invalid email address"));
    }

    let ep_config = &state.email_password_config;
    if pwd.len() < ep_config.min_password_length {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Password must be at least {} characters",
                ep_config.min_password_length
            ),
        ));
    }

    let violations = password_policy::validate(&pwd, &ep_config.password_policy);
    if !violations.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, &violations.join("; ")));
    }

    if ep_config.hibp_check
        && let Some(breach_msg) = hibp::validate_password_not_breached(&pwd).await
    {
        warn!(event = "yauth.register.breached_password", email = %email, "Breached password rejected");
        return Err(api_err(StatusCode::BAD_REQUEST, &breach_msg));
    }

    // Get diesel connection for this handler
    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Check if user exists
    let existing: Option<User> = yauth_users::table
        .filter(yauth_users::email.eq(&email))
        .select(User::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if existing.is_some() {
        warn!(event = "yauth.register.duplicate", email = %email, "Registration attempt with existing email");
        return Err(api_err(StatusCode::CONFLICT, "Registration failed"));
    }

    let password_hash = password::hash_password(&pwd).map_err(|e| {
        tracing::error!("Password hash error: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let user_id = Uuid::new_v4();

    let role = if state.should_auto_admin().await {
        info!(event = "yauth.register.auto_admin", email = %email, "First user — assigning admin role");
        "admin".to_string()
    } else {
        "user".to_string()
    };

    let now = chrono::Utc::now().naive_utc();
    let new_user = NewUser {
        id: user_id,
        email: email.clone(),
        display_name: input.display_name.as_ref().map(|n| input::sanitize(n)),
        email_verified: !ep_config.require_email_verification,
        role: role.clone(),
        banned: false,
        banned_reason: None,
        banned_until: None,
        created_at: now,
        updated_at: now,
    };

    diesel::insert_into(yauth_users::table)
        .values(&new_user)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create user: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let new_password = NewPassword {
        user_id,
        password_hash: password_hash.clone(),
    };

    diesel::insert_into(yauth_passwords::table)
        .values(&new_password)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to store password: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if ep_config.require_email_verification {
        let token = crypto::generate_token();
        let token_hash = crypto::hash_token(&token);
        let expires_at =
            chrono::Utc::now() + chrono::Duration::hours(VERIFICATION_TOKEN_EXPIRY_HOURS);

        let new_verification = NewEmailVerification {
            id: Uuid::new_v4(),
            user_id,
            token_hash,
            expires_at: expires_at.naive_utc(),
            created_at: chrono::Utc::now().naive_utc(),
        };

        diesel::insert_into(yauth_email_verifications::table)
            .values(&new_verification)
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create email verification: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        if let Some(ref email_service) = state.email_service
            && let Err(e) = email_service.send_verification_email(&email, &token)
        {
            tracing::error!("Failed to send verification email: {}", e);
        }
    }

    info!(event = "yauth.register", email = %email, user_id = %user_id, "User registered");

    state
        .write_audit_log(
            Some(user_id),
            "user_registered",
            Some(serde_json::json!({ "email": email, "method": "email-password" })),
            None,
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(MessageResponse {
            message: "Account created. Please check your email to verify your address.".to_string(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

async fn login(
    State(state): State<YAuthState>,
    Json(input): Json<LoginRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let email = input::sanitize(&input.email).to_lowercase();
    let password_input = input::sanitize_password(&input.password);

    if !state.rate_limiter.check(&format!("login:{}", email)).await {
        warn!(event = "yauth.login.rate_limited", email = %email, "Login rate limited");
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Shared struct for user data
    struct LoginUser {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
        banned: bool,
    }

    let (user_opt, hash) = {
        let user: Option<User> = yauth_users::table
            .filter(yauth_users::email.eq(&email))
            .select(User::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        match user {
            Some(u) => {
                let pwd: Option<Password> = yauth_passwords::table
                    .find(u.id)
                    .select(Password::as_select())
                    .first(&mut conn)
                    .await
                    .optional()
                    .map_err(|e| {
                        tracing::error!("DB error: {}", e);
                        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })?;
                let h = pwd
                    .map(|p| p.password_hash)
                    .unwrap_or_else(|| state.dummy_hash.clone());
                (
                    Some(LoginUser {
                        id: u.id,
                        email: u.email,
                        display_name: u.display_name,
                        email_verified: u.email_verified,
                        banned: u.banned,
                    }),
                    h,
                )
            }
            None => (None, state.dummy_hash.clone()),
        }
    };

    let valid = password::verify_password(&password_input, &hash).unwrap_or(false);

    match (user_opt, valid) {
        (Some(u), true) => {
            if u.banned {
                warn!(event = "yauth.login.banned", email = %u.email, "Login attempt by banned user");
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }

            if state.email_password_config.require_email_verification && !u.email_verified {
                warn!(event = "yauth.login.email_not_verified", email = %u.email, "Login attempt with unverified email");
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    "Email not verified. Please check your inbox or request a new verification email.",
                ));
            }

            let event_response = state.emit_event(&AuthEvent::LoginSucceeded {
                user_id: u.id,
                method: "email-password".to_string(),
            });

            match event_response {
                EventResponse::RequireMfa {
                    pending_session_id, ..
                } => {
                    info!(event = "yauth.login.mfa_required", email = %u.email, user_id = %u.id, "Login requires MFA");
                    Ok(Json(serde_json::json!({
                        "mfa_required": true,
                        "pending_session_id": pending_session_id,
                    }))
                    .into_response())
                }
                EventResponse::Block { status, message } => {
                    warn!(event = "yauth.login.blocked", email = %u.email, "Login blocked");
                    let status_code =
                        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    Err(api_err(status_code, &message))
                }
                EventResponse::Continue => {
                    let session_ttl = if input.remember_me.unwrap_or(false) {
                        state
                            .config
                            .remember_me_ttl
                            .map(|d| d.as_duration())
                            .unwrap_or(state.config.session_ttl)
                    } else {
                        state.config.session_ttl
                    };
                    let (token, _session_id) =
                        session::create_session(&state.db, u.id, None, None, session_ttl)
                            .await
                            .map_err(|e| {
                                tracing::error!("Failed to create session: {}", e);
                                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                            })?;

                    info!(event = "yauth.login", email = %u.email, user_id = %u.id, "User logged in");

                    state
                        .write_audit_log(
                            Some(u.id),
                            "login_succeeded",
                            Some(serde_json::json!({ "method": "email-password" })),
                            None,
                        )
                        .await;

                    Ok((
                        [(SET_COOKIE, session_set_cookie(&state, &token, session_ttl))],
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
            warn!(event = "yauth.login.failed", email = %email, "Failed login attempt");
            state.write_audit_log(
                None,
                "login_failed",
                Some(serde_json::json!({ "email": email, "method": "email-password", "reason": "invalid_credentials" })),
                None,
            ).await;

            let event_response = state.emit_event(&AuthEvent::LoginFailed {
                email: email.clone(),
                method: "email-password".to_string(),
                reason: "invalid_credentials".to_string(),
            });

            match event_response {
                EventResponse::Block { status, message } => {
                    let status_code =
                        StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED);
                    Err(api_err(status_code, &message))
                }
                _ => Err(api_err(
                    StatusCode::UNAUTHORIZED,
                    "Invalid email or password",
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Verify Email
// ---------------------------------------------------------------------------

async fn verify_email(
    State(state): State<YAuthState>,
    Json(input): Json<VerifyEmailRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let token = input::sanitize(&input.token);
    if token.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Verification token is required",
        ));
    }

    let token_hash = crypto::hash_token(&token);

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    {
        let verification: EmailVerification = yauth_email_verifications::table
            .filter(yauth_email_verifications::token_hash.eq(&token_hash))
            .select(EmailVerification::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| {
                api_err(
                    StatusCode::BAD_REQUEST,
                    "Invalid or expired verification link",
                )
            })?;

        let now = chrono::Utc::now().naive_utc();
        if verification.expires_at < now {
            diesel::delete(yauth_email_verifications::table.find(verification.id))
                .execute(&mut conn)
                .await
                .ok();
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "Verification link has expired. Please request a new one.",
            ));
        }

        let changeset = UpdateUser {
            email: None,
            display_name: None,
            email_verified: Some(true),
            role: None,
            banned: None,
            banned_reason: None,
            banned_until: None,
            updated_at: Some(chrono::Utc::now().naive_utc()),
        };

        diesel::update(yauth_users::table.find(verification.user_id))
            .set(&changeset)
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to update user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        diesel::delete(
            yauth_email_verifications::table
                .filter(yauth_email_verifications::user_id.eq(verification.user_id)),
        )
        .execute(&mut conn)
        .await
        .ok();

        info!(event = "yauth.email.verified", user_id = %verification.user_id, "Email verified");
        state
            .write_audit_log(Some(verification.user_id), "email_verified", None, None)
            .await;
    }

    Ok(Json(MessageResponse {
        message: "Email verified successfully. You can now sign in.".to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Resend Verification
// ---------------------------------------------------------------------------

async fn resend_verification(
    State(state): State<YAuthState>,
    Json(input): Json<ResendVerificationRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let email = input::sanitize(&input.email).to_lowercase();

    if !state.rate_limiter.check(&format!("resend:{}", email)).await {
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let success_msg = Json(MessageResponse {
        message: "If an account exists with that email, a verification link has been sent."
            .to_string(),
    });

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    let user_opt: Option<User> = yauth_users::table
        .filter(yauth_users::email.eq(&email))
        .select(User::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let user_id = match user_opt {
        Some(ref u) if !u.email_verified => u.id,
        _ => return Ok(success_msg),
    };

    diesel::delete(
        yauth_email_verifications::table.filter(yauth_email_verifications::user_id.eq(user_id)),
    )
    .execute(&mut conn)
    .await
    .ok();

    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(VERIFICATION_TOKEN_EXPIRY_HOURS);

    let new_verification = NewEmailVerification {
        id: Uuid::new_v4(),
        user_id,
        token_hash,
        expires_at: expires_at.naive_utc(),
        created_at: chrono::Utc::now().naive_utc(),
    };

    diesel::insert_into(yauth_email_verifications::table)
        .values(&new_verification)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create verification: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_verification_email(&email, &token)
    {
        tracing::error!("Failed to send verification email: {}", e);
    }

    info!(event = "yauth.email.verification_resent", email = %email, "Verification email resent");
    Ok(success_msg)
}

// ---------------------------------------------------------------------------
// Forgot Password
// ---------------------------------------------------------------------------

async fn forgot_password(
    State(state): State<YAuthState>,
    Json(input): Json<ForgotPasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let email = input::sanitize(&input.email).to_lowercase();

    if !state.rate_limiter.check(&format!("forgot:{}", email)).await {
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let success_msg = Json(MessageResponse {
        message: "If an account exists with that email, a password reset link has been sent."
            .to_string(),
    });

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    let user_opt: Option<User> = yauth_users::table
        .filter(yauth_users::email.eq(&email))
        .select(User::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let (user_id, user_email) = match user_opt {
        Some(u) => (u.id, u.email.clone()),
        None => return Ok(success_msg),
    };

    // Delete old unused reset tokens
    diesel::delete(
        yauth_password_resets::table.filter(
            yauth_password_resets::user_id
                .eq(user_id)
                .and(yauth_password_resets::used_at.is_null()),
        ),
    )
    .execute(&mut conn)
    .await
    .ok();

    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(RESET_TOKEN_EXPIRY_HOURS);

    let new_reset = NewPasswordReset {
        id: Uuid::new_v4(),
        user_id,
        token_hash,
        expires_at: expires_at.naive_utc(),
        created_at: chrono::Utc::now().naive_utc(),
    };

    diesel::insert_into(yauth_password_resets::table)
        .values(&new_reset)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create password reset: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_password_reset_email(&user_email, &token)
    {
        tracing::error!("Failed to send password reset email: {}", e);
    }

    info!(event = "yauth.password.reset_requested", email = %email, user_id = %user_id, "Password reset email sent");
    Ok(success_msg)
}

// ---------------------------------------------------------------------------
// Reset Password
// ---------------------------------------------------------------------------

async fn reset_password(
    State(state): State<YAuthState>,
    Json(input): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let token = input::sanitize(&input.token);
    if token.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "Reset token is required"));
    }

    let reset_password = input::sanitize_password(&input.password);
    let ep_config = &state.email_password_config;

    if reset_password.len() < ep_config.min_password_length {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Password must be at least {} characters",
                ep_config.min_password_length
            ),
        ));
    }

    let violations = password_policy::validate(&reset_password, &ep_config.password_policy);
    if !violations.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, &violations.join("; ")));
    }

    if ep_config.hibp_check
        && let Some(breach_msg) = hibp::validate_password_not_breached(&reset_password).await
    {
        return Err(api_err(StatusCode::BAD_REQUEST, &breach_msg));
    }

    let token_hash = crypto::hash_token(&token);

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Find reset token and get user_id + expiry
    struct ResetInfo {
        id: Uuid,
        user_id: Uuid,
        expired: bool,
    }

    let reset_info = {
        let reset: PasswordReset = yauth_password_resets::table
            .filter(
                yauth_password_resets::token_hash
                    .eq(&token_hash)
                    .and(yauth_password_resets::used_at.is_null()),
            )
            .select(PasswordReset::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Invalid or expired reset link"))?;

        let now = chrono::Utc::now().naive_utc();
        ResetInfo {
            id: reset.id,
            user_id: reset.user_id,
            expired: reset.expires_at < now,
        }
    };

    if reset_info.expired {
        diesel::delete(yauth_password_resets::table.find(reset_info.id))
            .execute(&mut conn)
            .await
            .ok();
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Reset link has expired. Please request a new one.",
        ));
    }

    let new_hash = password::hash_password(&reset_password).map_err(|e| {
        tracing::error!("Password hash error: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Update password (upsert)
    let upsert_password = NewPassword {
        user_id: reset_info.user_id,
        password_hash: new_hash.clone(),
    };

    diesel::insert_into(yauth_passwords::table)
        .values(&upsert_password)
        .on_conflict(yauth_passwords::user_id)
        .do_update()
        .set(yauth_passwords::password_hash.eq(&new_hash))
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update password: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let changeset = UpdateUser {
        email: None,
        display_name: None,
        email_verified: Some(true),
        role: None,
        banned: None,
        banned_reason: None,
        banned_until: None,
        updated_at: Some(chrono::Utc::now().naive_utc()),
    };

    diesel::update(yauth_users::table.find(reset_info.user_id))
        .set(&changeset)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update user: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    diesel::update(yauth_password_resets::table.find(reset_info.id))
        .set(yauth_password_resets::used_at.eq(Some(chrono::Utc::now().naive_utc())))
        .execute(&mut conn)
        .await
        .ok();

    session::delete_all_user_sessions(&state.db, reset_info.user_id)
        .await
        .ok();

    info!(event = "yauth.password.reset", user_id = %reset_info.user_id, "Password reset successfully");
    state
        .write_audit_log(Some(reset_info.user_id), "password_reset", None, None)
        .await;

    Ok(Json(MessageResponse {
        message: "Password reset successfully. You can now sign in with your new password."
            .to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Change Password
// ---------------------------------------------------------------------------

async fn change_password(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    jar: CookieJar,
    Json(input): Json<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !state
        .rate_limiter
        .check(&format!("change-pwd:{}", user.id))
        .await
    {
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let current_password = input::sanitize_password(&input.current_password);
    let new_password = input::sanitize_password(&input.new_password);
    let ep_config = &state.email_password_config;

    if new_password.len() < ep_config.min_password_length {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Password must be at least {} characters",
                ep_config.min_password_length
            ),
        ));
    }

    let violations = password_policy::validate(&new_password, &ep_config.password_policy);
    if !violations.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, &violations.join("; ")));
    }

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Get current password hash
    let pwd_record: Option<Password> = yauth_passwords::table
        .find(user.id)
        .select(Password::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let current_hash = pwd_record
        .as_ref()
        .map(|p| p.password_hash.as_str())
        .unwrap_or(&state.dummy_hash);

    let valid = password::verify_password(&current_password, current_hash).unwrap_or(false);
    if !valid || pwd_record.is_none() {
        warn!(event = "yauth.password.change_failed", user_id = %user.id, "Wrong current password");
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Current password is incorrect",
        ));
    }

    if ep_config.hibp_check
        && let Some(breach_msg) = hibp::validate_password_not_breached(&new_password).await
    {
        return Err(api_err(StatusCode::BAD_REQUEST, &breach_msg));
    }

    let new_hash = password::hash_password(&new_password).map_err(|e| {
        tracing::error!("Password hash error: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    diesel::update(yauth_passwords::table.find(user.id))
        .set(yauth_passwords::password_hash.eq(&new_hash))
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update password: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let current_token_hash = crypto::hash_token(cookie.value());
        session::delete_other_user_sessions(&state.db, user.id, &current_token_hash)
            .await
            .ok();
    } else {
        session::delete_all_user_sessions(&state.db, user.id)
            .await
            .ok();
    }

    state.emit_event(&AuthEvent::PasswordChanged { user_id: user.id });

    info!(event = "yauth.password.changed", user_id = %user.id, "Password changed successfully");
    state
        .write_audit_log(Some(user.id), "password_changed", None, None)
        .await;

    Ok(Json(MessageResponse {
        message: "Password changed successfully.".to_string(),
    }))
}
