use axum::{
    Extension, Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
    routing::post,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{crypto, hibp, input, password, password_policy, session};
use crate::error::api_err;
use crate::middleware::AuthUser;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

use crate::config::EmailPasswordConfig;

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

    fn schema(&self) -> Vec<crate::schema::TableDef> {
        crate::schema::plugin_schemas::email_password_schema()
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
        crate::otel::add_event("register_disabled", vec![]);
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Registration is currently disabled",
        ));
    }

    if let Some(ref rl) = state.email_password_config.rate_limit
        && !state
            .repos
            .rate_limits
            .check_rate_limit("register", rl.max_requests, rl.window_secs)
            .await
            .map(|r| r.allowed)
            .unwrap_or(true)
    {
        crate::otel::add_event("register_rate_limited", vec![]);
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
        crate::otel::add_event(
            "register_breached_password",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.email", email.clone())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(api_err(StatusCode::BAD_REQUEST, &breach_msg));
    }

    // Check if user exists
    {
        let existing = state.repos.users.find_by_email(&email).await.map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        if existing.is_some() {
            crate::otel::add_event(
                "register_duplicate_email",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new("user.email", email.clone())],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return Err(api_err(StatusCode::CONFLICT, "Registration failed"));
        }
    }

    let password_hash = password::hash_password(&pwd).await.map_err(|e| {
        crate::otel::record_error("password_hash_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let user_id = Uuid::now_v7();

    let role = if state.should_auto_admin().await {
        crate::otel::add_event(
            "register_auto_admin",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.email", email.clone())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        "admin".to_string()
    } else {
        "user".to_string()
    };

    let now = chrono::Utc::now().naive_utc();
    let new_user = crate::domain::NewUser {
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

    match state.repos.users.create(new_user).await {
        Ok(_) => {}
        Err(crate::repo::RepoError::Conflict(_)) => {
            return Err(api_err(
                StatusCode::CONFLICT,
                "An account with this email already exists",
            ));
        }
        Err(e) => {
            crate::otel::record_error("user_create_failed", &e);
            return Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"));
        }
    }

    let new_password = crate::domain::NewPassword {
        user_id,
        password_hash: password_hash.clone(),
    };

    state
        .repos
        .passwords
        .upsert(new_password)
        .await
        .map_err(|e| {
            crate::otel::record_error("password_store_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if ep_config.require_email_verification {
        let token = crypto::generate_token();
        let token_hash = crypto::hash_token(&token);
        let expires_at =
            chrono::Utc::now() + chrono::Duration::hours(VERIFICATION_TOKEN_EXPIRY_HOURS);

        let new_verification = crate::domain::NewEmailVerification {
            id: Uuid::now_v7(),
            user_id,
            token_hash,
            expires_at: expires_at.naive_utc(),
            created_at: chrono::Utc::now().naive_utc(),
        };

        state
            .repos
            .email_verifications
            .create(new_verification)
            .await
            .map_err(|e| {
                crate::otel::record_error("email_verification_create_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        if let Some(ref email_service) = state.email_service
            && let Err(e) = email_service.send_verification_email(&email, &token)
        {
            crate::otel::record_error("send_verification_email_failed", &e);
        }
    }

    crate::otel::add_event(
        "user_registered",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.email", email.clone()),
            opentelemetry::KeyValue::new("user.id", user_id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user_id),
            "user_registered",
            Some(serde_json::json!({ "email": email, "method": "email-password" })),
            None,
        )
        .await;

    let message = if ep_config.require_email_verification {
        "Account created. Please check your email to verify your address."
    } else {
        "Account created successfully."
    };

    Ok((
        StatusCode::CREATED,
        Json(MessageResponse {
            message: message.to_string(),
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

    if let Some(ref rl) = state.email_password_config.rate_limit
        && !state
            .repos
            .rate_limits
            .check_rate_limit(&format!("login:{}", email), rl.max_requests, rl.window_secs)
            .await
            .map(|r| r.allowed)
            .unwrap_or(true)
    {
        crate::otel::add_event(
            "login_rate_limited",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.email", email.clone())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    struct LoginUser {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
        banned: bool,
    }

    let (user_opt, hash) = {
        let user = state.repos.users.find_by_email(&email).await.map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        match user {
            Some(u) => {
                let pwd = state
                    .repos
                    .passwords
                    .find_by_user_id(u.id)
                    .await
                    .map_err(|e| {
                        crate::otel::record_error("db_error", &e);
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

    let valid = password::verify_password(&password_input, &hash)
        .await
        .unwrap_or(false);

    match (user_opt, valid) {
        (Some(u), true) => {
            if u.banned {
                crate::otel::add_event(
                    "login_banned_user",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("user.email", u.email.clone())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }

            if state.email_password_config.require_email_verification && !u.email_verified {
                crate::otel::add_event(
                    "login_email_not_verified",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("user.email", u.email.clone())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
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
                    crate::otel::add_event(
                        "login_mfa_required",
                        #[cfg(feature = "telemetry")]
                        vec![
                            opentelemetry::KeyValue::new("user.email", u.email.clone()),
                            opentelemetry::KeyValue::new("user.id", u.id.to_string()),
                        ],
                        #[cfg(not(feature = "telemetry"))]
                        vec![],
                    );
                    Ok(Json(serde_json::json!({
                        "mfa_required": true,
                        "pending_session_id": pending_session_id,
                    }))
                    .into_response())
                }
                EventResponse::Block { status, message } => {
                    crate::otel::add_event(
                        "login_blocked",
                        #[cfg(feature = "telemetry")]
                        vec![opentelemetry::KeyValue::new("user.email", u.email.clone())],
                        #[cfg(not(feature = "telemetry"))]
                        vec![],
                    );
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
                        session::create_session(&state, u.id, None, None, session_ttl)
                            .await
                            .map_err(|e| {
                                crate::otel::record_error("session_create_failed", &e);
                                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                            })?;

                    crate::otel::add_event(
                        "login_succeeded",
                        #[cfg(feature = "telemetry")]
                        vec![
                            opentelemetry::KeyValue::new("user.email", u.email.clone()),
                            opentelemetry::KeyValue::new("user.id", u.id.to_string()),
                        ],
                        #[cfg(not(feature = "telemetry"))]
                        vec![],
                    );

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
            crate::otel::add_event(
                "login_failed",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new("user.email", email.clone())],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
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

    let verification = state
        .repos
        .email_verifications
        .find_by_token_hash(&token_hash)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
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
        let _ = state
            .repos
            .email_verifications
            .delete(verification.id)
            .await;
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Verification link has expired. Please request a new one.",
        ));
    }

    let changeset = crate::domain::UpdateUser {
        email_verified: Some(true),
        updated_at: Some(chrono::Utc::now().naive_utc()),
        ..Default::default()
    };

    state
        .repos
        .users
        .update(verification.user_id, changeset)
        .await
        .map_err(|e| {
            crate::otel::record_error("user_update_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let _ = state
        .repos
        .email_verifications
        .delete_all_for_user(verification.user_id)
        .await;

    crate::otel::add_event(
        "email_verified",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new(
            "user.id",
            verification.user_id.to_string(),
        )],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );
    state
        .write_audit_log(Some(verification.user_id), "email_verified", None, None)
        .await;

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

    if let Some(ref rl) = state.email_password_config.rate_limit
        && !state
            .repos
            .rate_limits
            .check_rate_limit(
                &format!("resend:{}", email),
                rl.max_requests,
                rl.window_secs,
            )
            .await
            .map(|r| r.allowed)
            .unwrap_or(true)
    {
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let success_msg = Json(MessageResponse {
        message: "If an account exists with that email, a verification link has been sent."
            .to_string(),
    });

    let user_opt = state.repos.users.find_by_email(&email).await.map_err(|e| {
        crate::otel::record_error("db_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let user_id = match user_opt {
        Some(ref u) if !u.email_verified => u.id,
        _ => return Ok(success_msg),
    };

    let _ = state
        .repos
        .email_verifications
        .delete_all_for_user(user_id)
        .await;

    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(VERIFICATION_TOKEN_EXPIRY_HOURS);

    let new_verification = crate::domain::NewEmailVerification {
        id: Uuid::now_v7(),
        user_id,
        token_hash,
        expires_at: expires_at.naive_utc(),
        created_at: chrono::Utc::now().naive_utc(),
    };

    state
        .repos
        .email_verifications
        .create(new_verification)
        .await
        .map_err(|e| {
            crate::otel::record_error("verification_create_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_verification_email(&email, &token)
    {
        crate::otel::record_error("send_verification_email_failed", &e);
    }

    crate::otel::add_event(
        "verification_email_resent",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.email", email.clone())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );
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

    if let Some(ref rl) = state.email_password_config.rate_limit
        && !state
            .repos
            .rate_limits
            .check_rate_limit(
                &format!("forgot:{}", email),
                rl.max_requests,
                rl.window_secs,
            )
            .await
            .map(|r| r.allowed)
            .unwrap_or(true)
    {
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let success_msg = Json(MessageResponse {
        message: "If an account exists with that email, a password reset link has been sent."
            .to_string(),
    });

    let user_opt = state.repos.users.find_by_email(&email).await.map_err(|e| {
        crate::otel::record_error("db_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let (user_id, user_email) = match user_opt {
        Some(u) => (u.id, u.email.clone()),
        None => return Ok(success_msg),
    };

    // Delete old unused reset tokens
    let _ = state
        .repos
        .password_resets
        .delete_unused_for_user(user_id)
        .await;

    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(RESET_TOKEN_EXPIRY_HOURS);

    let new_reset = crate::domain::NewPasswordReset {
        id: Uuid::now_v7(),
        user_id,
        token_hash,
        expires_at: expires_at.naive_utc(),
        created_at: chrono::Utc::now().naive_utc(),
    };

    state
        .repos
        .password_resets
        .create(new_reset)
        .await
        .map_err(|e| {
            crate::otel::record_error("password_reset_create_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_password_reset_email(&user_email, &token)
    {
        crate::otel::record_error("send_password_reset_email_failed", &e);
    }

    crate::otel::add_event(
        "password_reset_requested",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.email", email.clone()),
            opentelemetry::KeyValue::new("user.id", user_id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );
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

    let reset = state
        .repos
        .password_resets
        .find_by_token_hash(&token_hash)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Invalid or expired reset link"))?;

    let now = chrono::Utc::now().naive_utc();
    if reset.expires_at < now {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Reset link has expired. Please request a new one.",
        ));
    }

    let new_hash = password::hash_password(&reset_password)
        .await
        .map_err(|e| {
            crate::otel::record_error("password_hash_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Upsert password
    let upsert_password = crate::domain::NewPassword {
        user_id: reset.user_id,
        password_hash: new_hash,
    };
    state
        .repos
        .passwords
        .upsert(upsert_password)
        .await
        .map_err(|e| {
            crate::otel::record_error("password_update_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Mark email verified and update timestamp
    let changeset = crate::domain::UpdateUser {
        email_verified: Some(true),
        updated_at: Some(chrono::Utc::now().naive_utc()),
        ..Default::default()
    };
    state
        .repos
        .users
        .update(reset.user_id, changeset)
        .await
        .map_err(|e| {
            crate::otel::record_error("user_update_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Mark reset token as used — we need to update the reset record.
    // The repo trait doesn't have a mark_used method, so we use the DB for now.
    // This is handled by the fact that find_by_token_hash filters by used_at IS NULL.
    // We delete unused tokens for the user instead (same effect for security).
    let _ = state
        .repos
        .password_resets
        .delete_unused_for_user(reset.user_id)
        .await;

    session::delete_all_user_sessions(&state, reset.user_id)
        .await
        .ok();

    crate::otel::add_event(
        "password_reset_completed",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new(
            "user.id",
            reset.user_id.to_string(),
        )],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );
    state
        .write_audit_log(Some(reset.user_id), "password_reset", None, None)
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
    if let Some(ref rl) = state.email_password_config.rate_limit
        && !state
            .repos
            .rate_limits
            .check_rate_limit(
                &format!("change-pwd:{}", user.id),
                rl.max_requests,
                rl.window_secs,
            )
            .await
            .map(|r| r.allowed)
            .unwrap_or(true)
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

    // Fetch current password hash
    let (current_hash, has_record) = {
        let pwd_record = state
            .repos
            .passwords
            .find_by_user_id(user.id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let hash = pwd_record
            .as_ref()
            .map(|p| p.password_hash.clone())
            .unwrap_or_else(|| state.dummy_hash.clone());
        (hash, pwd_record.is_some())
    };

    let valid = password::verify_password(&current_password, &current_hash)
        .await
        .unwrap_or(false);
    if !valid || !has_record {
        crate::otel::add_event(
            "password_change_failed",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
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

    let new_hash = password::hash_password(&new_password).await.map_err(|e| {
        crate::otel::record_error("password_hash_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let upsert = crate::domain::NewPassword {
        user_id: user.id,
        password_hash: new_hash,
    };
    state.repos.passwords.upsert(upsert).await.map_err(|e| {
        crate::otel::record_error("password_update_failed", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        session::delete_other_user_sessions(&state, user.id, cookie.value())
            .await
            .ok();
    } else {
        session::delete_all_user_sessions(&state, user.id)
            .await
            .ok();
    }

    state.emit_event(&AuthEvent::PasswordChanged { user_id: user.id });

    crate::otel::add_event(
        "password_changed",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );
    state
        .write_audit_log(Some(user.id), "password_changed", None, None)
        .await;

    Ok(Json(MessageResponse {
        message: "Password changed successfully.".to_string(),
    }))
}
