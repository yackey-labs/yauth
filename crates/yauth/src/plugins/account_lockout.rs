use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware as axum_mw,
    routing::post,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::crypto;
use crate::config::AccountLockoutConfig;
use crate::error::api_err;
use crate::middleware::require_admin;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::repo::Repositories;
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

pub struct AccountLockoutPlugin;

impl YAuthPlugin for AccountLockoutPlugin {
    fn name(&self) -> &'static str {
        "account-lockout"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/account/request-unlock", post(request_unlock))
                .route("/account/unlock", post(unlock_account)),
        )
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/admin/users/{id}/unlock", post(admin_unlock))
                .layer(axum_mw::from_fn(require_admin)),
        )
    }

    fn on_event(&self, event: &AuthEvent, ctx: &PluginContext) -> EventResponse {
        match event {
            AuthEvent::LoginFailed { email, .. } => {
                let email = email.clone();
                let repos = ctx.state.repos.clone();
                let config = ctx.state.account_lockout_config.clone();

                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { handle_login_failed(&repos, &config, &email).await })
                })
            }
            AuthEvent::LoginSucceeded { user_id, .. } => {
                let user_id = *user_id;
                let repos = ctx.state.repos.clone();
                let config = ctx.state.account_lockout_config.clone();

                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { handle_login_succeeded(&repos, &config, user_id).await })
                })
            }
            _ => EventResponse::Continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Event handlers (async logic)
// ---------------------------------------------------------------------------

/// Check if account is locked, increment failed count, lock if threshold exceeded.
async fn handle_login_failed(
    repos: &Repositories,
    config: &AccountLockoutConfig,
    email: &str,
) -> EventResponse {
    // Find user by email
    let user_id = match repos.users.find_by_email(email).await {
        Ok(Some(u)) => u.id,
        Ok(None) => return EventResponse::Continue,
        Err(e) => {
            crate::otel::record_error("lockout_user_lookup_error", &e);
            return EventResponse::Continue;
        }
    };

    let now = Utc::now().fixed_offset();

    // Find or create account lock record
    let lock_record = match repos.account_locks.find_by_user_id(user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            let new_lock = crate::domain::NewAccountLock {
                id: Uuid::new_v4(),
                user_id,
                failed_count: 0,
                locked_until: None,
                lock_count: 0,
                locked_reason: None,
                created_at: now.naive_utc(),
                updated_at: now.naive_utc(),
            };
            match repos.account_locks.create(new_lock).await {
                Ok(r) => r,
                Err(e) => {
                    crate::otel::record_error("lockout_create_lock_failed", &e);
                    return EventResponse::Continue;
                }
            }
        }
        Err(e) => {
            crate::otel::record_error("lockout_check_lock_error", &e);
            return EventResponse::Continue;
        }
    };

    // Check if already locked and not expired
    if let Some(locked_until) = lock_record.locked_until {
        let locked_until_fo = locked_until.and_utc().fixed_offset();
        if now < locked_until_fo {
            crate::otel::add_event(
                "lockout_blocked",
                #[cfg(feature = "telemetry")]
                vec![
                    opentelemetry::KeyValue::new("user.email", email.to_string()),
                    opentelemetry::KeyValue::new("locked_until", locked_until_fo.to_string()),
                ],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return EventResponse::Block {
                status: 423,
                message: format!(
                    "Account is locked. Try again after {}.",
                    locked_until_fo.format("%Y-%m-%d %H:%M:%S UTC")
                ),
            };
        }
        if config.auto_unlock
            && let Err(e) = repos.account_locks.auto_unlock(lock_record.id).await
        {
            crate::otel::record_error("lockout_auto_unlock_failed", &e);
        }
    }

    // Re-read lock record after potential auto-unlock reset
    let lock_record = match repos.account_locks.find_by_user_id(user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return EventResponse::Continue,
        Err(e) => {
            crate::otel::record_error("lockout_reread_lock_error", &e);
            return EventResponse::Continue;
        }
    };

    // Check if we are within the attempt window
    let window_start = now - chrono::Duration::seconds(config.attempt_window.as_secs() as i64);
    let updated_at_fo = lock_record.updated_at.and_utc().fixed_offset();
    let new_failed_count = if updated_at_fo < window_start {
        // Window expired — reset then increment (result: 1)
        if let Err(e) = repos.account_locks.reset_failed_count(lock_record.id).await {
            crate::otel::record_error("lockout_reset_failed_count_error", &e);
        }
        1
    } else {
        lock_record.failed_count + 1
    };

    // Increment failed count
    if let Err(e) = repos
        .account_locks
        .increment_failed_count(lock_record.id)
        .await
    {
        crate::otel::record_error("lockout_update_failed_count_error", &e);
    }

    // Check if we have exceeded the threshold
    if new_failed_count >= config.max_failed_attempts as i32 {
        let new_lock_count = lock_record.lock_count + 1;
        let lockout_duration = calculate_lockout_duration(config, new_lock_count as u32);
        let locked_until = now + chrono::Duration::seconds(lockout_duration.as_secs() as i64);

        if let Err(e) = repos
            .account_locks
            .set_locked(
                lock_record.id,
                Some(locked_until.naive_utc()),
                Some("Too many failed login attempts"),
                new_lock_count,
            )
            .await
        {
            crate::otel::record_error("lockout_update_lock_failed", &e);
            return EventResponse::Continue;
        }

        crate::otel::add_event(
            "lockout_account_locked",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("user.email", email.to_string()),
                opentelemetry::KeyValue::new("user.id", user_id.to_string()),
                opentelemetry::KeyValue::new("lock_count", new_lock_count as i64),
                opentelemetry::KeyValue::new("locked_until", locked_until.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );

        return EventResponse::Block {
            status: 423,
            message: format!(
                "Account has been locked due to too many failed login attempts. Try again after {}.",
                locked_until.format("%Y-%m-%d %H:%M:%S UTC")
            ),
        };
    }

    EventResponse::Continue
}

/// On successful login, check if account is locked first. If not, reset failed count.
async fn handle_login_succeeded(
    repos: &Repositories,
    _config: &AccountLockoutConfig,
    user_id: Uuid,
) -> EventResponse {
    let now = Utc::now().fixed_offset();

    let lock_record = match repos.account_locks.find_by_user_id(user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return EventResponse::Continue,
        Err(e) => {
            crate::otel::record_error("lockout_check_lock_on_success_error", &e);
            return EventResponse::Continue;
        }
    };

    // Check if account is currently locked
    if let Some(locked_until) = lock_record.locked_until {
        let locked_until_fo = locked_until.and_utc().fixed_offset();
        if now < locked_until_fo {
            crate::otel::add_event(
                "lockout_blocked_valid_credentials",
                #[cfg(feature = "telemetry")]
                vec![
                    opentelemetry::KeyValue::new("user.id", user_id.to_string()),
                    opentelemetry::KeyValue::new("locked_until", locked_until_fo.to_string()),
                ],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return EventResponse::Block {
                status: 423,
                message: format!(
                    "Account is locked. Try again after {}.",
                    locked_until_fo.format("%Y-%m-%d %H:%M:%S UTC")
                ),
            };
        }
    }

    // Reset failed count on successful login
    if let Err(e) = repos.account_locks.auto_unlock(lock_record.id).await {
        crate::otel::record_error("lockout_reset_on_success_failed", &e);
    }

    EventResponse::Continue
}

// ---------------------------------------------------------------------------
// Lockout duration calculation
// ---------------------------------------------------------------------------

/// Calculate lockout duration with optional exponential backoff.
pub fn calculate_lockout_duration(
    config: &AccountLockoutConfig,
    lock_count: u32,
) -> std::time::Duration {
    if !config.exponential_backoff || lock_count <= 1 {
        return config.lockout_duration;
    }

    // Exponential: base * 2^(lock_count - 1), capped at max
    let multiplier = 2u64.saturating_pow(lock_count - 1);
    let duration_secs = config.lockout_duration.as_secs().saturating_mul(multiplier);
    let capped = duration_secs.min(config.max_lockout_duration.as_secs());

    std::time::Duration::from_secs(capped)
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RequestUnlockRequest {
    pub email: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UnlockAccountRequest {
    pub token: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AccountLockoutMessageResponse {
    pub message: String,
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /account/request-unlock (public)
///
/// Send an unlock email to the user. Always returns a generic success message
/// to avoid leaking whether the account exists or is locked (timing-safe).
async fn request_unlock(
    State(state): State<YAuthState>,
    Json(input): Json<RequestUnlockRequest>,
) -> Result<Json<AccountLockoutMessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let email = input.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "Email is required"));
    }

    // Rate limit unlock requests
    if !state
        .rate_limiter
        .check(&format!("unlock_request:{}", email))
        .await
    {
        crate::otel::add_event(
            "lockout_unlock_rate_limited",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new(
                "user.email",
                email.to_string(),
            )],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    // Look up user (don't leak whether user exists)
    let user_opt = state.repos.users.find_by_email(&email).await.map_err(|e| {
        crate::otel::record_error("db_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    if let Some(user) = user_opt {
        // Check if account is actually locked
        let lock_record = state
            .repos
            .account_locks
            .find_by_user_id(user.id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let is_locked = lock_record
            .as_ref()
            .and_then(|r| r.locked_until)
            .map(|until| Utc::now().fixed_offset() < until.and_utc().fixed_offset())
            .unwrap_or(false);

        if is_locked {
            // Delete any existing unlock tokens for this user
            let _ = state.repos.unlock_tokens.delete_all_for_user(user.id).await;

            // Generate unlock token
            let token = crypto::generate_token();
            let token_hash = crypto::hash_token(&token);
            let now = Utc::now();
            let expires_at = now + chrono::Duration::hours(1);

            let new_token = crate::domain::NewUnlockToken {
                id: Uuid::new_v4(),
                user_id: user.id,
                token_hash,
                expires_at: expires_at.naive_utc(),
                created_at: now.naive_utc(),
            };

            state
                .repos
                .unlock_tokens
                .create(new_token)
                .await
                .map_err(|e| {
                    crate::otel::record_error("lockout_store_unlock_token_failed", &e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

            // Send unlock email if SMTP is configured
            if let Some(ref email_service) = state.email_service {
                let unlock_url =
                    format!("{}/account/unlock?token={}", state.config.base_url, token);
                if let Err(e) = email_service.send_unlock_email(&email, &unlock_url) {
                    crate::otel::record_error("lockout_send_unlock_email_failed", &e);
                    // Don't fail the request - still return generic message
                }
            }

            crate::otel::add_event(
                "lockout_unlock_email_sent",
                #[cfg(feature = "telemetry")]
                vec![
                    opentelemetry::KeyValue::new("user.email", email.to_string()),
                    opentelemetry::KeyValue::new("user.id", user.id.to_string()),
                ],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );

            state
                .write_audit_log(Some(user.id), "unlock_requested", None, None)
                .await;
        }
    }

    // Always return the same message to prevent user enumeration
    Ok(Json(AccountLockoutMessageResponse {
        message: "If your account is locked, you will receive an email with unlock instructions."
            .to_string(),
    }))
}

/// POST /account/unlock (public)
///
/// Verify the unlock token and reset the account lock.
async fn unlock_account(
    State(state): State<YAuthState>,
    Json(input): Json<UnlockAccountRequest>,
) -> Result<Json<AccountLockoutMessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let token = input.token.trim().to_string();
    if token.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "Token is required"));
    }

    let token_hash = crypto::hash_token(&token);

    // Find the unlock token (repo filters expired tokens)
    let unlock_token = state
        .repos
        .unlock_tokens
        .find_by_token_hash(&token_hash)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Invalid or expired unlock token"))?;

    let user_id = unlock_token.user_id;

    // Delete the token (one-time use)
    let _ = state.repos.unlock_tokens.delete(unlock_token.id).await;

    // Reset the account lock (keep lock_count for exponential backoff history)
    reset_account_lock(&state.repos, user_id, false)
        .await
        .map_err(|e| {
            crate::otel::record_error("lockout_reset_lock_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    crate::otel::add_event(
        "lockout_account_unlocked",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user_id.to_string()),
            opentelemetry::KeyValue::new("unlock.method", "token"),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user_id),
            "account_unlocked",
            Some(serde_json::json!({ "method": "token" })),
            None,
        )
        .await;

    Ok(Json(AccountLockoutMessageResponse {
        message: "Account has been unlocked. You can now log in.".to_string(),
    }))
}

/// POST /admin/users/:id/unlock (protected, admin only)
///
/// Admin endpoint to manually unlock a user's account.
/// Admin role check is enforced by the `require_admin` middleware layer.
async fn admin_unlock(
    State(state): State<YAuthState>,
    axum::Extension(auth_user): axum::Extension<crate::middleware::AuthUser>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<AccountLockoutMessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Verify target user exists
    let exists = state.repos.users.find_by_id(user_id).await.map_err(|e| {
        crate::otel::record_error("db_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;
    if exists.is_none() {
        return Err(api_err(StatusCode::NOT_FOUND, "User not found"));
    }

    // Reset the account lock fully (including lock_count for admin unlock)
    reset_account_lock(&state.repos, user_id, true)
        .await
        .map_err(|e| {
            crate::otel::record_error("lockout_reset_lock_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Delete any pending unlock tokens
    let _ = state.repos.unlock_tokens.delete_all_for_user(user_id).await;

    crate::otel::add_event(
        "lockout_account_unlocked",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user_id.to_string()),
            opentelemetry::KeyValue::new("admin.id", auth_user.id.to_string()),
            opentelemetry::KeyValue::new("unlock.method", "admin"),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user_id),
            "account_unlocked",
            Some(serde_json::json!({
                "method": "admin",
                "admin_id": auth_user.id.to_string(),
            })),
            None,
        )
        .await;

    Ok(Json(AccountLockoutMessageResponse {
        message: "Account has been unlocked.".to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reset the account lock. When `reset_lock_count` is true, also resets the
/// lock_count (used for admin unlock to clear exponential backoff history).
async fn reset_account_lock(
    repos: &Repositories,
    user_id: Uuid,
    reset_lock_count: bool,
) -> Result<(), crate::repo::RepoError> {
    let lock_record = repos.account_locks.find_by_user_id(user_id).await?;

    if let Some(record) = lock_record {
        // auto_unlock clears locked_until, locked_reason, and failed_count
        repos.account_locks.auto_unlock(record.id).await?;

        if reset_lock_count {
            // Also reset the lock_count for admin unlock
            repos
                .account_locks
                .set_locked(record.id, None, None, 0)
                .await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> AccountLockoutConfig {
        AccountLockoutConfig {
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(300),
            exponential_backoff: true,
            max_lockout_duration: Duration::from_secs(86400),
            attempt_window: Duration::from_secs(900),
            auto_unlock: true,
        }
    }

    #[test]
    fn exponential_backoff_calculation() {
        let config = test_config();

        // First lockout: base duration (300s)
        let d1 = calculate_lockout_duration(&config, 1);
        assert_eq!(d1, Duration::from_secs(300));

        // Second lockout: 300 * 2 = 600s
        let d2 = calculate_lockout_duration(&config, 2);
        assert_eq!(d2, Duration::from_secs(600));

        // Third lockout: 300 * 4 = 1200s
        let d3 = calculate_lockout_duration(&config, 3);
        assert_eq!(d3, Duration::from_secs(1200));

        // Fourth lockout: 300 * 8 = 2400s
        let d4 = calculate_lockout_duration(&config, 4);
        assert_eq!(d4, Duration::from_secs(2400));

        // Fifth lockout: 300 * 16 = 4800s
        let d5 = calculate_lockout_duration(&config, 5);
        assert_eq!(d5, Duration::from_secs(4800));
    }

    #[test]
    fn exponential_backoff_capped_at_max() {
        let config = AccountLockoutConfig {
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(300),
            exponential_backoff: true,
            max_lockout_duration: Duration::from_secs(3600), // 1 hour cap
            attempt_window: Duration::from_secs(900),
            auto_unlock: true,
        };

        // 300 * 2^9 = 300 * 512 = 153600, capped at 3600
        let d = calculate_lockout_duration(&config, 10);
        assert_eq!(d, Duration::from_secs(3600));
    }

    #[test]
    fn no_exponential_backoff_uses_base_duration() {
        let config = AccountLockoutConfig {
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(300),
            exponential_backoff: false,
            max_lockout_duration: Duration::from_secs(86400),
            attempt_window: Duration::from_secs(900),
            auto_unlock: true,
        };

        // Without backoff, always use base duration
        assert_eq!(
            calculate_lockout_duration(&config, 1),
            Duration::from_secs(300)
        );
        assert_eq!(
            calculate_lockout_duration(&config, 5),
            Duration::from_secs(300)
        );
        assert_eq!(
            calculate_lockout_duration(&config, 10),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn lockout_threshold_default_config() {
        let config = AccountLockoutConfig::default();
        assert_eq!(config.max_failed_attempts, 5);
        assert_eq!(config.lockout_duration, Duration::from_secs(300));
        assert!(config.exponential_backoff);
        assert_eq!(config.max_lockout_duration, Duration::from_secs(86400));
        assert_eq!(config.attempt_window, Duration::from_secs(900));
        assert!(config.auto_unlock);
    }

    #[test]
    fn exponential_backoff_zero_lock_count() {
        let config = test_config();

        // lock_count 0 should use base duration
        let d = calculate_lockout_duration(&config, 0);
        assert_eq!(d, Duration::from_secs(300));
    }
}
