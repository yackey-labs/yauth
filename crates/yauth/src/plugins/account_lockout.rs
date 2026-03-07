use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware as axum_mw,
    routing::post,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::crypto;
use crate::config::AccountLockoutConfig;
use crate::error::api_err;
use crate::middleware::require_admin;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
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
                let db = ctx.state.db.clone();
                let config = ctx.state.account_lockout_config.clone();

                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { handle_login_failed(&db, &config, &email).await })
                })
            }
            AuthEvent::LoginSucceeded { user_id, .. } => {
                let user_id = *user_id;
                let db = ctx.state.db.clone();
                let config = ctx.state.account_lockout_config.clone();

                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { handle_login_succeeded(&db, &config, user_id).await })
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
    db: &sea_orm::DatabaseConnection,
    config: &AccountLockoutConfig,
    email: &str,
) -> EventResponse {
    // Find user by email
    let user = match yauth_entity::users::Entity::find()
        .filter(yauth_entity::users::Column::Email.eq(email))
        .one(db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return EventResponse::Continue, // Unknown user, nothing to lock
        Err(e) => {
            tracing::error!("DB error looking up user for lockout: {}", e);
            return EventResponse::Continue;
        }
    };

    let now = Utc::now().fixed_offset();

    // Find or create account lock record
    let lock_record = yauth_entity::account_locks::Entity::find()
        .filter(yauth_entity::account_locks::Column::UserId.eq(user.id))
        .one(db)
        .await;

    let lock_record = match lock_record {
        Ok(Some(r)) => r,
        Ok(None) => {
            // Create a new lock record with failed_count = 0
            let new_lock = yauth_entity::account_locks::ActiveModel {
                id: Set(Uuid::new_v4()),
                user_id: Set(user.id),
                failed_count: Set(0),
                locked_until: Set(None),
                lock_count: Set(0),
                locked_reason: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            match new_lock.insert(db).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Failed to create account lock record: {}", e);
                    return EventResponse::Continue;
                }
            }
        }
        Err(e) => {
            tracing::error!("DB error checking account lock: {}", e);
            return EventResponse::Continue;
        }
    };

    // Check if already locked and not expired
    if let Some(locked_until) = lock_record.locked_until {
        if now < locked_until {
            warn!(
                event = "login_blocked_locked",
                email = %email,
                locked_until = %locked_until,
                "Login attempt on locked account"
            );
            return EventResponse::Block {
                status: 423,
                message: format!(
                    "Account is locked. Try again after {}.",
                    locked_until.format("%Y-%m-%d %H:%M:%S UTC")
                ),
            };
        }
        // Lock has expired and auto_unlock is on - reset the lock state
        // (but keep the lock_count for exponential backoff)
        if config.auto_unlock {
            let mut active: yauth_entity::account_locks::ActiveModel = lock_record.clone().into();
            active.failed_count = Set(0);
            active.locked_until = Set(None);
            active.locked_reason = Set(None);
            active.updated_at = Set(now);
            if let Err(e) = active.update(db).await {
                tracing::error!("Failed to auto-unlock expired lock: {}", e);
            }
        }
    }

    // Re-read lock record after potential auto-unlock reset
    let lock_record = match yauth_entity::account_locks::Entity::find()
        .filter(yauth_entity::account_locks::Column::UserId.eq(user.id))
        .one(db)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return EventResponse::Continue,
        Err(e) => {
            tracing::error!("DB error re-reading account lock: {}", e);
            return EventResponse::Continue;
        }
    };

    // Check if we are within the attempt window
    let window_start = now - chrono::Duration::seconds(config.attempt_window.as_secs() as i64);
    let new_failed_count = if lock_record.updated_at < window_start {
        // Outside the window - reset counter
        1
    } else {
        lock_record.failed_count + 1
    };

    let mut active: yauth_entity::account_locks::ActiveModel = lock_record.clone().into();
    active.failed_count = Set(new_failed_count);
    active.updated_at = Set(now);

    // Check if we have exceeded the threshold
    if new_failed_count >= config.max_failed_attempts as i32 {
        let new_lock_count = lock_record.lock_count + 1;
        let lockout_duration = calculate_lockout_duration(config, new_lock_count as u32);
        let locked_until = now + chrono::Duration::seconds(lockout_duration.as_secs() as i64);

        active.locked_until = Set(Some(locked_until));
        active.lock_count = Set(new_lock_count);
        active.locked_reason = Set(Some("Too many failed login attempts".to_string()));

        if let Err(e) = active.update(db).await {
            tracing::error!("Failed to update account lock: {}", e);
            return EventResponse::Continue;
        }

        warn!(
            event = "account_locked",
            email = %email,
            user_id = %user.id,
            lock_count = new_lock_count,
            locked_until = %locked_until,
            "Account locked due to too many failed attempts"
        );

        return EventResponse::Block {
            status: 423,
            message: format!(
                "Account has been locked due to too many failed login attempts. Try again after {}.",
                locked_until.format("%Y-%m-%d %H:%M:%S UTC")
            ),
        };
    }

    // Just increment - not yet locked
    if let Err(e) = active.update(db).await {
        tracing::error!("Failed to update failed count: {}", e);
    }

    EventResponse::Continue
}

/// On successful login, check if account is locked first. If not, reset failed count.
async fn handle_login_succeeded(
    db: &sea_orm::DatabaseConnection,
    _config: &AccountLockoutConfig,
    user_id: Uuid,
) -> EventResponse {
    let now = Utc::now().fixed_offset();

    let lock_record = match yauth_entity::account_locks::Entity::find()
        .filter(yauth_entity::account_locks::Column::UserId.eq(user_id))
        .one(db)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return EventResponse::Continue, // No lock record, allow login
        Err(e) => {
            tracing::error!("DB error checking account lock on success: {}", e);
            return EventResponse::Continue;
        }
    };

    // Check if account is currently locked
    if let Some(locked_until) = lock_record.locked_until
        && now < locked_until
    {
        // Account is still locked - block even though credentials are valid
        warn!(
            event = "login_blocked_locked_valid_creds",
            user_id = %user_id,
            locked_until = %locked_until,
            "Valid credentials but account is locked"
        );
        return EventResponse::Block {
            status: 423,
            message: format!(
                "Account is locked. Try again after {}.",
                locked_until.format("%Y-%m-%d %H:%M:%S UTC")
            ),
        };
        // Lock expired - fall through to reset
    }

    // Reset failed count on successful login
    let mut active: yauth_entity::account_locks::ActiveModel = lock_record.into();
    active.failed_count = Set(0);
    active.locked_until = Set(None);
    active.locked_reason = Set(None);
    // Keep lock_count for exponential backoff history (only reset on explicit unlock)
    active.updated_at = Set(now);

    if let Err(e) = active.update(db).await {
        tracing::error!("Failed to reset account lock on success: {}", e);
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

#[derive(Deserialize, TS)]
#[ts(export)]
pub struct RequestUnlockRequest {
    pub email: String,
}

#[derive(Deserialize, TS)]
#[ts(export)]
pub struct UnlockAccountRequest {
    pub token: String,
}

#[derive(Serialize, TS)]
#[ts(export)]
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
        warn!(
            event = "unlock_request_rate_limited",
            email = %email,
            "Unlock request rate limited"
        );
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    // Look up user (don't leak whether user exists)
    let user = yauth_entity::users::Entity::find()
        .filter(yauth_entity::users::Column::Email.eq(&email))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if let Some(user) = user {
        // Check if account is actually locked
        let lock_record = yauth_entity::account_locks::Entity::find()
            .filter(yauth_entity::account_locks::Column::UserId.eq(user.id))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let is_locked = lock_record
            .as_ref()
            .and_then(|r| r.locked_until)
            .map(|until| Utc::now().fixed_offset() < until)
            .unwrap_or(false);

        if is_locked {
            // Delete any existing unlock tokens for this user
            yauth_entity::unlock_tokens::Entity::delete_many()
                .filter(yauth_entity::unlock_tokens::Column::UserId.eq(user.id))
                .exec(&state.db)
                .await
                .ok();

            // Generate unlock token
            let token = crypto::generate_token();
            let token_hash = crypto::hash_token(&token);
            let now = Utc::now().fixed_offset();
            let expires_at = now + chrono::Duration::hours(1);

            let unlock_token = yauth_entity::unlock_tokens::ActiveModel {
                id: Set(Uuid::new_v4()),
                user_id: Set(user.id),
                token_hash: Set(token_hash),
                expires_at: Set(expires_at),
                created_at: Set(now),
            };

            if let Err(e) = unlock_token.insert(&state.db).await {
                tracing::error!("Failed to store unlock token: {}", e);
                return Err(api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"));
            }

            // Send unlock email if SMTP is configured
            if let Some(ref email_service) = state.email_service {
                let unlock_url =
                    format!("{}/account/unlock?token={}", state.config.base_url, token);
                if let Err(e) = email_service.send_unlock_email(&email, &unlock_url) {
                    tracing::error!("Failed to send unlock email: {}", e);
                    // Don't fail the request - still return generic message
                }
            }

            info!(
                event = "unlock_email_sent",
                email = %email,
                user_id = %user.id,
                "Account unlock email sent"
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
    let now = Utc::now().fixed_offset();

    // Find the unlock token
    let unlock_token = yauth_entity::unlock_tokens::Entity::find()
        .filter(yauth_entity::unlock_tokens::Column::TokenHash.eq(&token_hash))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let unlock_token = match unlock_token {
        Some(t) => t,
        None => {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "Invalid or expired unlock token",
            ));
        }
    };

    // Check expiry
    if now > unlock_token.expires_at {
        // Delete the expired token
        yauth_entity::unlock_tokens::Entity::delete_by_id(unlock_token.id)
            .exec(&state.db)
            .await
            .ok();
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Invalid or expired unlock token",
        ));
    }

    let user_id = unlock_token.user_id;

    // Delete the token (one-time use)
    yauth_entity::unlock_tokens::Entity::delete_by_id(unlock_token.id)
        .exec(&state.db)
        .await
        .ok();

    // Reset the account lock (keep lock_count for exponential backoff history)
    reset_account_lock(&state.db, user_id, false)
        .await
        .map_err(|e| {
            tracing::error!("Failed to reset account lock: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    info!(
        event = "account_unlocked",
        user_id = %user_id,
        method = "token",
        "Account unlocked via token"
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
    let user = yauth_entity::users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if user.is_none() {
        return Err(api_err(StatusCode::NOT_FOUND, "User not found"));
    }

    // Reset the account lock fully (including lock_count for admin unlock)
    reset_account_lock(&state.db, user_id, true)
        .await
        .map_err(|e| {
            tracing::error!("Failed to reset account lock: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Delete any pending unlock tokens
    yauth_entity::unlock_tokens::Entity::delete_many()
        .filter(yauth_entity::unlock_tokens::Column::UserId.eq(user_id))
        .exec(&state.db)
        .await
        .ok();

    info!(
        event = "account_unlocked",
        user_id = %user_id,
        admin_id = %auth_user.id,
        method = "admin",
        "Account unlocked by admin"
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
    db: &sea_orm::DatabaseConnection,
    user_id: Uuid,
    reset_lock_count: bool,
) -> Result<(), sea_orm::DbErr> {
    let now = Utc::now().fixed_offset();

    let lock_record = yauth_entity::account_locks::Entity::find()
        .filter(yauth_entity::account_locks::Column::UserId.eq(user_id))
        .one(db)
        .await?;

    if let Some(record) = lock_record {
        let mut active: yauth_entity::account_locks::ActiveModel = record.into();
        active.failed_count = Set(0);
        active.locked_until = Set(None);
        active.locked_reason = Set(None);
        if reset_lock_count {
            active.lock_count = Set(0);
        }
        active.updated_at = Set(now);
        active.update(db).await?;
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
