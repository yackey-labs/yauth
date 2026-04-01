use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware as axum_mw,
    routing::post,
};
use chrono::Utc;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::crypto;
use crate::config::AccountLockoutConfig;
use crate::db::models::{AccountLock, NewAccountLock, NewUnlockToken, UnlockToken};
use crate::db::schema::{yauth_account_locks, yauth_unlock_tokens, yauth_users};
use crate::error::api_err;
use crate::middleware::require_admin;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Diesel-async helpers
// ---------------------------------------------------------------------------

type Conn = diesel_async_crate::AsyncPgConnection;
type DbResult<T> = Result<T, String>;

async fn find_user_by_email_id(conn: &mut Conn, email: &str) -> DbResult<Option<Uuid>> {
    yauth_users::table
        .filter(yauth_users::email.eq(email))
        .select(yauth_users::id)
        .first::<Uuid>(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn find_user_exists(conn: &mut Conn, user_id: Uuid) -> DbResult<bool> {
    let row: Option<Uuid> = yauth_users::table
        .filter(yauth_users::id.eq(user_id))
        .select(yauth_users::id)
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(row.is_some())
}

async fn find_lock_by_user(conn: &mut Conn, user_id: Uuid) -> DbResult<Option<AccountLock>> {
    yauth_account_locks::table
        .filter(yauth_account_locks::user_id.eq(user_id))
        .select(AccountLock::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn insert_lock(
    conn: &mut Conn,
    id: Uuid,
    user_id: Uuid,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<AccountLock> {
    let new_lock = NewAccountLock {
        id,
        user_id,
        failed_count: 0,
        locked_until: None,
        lock_count: 0,
        locked_reason: None,
        created_at: now.naive_utc(),
        updated_at: now.naive_utc(),
    };
    diesel::insert_into(yauth_account_locks::table)
        .values(&new_lock)
        .returning(AccountLock::as_returning())
        .get_result(conn)
        .await
        .map_err(|e| e.to_string())
}

async fn update_lock_auto_unlock(
    conn: &mut Conn,
    lock_id: Uuid,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(lock_id)))
        .set((
            yauth_account_locks::failed_count.eq(0),
            yauth_account_locks::locked_until.eq(None::<chrono::NaiveDateTime>),
            yauth_account_locks::locked_reason.eq(None::<String>),
            yauth_account_locks::updated_at.eq(now.naive_utc()),
        ))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn update_lock_increment(
    conn: &mut Conn,
    lock_id: Uuid,
    failed_count: i32,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(lock_id)))
        .set((
            yauth_account_locks::failed_count.eq(failed_count),
            yauth_account_locks::updated_at.eq(now.naive_utc()),
        ))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn update_lock_locked(
    conn: &mut Conn,
    lock_id: Uuid,
    failed_count: i32,
    locked_until: chrono::DateTime<chrono::FixedOffset>,
    lock_count: i32,
    reason: &str,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(lock_id)))
        .set((
            yauth_account_locks::failed_count.eq(failed_count),
            yauth_account_locks::locked_until.eq(Some(locked_until.naive_utc())),
            yauth_account_locks::lock_count.eq(lock_count),
            yauth_account_locks::locked_reason.eq(Some(reason.to_string())),
            yauth_account_locks::updated_at.eq(now.naive_utc()),
        ))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn update_lock_reset(
    conn: &mut Conn,
    lock_id: Uuid,
    reset_lock_count: bool,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    if reset_lock_count {
        diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(lock_id)))
            .set((
                yauth_account_locks::failed_count.eq(0),
                yauth_account_locks::locked_until.eq(None::<chrono::NaiveDateTime>),
                yauth_account_locks::locked_reason.eq(None::<String>),
                yauth_account_locks::lock_count.eq(0),
                yauth_account_locks::updated_at.eq(now.naive_utc()),
            ))
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(lock_id)))
            .set((
                yauth_account_locks::failed_count.eq(0),
                yauth_account_locks::locked_until.eq(None::<chrono::NaiveDateTime>),
                yauth_account_locks::locked_reason.eq(None::<String>),
                yauth_account_locks::updated_at.eq(now.naive_utc()),
            ))
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn find_unlock_token_by_hash(
    conn: &mut Conn,
    token_hash: &str,
) -> DbResult<Option<UnlockToken>> {
    yauth_unlock_tokens::table
        .filter(yauth_unlock_tokens::token_hash.eq(token_hash))
        .select(UnlockToken::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn delete_unlock_token(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::delete(yauth_unlock_tokens::table.filter(yauth_unlock_tokens::id.eq(id)))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn delete_unlock_tokens_for_user(conn: &mut Conn, user_id: Uuid) -> DbResult<()> {
    diesel::delete(yauth_unlock_tokens::table.filter(yauth_unlock_tokens::user_id.eq(user_id)))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn insert_unlock_token(
    conn: &mut Conn,
    id: Uuid,
    user_id: Uuid,
    token_hash: &str,
    expires_at: chrono::DateTime<chrono::FixedOffset>,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    let new_token = NewUnlockToken {
        id,
        user_id,
        token_hash: token_hash.to_string(),
        expires_at: expires_at.naive_utc(),
        created_at: now.naive_utc(),
    };
    diesel::insert_into(yauth_unlock_tokens::table)
        .values(&new_token)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

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
    db: &crate::state::DbPool,
    config: &AccountLockoutConfig,
    email: &str,
) -> EventResponse {
    let mut conn = match db.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Pool error in lockout handler: {}", e);
            return EventResponse::Continue;
        }
    };

    // Find user by email
    let user_id = match find_user_by_email_id(&mut conn, email).await {
        Ok(Some(id)) => id,
        Ok(None) => return EventResponse::Continue,
        Err(e) => {
            tracing::error!("DB error looking up user for lockout: {}", e);
            return EventResponse::Continue;
        }
    };

    let now = Utc::now().fixed_offset();

    // Find or create account lock record
    let lock_record = match find_lock_by_user(&mut conn, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => match insert_lock(&mut conn, Uuid::new_v4(), user_id, now).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Failed to create account lock record: {}", e);
                return EventResponse::Continue;
            }
        },
        Err(e) => {
            tracing::error!("DB error checking account lock: {}", e);
            return EventResponse::Continue;
        }
    };

    // Check if already locked and not expired
    if let Some(locked_until) = lock_record.locked_until {
        let locked_until_fo = locked_until.and_utc().fixed_offset();
        if now < locked_until_fo {
            warn!(
                event = "yauth.lockout.blocked",
                email = %email,
                locked_until = %locked_until_fo,
                "Login attempt on locked account"
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
            && let Err(e) = update_lock_auto_unlock(&mut conn, lock_record.id, now).await
        {
            tracing::error!("Failed to auto-unlock expired lock: {}", e);
        }
    }

    // Re-read lock record after potential auto-unlock reset
    let lock_record = match find_lock_by_user(&mut conn, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return EventResponse::Continue,
        Err(e) => {
            tracing::error!("DB error re-reading account lock: {}", e);
            return EventResponse::Continue;
        }
    };

    // Check if we are within the attempt window
    let window_start = now - chrono::Duration::seconds(config.attempt_window.as_secs() as i64);
    let updated_at_fo = lock_record.updated_at.and_utc().fixed_offset();
    let new_failed_count = if updated_at_fo < window_start {
        1
    } else {
        lock_record.failed_count + 1
    };

    // Check if we have exceeded the threshold
    if new_failed_count >= config.max_failed_attempts as i32 {
        let new_lock_count = lock_record.lock_count + 1;
        let lockout_duration = calculate_lockout_duration(config, new_lock_count as u32);
        let locked_until = now + chrono::Duration::seconds(lockout_duration.as_secs() as i64);

        if let Err(e) = update_lock_locked(
            &mut conn,
            lock_record.id,
            new_failed_count,
            locked_until,
            new_lock_count,
            "Too many failed login attempts",
            now,
        )
        .await
        {
            tracing::error!("Failed to update account lock: {}", e);
            return EventResponse::Continue;
        }

        warn!(
            event = "yauth.lockout.locked",
            email = %email,
            user_id = %user_id,
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
    if let Err(e) = update_lock_increment(&mut conn, lock_record.id, new_failed_count, now).await {
        tracing::error!("Failed to update failed count: {}", e);
    }

    EventResponse::Continue
}

/// On successful login, check if account is locked first. If not, reset failed count.
async fn handle_login_succeeded(
    db: &crate::state::DbPool,
    _config: &AccountLockoutConfig,
    user_id: Uuid,
) -> EventResponse {
    let mut conn = match db.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Pool error in lockout handler: {}", e);
            return EventResponse::Continue;
        }
    };

    let now = Utc::now().fixed_offset();

    let lock_record = match find_lock_by_user(&mut conn, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return EventResponse::Continue,
        Err(e) => {
            tracing::error!("DB error checking account lock on success: {}", e);
            return EventResponse::Continue;
        }
    };

    // Check if account is currently locked
    if let Some(locked_until) = lock_record.locked_until {
        let locked_until_fo = locked_until.and_utc().fixed_offset();
        if now < locked_until_fo {
            warn!(
                event = "yauth.lockout.blocked_valid_creds",
                user_id = %user_id,
                locked_until = %locked_until_fo,
                "Valid credentials but account is locked"
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
    if let Err(e) = update_lock_auto_unlock(&mut conn, lock_record.id, now).await {
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
        warn!(
            event = "yauth.lockout.unlock_rate_limited",
            email = %email,
            "Unlock request rate limited"
        );
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    struct FoundUser {
        id: Uuid,
    }

    // Look up user (don't leak whether user exists)
    let user_opt = {
        find_user_by_email_id(&mut conn, &email)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .map(|id| FoundUser { id })
    };

    if let Some(user) = user_opt {
        // Check if account is actually locked
        let is_locked = {
            let lock_record = find_lock_by_user(&mut conn, user.id).await.map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

            lock_record
                .as_ref()
                .and_then(|r| r.locked_until)
                .map(|until| Utc::now().fixed_offset() < until.and_utc().fixed_offset())
                .unwrap_or(false)
        };

        if is_locked {
            // Delete any existing unlock tokens for this user
            let _ = delete_unlock_tokens_for_user(&mut conn, user.id).await;

            // Generate unlock token
            let token = crypto::generate_token();
            let token_hash = crypto::hash_token(&token);
            let now = Utc::now().fixed_offset();
            let expires_at = now + chrono::Duration::hours(1);

            insert_unlock_token(
                &mut conn,
                Uuid::new_v4(),
                user.id,
                &token_hash,
                expires_at,
                now,
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to store unlock token: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

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
                event = "yauth.lockout.unlock_email_sent",
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

    struct FoundToken {
        id: Uuid,
        user_id: Uuid,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
    }

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Find the unlock token
    let unlock_token = {
        let found = find_unlock_token_by_hash(&mut conn, &token_hash)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        match found {
            Some(t) => FoundToken {
                id: t.id,
                user_id: t.user_id,
                expires_at: t.expires_at.and_utc().fixed_offset(),
            },
            None => {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "Invalid or expired unlock token",
                ));
            }
        }
    };

    // Check expiry
    if now > unlock_token.expires_at {
        // Delete the expired token
        let _ = delete_unlock_token(&mut conn, unlock_token.id).await;
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Invalid or expired unlock token",
        ));
    }

    let user_id = unlock_token.user_id;

    // Delete the token (one-time use)
    let _ = delete_unlock_token(&mut conn, unlock_token.id).await;

    // Reset the account lock (keep lock_count for exponential backoff history)
    reset_account_lock_diesel(&mut conn, user_id, false)
        .await
        .map_err(|e| {
            tracing::error!("Failed to reset account lock: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    info!(
        event = "yauth.lockout.unlocked",
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
    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // Verify target user exists
    let exists = find_user_exists(&mut conn, user_id).await.map_err(|e| {
        tracing::error!("DB error: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;
    if !exists {
        return Err(api_err(StatusCode::NOT_FOUND, "User not found"));
    }

    // Reset the account lock fully (including lock_count for admin unlock)
    reset_account_lock_diesel(&mut conn, user_id, true)
        .await
        .map_err(|e| {
            tracing::error!("Failed to reset account lock: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Delete any pending unlock tokens
    let _ = delete_unlock_tokens_for_user(&mut conn, user_id).await;

    info!(
        event = "yauth.lockout.unlocked",
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
async fn reset_account_lock_diesel(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    user_id: Uuid,
    reset_lock_count: bool,
) -> Result<(), String> {
    let now = Utc::now().fixed_offset();

    let lock_record = find_lock_by_user(conn, user_id).await?;

    if let Some(record) = lock_record {
        update_lock_reset(conn, record.id, reset_lock_count, now).await?;
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
