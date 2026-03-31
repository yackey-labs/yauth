use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware as axum_mw,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use chrono::Utc;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::WebhookConfig;
use crate::db::models::{NewWebhook, NewWebhookDelivery, UpdateWebhook, Webhook, WebhookDelivery};
use crate::db::schema::{yauth_webhook_deliveries, yauth_webhooks};
use crate::error::{ApiError, api_err};
use crate::middleware::{AuthUser, require_admin};
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Diesel-async helpers
// ---------------------------------------------------------------------------

type Conn = diesel_async_crate::AsyncPgConnection;
type DbResult<T> = Result<T, String>;

async fn find_active_webhooks(conn: &mut Conn) -> DbResult<Vec<Webhook>> {
    yauth_webhooks::table
        .filter(yauth_webhooks::active.eq(true))
        .select(Webhook::as_select())
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

async fn find_all_webhooks(conn: &mut Conn) -> DbResult<Vec<Webhook>> {
    yauth_webhooks::table
        .order(yauth_webhooks::created_at.desc())
        .select(Webhook::as_select())
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

async fn find_webhook_by_id(conn: &mut Conn, id: Uuid) -> DbResult<Option<Webhook>> {
    yauth_webhooks::table
        .filter(yauth_webhooks::id.eq(id))
        .select(Webhook::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_insert_webhook(
    conn: &mut Conn,
    id: Uuid,
    url: &str,
    secret: &str,
    events: &serde_json::Value,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    let new_webhook = NewWebhook {
        id,
        url: url.to_string(),
        secret: secret.to_string(),
        events: events.clone(),
        active: true,
        created_at: now.naive_utc(),
        updated_at: now.naive_utc(),
    };
    diesel::insert_into(yauth_webhooks::table)
        .values(&new_webhook)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_update_webhook(
    conn: &mut Conn,
    id: Uuid,
    url: Option<&str>,
    events: Option<&serde_json::Value>,
    secret: Option<&str>,
    active: Option<bool>,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<Option<Webhook>> {
    let changeset = UpdateWebhook {
        url: url.map(|s| s.to_string()),
        events: events.cloned(),
        secret: secret.map(|s| s.to_string()),
        active,
        updated_at: Some(now.naive_utc()),
    };
    diesel::update(yauth_webhooks::table.filter(yauth_webhooks::id.eq(id)))
        .set(&changeset)
        .returning(Webhook::as_returning())
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_delete_webhook(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::delete(yauth_webhooks::table.filter(yauth_webhooks::id.eq(id)))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_delivery(
    conn: &mut Conn,
    id: Uuid,
    webhook_id: Uuid,
    event_type: &str,
    payload: &serde_json::Value,
    status_code: Option<i16>,
    response_body: Option<&str>,
    success: bool,
    attempt: i32,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    let new_delivery = NewWebhookDelivery {
        id,
        webhook_id,
        event_type: event_type.to_string(),
        payload: payload.clone(),
        status_code,
        response_body: response_body.map(|s| s.to_string()),
        success,
        attempt,
        created_at: now.naive_utc(),
    };
    diesel::insert_into(yauth_webhook_deliveries::table)
        .values(&new_delivery)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn find_recent_deliveries(
    conn: &mut Conn,
    webhook_id: Uuid,
    limit: i64,
) -> DbResult<Vec<WebhookDelivery>> {
    yauth_webhook_deliveries::table
        .filter(yauth_webhook_deliveries::webhook_id.eq(webhook_id))
        .order(yauth_webhook_deliveries::created_at.desc())
        .limit(limit)
        .select(WebhookDelivery::as_select())
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

pub struct WebhookPlugin {
    config: WebhookConfig,
}

impl WebhookPlugin {
    pub fn new(config: WebhookConfig) -> Self {
        Self { config }
    }
}

impl YAuthPlugin for WebhookPlugin {
    fn name(&self) -> &'static str {
        "webhooks"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/webhooks", post(create_webhook))
                .route("/webhooks", get(list_webhooks))
                .route("/webhooks/{id}", get(get_webhook))
                .route("/webhooks/{id}", put(update_webhook))
                .route("/webhooks/{id}", delete(delete_webhook))
                .route("/webhooks/{id}/test", post(test_webhook))
                .layer(axum_mw::from_fn(require_admin)),
        )
    }

    fn on_event(&self, event: &AuthEvent, ctx: &PluginContext) -> EventResponse {
        let db = ctx.state.db.clone();
        let event_clone = event.clone();
        let max_retries = self.config.max_retries;
        let retry_delay = self.config.retry_delay;
        let timeout = self.config.timeout;

        tokio::spawn(async move {
            if let Err(e) =
                dispatch_webhooks_diesel(db, event_clone, max_retries, retry_delay, timeout).await
            {
                error!("Webhook dispatch error: {}", e);
            }
        });

        EventResponse::Continue
    }
}

// ---------------------------------------------------------------------------
// Event type string extraction
// ---------------------------------------------------------------------------

fn event_type_name(event: &AuthEvent) -> &'static str {
    match event {
        AuthEvent::UserRegistered { .. } => "user.registered",
        AuthEvent::LoginSucceeded { .. } => "login.succeeded",
        AuthEvent::LoginFailed { .. } => "login.failed",
        AuthEvent::SessionCreated { .. } => "session.created",
        AuthEvent::Logout { .. } => "logout",
        AuthEvent::PasswordChanged { .. } => "password.changed",
        AuthEvent::EmailVerified { .. } => "email.verified",
        AuthEvent::MfaEnabled { .. } => "mfa.enabled",
        AuthEvent::MfaDisabled { .. } => "mfa.disabled",
        AuthEvent::UserBanned { .. } => "user.banned",
        AuthEvent::UserUnbanned { .. } => "user.unbanned",
        AuthEvent::MagicLinkSent { .. } => "magic_link.sent",
        AuthEvent::MagicLinkVerified { .. } => "magic_link.verified",
        #[cfg(feature = "account-lockout")]
        AuthEvent::AccountLocked { .. } => "account.locked",
        #[cfg(feature = "account-lockout")]
        AuthEvent::AccountUnlocked { .. } => "account.unlocked",
    }
}

// ---------------------------------------------------------------------------
// Webhook dispatch (background task)
// ---------------------------------------------------------------------------

async fn dispatch_webhooks_diesel(
    pool: diesel_async_crate::pooled_connection::deadpool::Pool<
        diesel_async_crate::AsyncPgConnection,
    >,
    event: AuthEvent,
    max_retries: u32,
    retry_delay: std::time::Duration,
    timeout: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let event_type = event_type_name(&event);
    let payload = serde_json::to_value(&event)?;

    let mut conn = pool.get().await.map_err(|e| e.to_string())?;
    let webhooks = find_active_webhooks(&mut conn)
        .await
        .map_err(|e| e.to_string())?;

    let client = reqwest::Client::builder().timeout(timeout).build()?;

    for webhook in webhooks {
        let events: Vec<String> =
            serde_json::from_value(webhook.events.clone()).unwrap_or_default();
        if !events.contains(&"*".to_string()) && !events.contains(&event_type.to_string()) {
            continue;
        }

        let body = serde_json::json!({
            "event": event_type,
            "payload": payload,
            "timestamp": Utc::now().to_rfc3339(),
            "webhook_id": webhook.id,
        });
        let body_str = serde_json::to_string(&body)?;

        let signature = compute_signature(&webhook.secret, &body_str);

        let mut last_status: Option<i16> = None;
        let mut last_body: Option<String> = None;
        let mut success = false;

        for attempt in 1..=(max_retries + 1) {
            match client
                .post(&webhook.url)
                .header("Content-Type", "application/json")
                .header("X-YAuth-Signature", format!("sha256={}", signature))
                .header("X-YAuth-Event", event_type)
                .body(body_str.clone())
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status().as_u16() as i16;
                    let resp_body = response.text().await.unwrap_or_default();
                    last_status = Some(status);
                    last_body = Some(resp_body.clone());

                    if (200..300).contains(&(status as u16)) {
                        success = true;
                        let mut conn = pool.get().await.map_err(|e| e.to_string())?;
                        if let Err(e) = insert_delivery(
                            &mut conn,
                            Uuid::new_v4(),
                            webhook.id,
                            event_type,
                            &body,
                            Some(status),
                            Some(&truncate_response(&resp_body)),
                            true,
                            attempt as i32,
                            Utc::now().fixed_offset(),
                        )
                        .await
                        {
                            error!("Failed to record webhook delivery: {}", e);
                        }
                        break;
                    } else if (500..600).contains(&(status as u16)) && attempt <= max_retries {
                        warn!(
                            webhook_id = %webhook.id,
                            status = status,
                            attempt = attempt,
                            "Webhook delivery got 5xx, retrying"
                        );
                        tokio::time::sleep(retry_delay).await;
                        continue;
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    last_body = Some(e.to_string());
                    if attempt <= max_retries {
                        warn!(
                            webhook_id = %webhook.id,
                            error = %e,
                            attempt = attempt,
                            "Webhook delivery failed, retrying"
                        );
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }

        if !success {
            let mut conn = pool.get().await.map_err(|e| e.to_string())?;
            if let Err(e) = insert_delivery(
                &mut conn,
                Uuid::new_v4(),
                webhook.id,
                event_type,
                &body,
                last_status,
                last_body.as_deref().map(truncate_response).as_deref(),
                false,
                (max_retries + 1) as i32,
                Utc::now().fixed_offset(),
            )
            .await
            {
                error!("Failed to record webhook delivery: {}", e);
            }
        }
    }

    Ok(())
}

fn compute_signature(secret: &str, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn truncate_response(body: &str) -> String {
    if body.len() > 4096 {
        format!("{}...(truncated)", &body[..4096])
    } else {
        body.to_string()
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
    pub secret: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub secret: Option<String>,
    pub active: Option<bool>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WebhookResponse {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WebhookDetailResponse {
    pub webhook: WebhookResponse,
    pub recent_deliveries: Vec<WebhookDeliveryResponse>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WebhookDeliveryResponse {
    pub id: String,
    pub event_type: String,
    pub status_code: Option<i16>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: String,
}

impl From<Webhook> for WebhookResponse {
    fn from(r: Webhook) -> Self {
        use chrono::TimeZone;
        let events: Vec<String> = serde_json::from_value(r.events).unwrap_or_default();
        let created = chrono::Utc.from_utc_datetime(&r.created_at);
        let updated = chrono::Utc.from_utc_datetime(&r.updated_at);
        Self {
            id: r.id.to_string(),
            url: r.url,
            events,
            active: r.active,
            created_at: created.to_rfc3339(),
            updated_at: updated.to_rfc3339(),
        }
    }
}

impl From<WebhookDelivery> for WebhookDeliveryResponse {
    fn from(r: WebhookDelivery) -> Self {
        use chrono::TimeZone;
        let created = chrono::Utc.from_utc_datetime(&r.created_at);
        Self {
            id: r.id.to_string(),
            event_type: r.event_type,
            status_code: r.status_code,
            success: r.success,
            attempt: r.attempt,
            created_at: created.to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// POST /webhooks -- create webhook
// ---------------------------------------------------------------------------

async fn create_webhook(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Json(input): Json<CreateWebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate URL
    if input.url.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "URL is required"));
    }

    // Validate events
    if input.events.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "At least one event type is required",
        ));
    }

    // Generate secret if not provided
    let secret = input
        .secret
        .unwrap_or_else(crate::auth::crypto::generate_token);

    let now = Utc::now().fixed_offset();
    let id = Uuid::new_v4();
    let events_json = serde_json::to_value(&input.events).unwrap();

    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        db_insert_webhook(&mut conn, id, &input.url, &secret, &events_json, now)
            .await
            .map_err(|e| {
                error!("DB error creating webhook: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        info!(
            event = "yauth.webhook.created",
            admin_id = %admin.id,
            webhook_id = %id,
            "Admin created webhook"
        );

        state
            .write_audit_log(
                Some(admin.id),
                "webhook_created",
                Some(serde_json::json!({ "webhook_id": id, "url": input.url })),
                None,
            )
            .await;

        Ok((
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": id,
                "url": input.url,
                "secret": secret,
                "events": input.events,
                "active": true,
                "created_at": now.to_rfc3339(),
                "updated_at": now.to_rfc3339(),
            })),
        ))
    }
}

// ---------------------------------------------------------------------------
// GET /webhooks -- list webhooks
// ---------------------------------------------------------------------------

async fn list_webhooks(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
) -> Result<impl IntoResponse, ApiError> {
    let responses: Vec<WebhookResponse> = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let webhooks = find_all_webhooks(&mut conn).await.map_err(|e| {
            error!("DB error listing webhooks: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
        webhooks.into_iter().map(Into::into).collect()
    };

    Ok(Json(serde_json::json!({ "webhooks": responses })))
}

// ---------------------------------------------------------------------------
// GET /webhooks/{id} -- get webhook + recent deliveries
// ---------------------------------------------------------------------------

async fn get_webhook(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let detail = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        let webhook = find_webhook_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                error!("DB error fetching webhook: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;

        let deliveries = find_recent_deliveries(&mut conn, id, 50)
            .await
            .map_err(|e| {
                error!("DB error fetching deliveries: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let delivery_responses: Vec<WebhookDeliveryResponse> =
            deliveries.into_iter().map(Into::into).collect();

        WebhookDetailResponse {
            webhook: webhook.into(),
            recent_deliveries: delivery_responses,
        }
    };

    Ok(Json(detail))
}

// ---------------------------------------------------------------------------
// PUT /webhooks/{id} -- update webhook
// ---------------------------------------------------------------------------

async fn update_webhook(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateWebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let response: WebhookResponse = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        // Check existence first
        find_webhook_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                error!("DB error fetching webhook: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;

        let events_json = input
            .events
            .as_ref()
            .map(|e| serde_json::to_value(e).unwrap());
        let now = Utc::now().fixed_offset();

        let updated = db_update_webhook(
            &mut conn,
            id,
            input.url.as_deref(),
            events_json.as_ref(),
            input.secret.as_deref(),
            input.active,
            now,
        )
        .await
        .map_err(|e| {
            error!("DB error updating webhook: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;

        updated.into()
    };

    info!(
        event = "yauth.webhook.updated",
        admin_id = %admin.id,
        webhook_id = %id,
        "Admin updated webhook"
    );

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// DELETE /webhooks/{id} -- delete webhook
// ---------------------------------------------------------------------------

async fn delete_webhook(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        find_webhook_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                error!("DB error fetching webhook: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;

        db_delete_webhook(&mut conn, id).await.map_err(|e| {
            error!("DB error deleting webhook: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }

    info!(
        event = "yauth.webhook.deleted",
        admin_id = %admin.id,
        webhook_id = %id,
        "Admin deleted webhook"
    );

    state
        .write_audit_log(
            Some(admin.id),
            "webhook_deleted",
            Some(serde_json::json!({ "webhook_id": id })),
            None,
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /webhooks/{id}/test -- send test delivery
// ---------------------------------------------------------------------------

async fn test_webhook(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    // Fetch webhook URL, secret, and id
    let (webhook_id, webhook_url, webhook_secret) = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let webhook = find_webhook_by_id(&mut conn, id)
            .await
            .map_err(|e| {
                error!("DB error fetching webhook: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;
        (webhook.id, webhook.url, webhook.secret)
    };

    let body = serde_json::json!({
        "event": "test",
        "payload": {
            "message": "This is a test webhook delivery",
            "triggered_by": admin.id,
        },
        "timestamp": Utc::now().to_rfc3339(),
        "webhook_id": webhook_id,
    });
    let body_str = serde_json::to_string(&body)
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Serialization error"))?;

    let signature = compute_signature(&webhook_secret, &body_str);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "HTTP client error"))?;

    let result = client
        .post(&webhook_url)
        .header("Content-Type", "application/json")
        .header("X-YAuth-Signature", format!("sha256={}", signature))
        .header("X-YAuth-Event", "test")
        .body(body_str)
        .send()
        .await;

    let (status_code, response_body, success) = match result {
        Ok(response) => {
            let status = response.status().as_u16() as i16;
            let resp_body = response.text().await.unwrap_or_default();
            let ok = (200..300).contains(&(status as u16));
            (Some(status), Some(truncate_response(&resp_body)), ok)
        }
        Err(e) => (None, Some(e.to_string()), false),
    };

    // Record delivery
    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

        insert_delivery(
            &mut conn,
            Uuid::new_v4(),
            webhook_id,
            "test",
            &body,
            status_code,
            response_body.as_deref(),
            success,
            1,
            Utc::now().fixed_offset(),
        )
        .await
        .map_err(|e| {
            error!("DB error recording test delivery: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }

    Ok(Json(serde_json::json!({
        "success": success,
        "status_code": status_code,
        "response_body": response_body,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::AuthEvent;

    #[test]
    fn compute_signature_known_input() {
        // Pre-computed HMAC-SHA256 of "hello" with key "secret"
        let sig = compute_signature("secret", "hello");
        assert_eq!(
            sig,
            "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
        );
    }

    #[test]
    fn compute_signature_different_body_produces_different_signature() {
        let sig1 = compute_signature("secret", "body-a");
        let sig2 = compute_signature("secret", "body-b");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn compute_signature_different_secret_produces_different_signature() {
        let sig1 = compute_signature("secret-1", "same-body");
        let sig2 = compute_signature("secret-2", "same-body");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn truncate_response_short_body_returned_as_is() {
        let body = "short response";
        assert_eq!(truncate_response(body), body);
    }

    #[test]
    fn truncate_response_exact_4096_returned_as_is() {
        let body = "x".repeat(4096);
        assert_eq!(truncate_response(&body), body);
    }

    #[test]
    fn truncate_response_long_body_is_truncated() {
        let body = "y".repeat(5000);
        let result = truncate_response(&body);
        assert!(result.ends_with("...(truncated)"));
        assert_eq!(result.len(), 4096 + "...(truncated)".len());
        assert!(result.starts_with(&body[..4096]));
    }

    #[test]
    fn event_type_name_all_variants() {
        let uid = Uuid::nil();
        let sid = Uuid::nil();

        let cases: Vec<(AuthEvent, &str)> = vec![
            (
                AuthEvent::UserRegistered {
                    user_id: uid,
                    email: "a@b.com".into(),
                },
                "user.registered",
            ),
            (
                AuthEvent::LoginSucceeded {
                    user_id: uid,
                    method: "email".into(),
                },
                "login.succeeded",
            ),
            (
                AuthEvent::LoginFailed {
                    email: "a@b.com".into(),
                    method: "email".into(),
                    reason: "bad password".into(),
                },
                "login.failed",
            ),
            (
                AuthEvent::SessionCreated {
                    user_id: uid,
                    session_id: sid,
                },
                "session.created",
            ),
            (
                AuthEvent::Logout {
                    user_id: uid,
                    session_id: sid,
                },
                "logout",
            ),
            (
                AuthEvent::PasswordChanged { user_id: uid },
                "password.changed",
            ),
            (AuthEvent::EmailVerified { user_id: uid }, "email.verified"),
            (
                AuthEvent::MfaEnabled {
                    user_id: uid,
                    method: "totp".into(),
                },
                "mfa.enabled",
            ),
            (
                AuthEvent::MfaDisabled {
                    user_id: uid,
                    method: "totp".into(),
                },
                "mfa.disabled",
            ),
            (AuthEvent::UserBanned { user_id: uid }, "user.banned"),
            (AuthEvent::UserUnbanned { user_id: uid }, "user.unbanned"),
            (
                AuthEvent::MagicLinkSent {
                    email: "a@b.com".into(),
                },
                "magic_link.sent",
            ),
            (
                AuthEvent::MagicLinkVerified {
                    user_id: uid,
                    is_new_user: false,
                },
                "magic_link.verified",
            ),
        ];

        for (event, expected) in cases {
            assert_eq!(
                event_type_name(&event),
                expected,
                "Mismatch for event: {:?}",
                event
            );
        }
    }

    #[cfg(feature = "account-lockout")]
    #[test]
    fn event_type_name_account_lockout_variants() {
        let uid = Uuid::new_v4();
        assert_eq!(
            event_type_name(&AuthEvent::AccountLocked {
                user_id: uid,
                email: "a@b.com".into(),
                locked_until: None,
            }),
            "account.locked"
        );
        assert_eq!(
            event_type_name(&AuthEvent::AccountUnlocked {
                user_id: uid,
                method: "admin".into(),
            }),
            "account.unlocked"
        );
    }

    #[test]
    fn create_webhook_request_deserialization() {
        let json = r#"{"url":"https://example.com/hook","events":["user.registered","*"]}"#;
        let req: CreateWebhookRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.url, "https://example.com/hook");
        assert_eq!(req.events, vec!["user.registered", "*"]);
        assert!(req.secret.is_none());

        let json_with_secret =
            r#"{"url":"https://example.com","events":["login.succeeded"],"secret":"mysecret"}"#;
        let req2: CreateWebhookRequest = serde_json::from_str(json_with_secret).unwrap();
        assert_eq!(req2.secret.as_deref(), Some("mysecret"));
    }
}
