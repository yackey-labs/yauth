use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware as axum_mw,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::config::WebhookConfig;
use crate::error::{ApiError, api_err};
use crate::middleware::{AuthUser, require_admin};
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::repo::Repositories;
use crate::state::YAuthState;

type HmacSha256 = Hmac<Sha256>;

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
        let repos = ctx.state.repos.clone();
        let event_clone = event.clone();
        let max_retries = self.config.max_retries;
        let retry_delay = self.config.retry_delay;
        let timeout = self.config.timeout;

        tokio::spawn(async move {
            if let Err(e) =
                dispatch_webhooks(repos, event_clone, max_retries, retry_delay, timeout).await
            {
                crate::otel::record_error("webhook_dispatch_error", &e);
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

async fn dispatch_webhooks(
    repos: Repositories,
    event: AuthEvent,
    max_retries: u32,
    retry_delay: std::time::Duration,
    timeout: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let event_type = event_type_name(&event);
    let payload = serde_json::to_value(&event)?;

    // Load active webhooks
    let webhooks = repos
        .webhooks_repo
        .find_active()
        .await
        .map_err(|e| e.to_string())?;

    let client = reqwest::Client::builder().timeout(timeout).build()?;

    for webhook in webhooks {
        let events: Vec<String> =
            serde_json::from_value(webhook.events.clone()).unwrap_or_default();
        if !events.contains(&"*".to_string()) && !events.contains(&event_type.to_string()) {
            continue;
        }

        // Defense in depth: skip delivery if URL fails SSRF check (may pre-date validation)
        if !is_ssrf_safe(&webhook.url) {
            crate::otel::add_event(
                "webhook_skipped_private_url",
                #[cfg(feature = "telemetry")]
                vec![
                    opentelemetry::KeyValue::new("webhook.id", webhook.id.to_string()),
                    opentelemetry::KeyValue::new("webhook.url", webhook.url.clone()),
                ],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
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
                        let new_delivery = crate::domain::NewWebhookDelivery {
                            id: Uuid::new_v4(),
                            webhook_id: webhook.id,
                            event_type: event_type.to_string(),
                            payload: body.clone(),
                            status_code: Some(status),
                            response_body: Some(truncate_response(&resp_body)),
                            success: true,
                            attempt: attempt as i32,
                            created_at: Utc::now().naive_utc(),
                        };
                        if let Err(e) = repos.webhook_deliveries.create(new_delivery).await {
                            crate::otel::record_error("webhook_delivery_record_failed", &e);
                        }
                        break;
                    } else if (500..600).contains(&(status as u16)) && attempt <= max_retries {
                        crate::otel::add_event(
                            "webhook_delivery_5xx_retry",
                            #[cfg(feature = "telemetry")]
                            vec![
                                opentelemetry::KeyValue::new("webhook.id", webhook.id.to_string()),
                                opentelemetry::KeyValue::new("http.status", status.to_string()),
                                opentelemetry::KeyValue::new("attempt", attempt as i64),
                            ],
                            #[cfg(not(feature = "telemetry"))]
                            vec![],
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
                        crate::otel::add_event(
                            "webhook_delivery_failed_retry",
                            #[cfg(feature = "telemetry")]
                            vec![
                                opentelemetry::KeyValue::new("webhook.id", webhook.id.to_string()),
                                opentelemetry::KeyValue::new("error.message", e.to_string()),
                                opentelemetry::KeyValue::new("attempt", attempt as i64),
                            ],
                            #[cfg(not(feature = "telemetry"))]
                            vec![],
                        );
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }

        if !success {
            let new_delivery = crate::domain::NewWebhookDelivery {
                id: Uuid::new_v4(),
                webhook_id: webhook.id,
                event_type: event_type.to_string(),
                payload: body.clone(),
                status_code: last_status,
                response_body: last_body.as_deref().map(truncate_response),
                success: false,
                attempt: (max_retries + 1) as i32,
                created_at: Utc::now().naive_utc(),
            };
            if let Err(e) = repos.webhook_deliveries.create(new_delivery).await {
                crate::otel::record_error("webhook_delivery_record_failed", &e);
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

impl From<crate::domain::Webhook> for WebhookResponse {
    fn from(r: crate::domain::Webhook) -> Self {
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

impl From<crate::domain::WebhookDelivery> for WebhookDeliveryResponse {
    fn from(r: crate::domain::WebhookDelivery) -> Self {
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
// URL validation helper
// ---------------------------------------------------------------------------

fn is_ssrf_safe(url_str: &str) -> bool {
    let parsed = match url::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let host = match parsed.host_str() {
        Some(h) => h,
        None => return false,
    };

    // Block obvious internal hostnames
    let blocked_hosts = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "[::1]",
        "metadata.google.internal",
    ];
    if blocked_hosts.contains(&host) {
        return false;
    }

    // Block private IP ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || (v4.octets()[0] == 169 && v4.octets()[1] == 254) // link-local
                    || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
                // CGN
                {
                    return false;
                }
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return false;
                }
            }
        }
    }

    true
}

fn validate_webhook_url(url: &str) -> Result<(), ApiError> {
    if url.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "URL is required"));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) || !url.contains('.') {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Invalid webhook URL: must be an HTTP or HTTPS URL",
        ));
    }
    if !is_ssrf_safe(url) {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Webhook URL must not point to internal or private networks",
        ));
    }
    Ok(())
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
    validate_webhook_url(&input.url)?;

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

    let now = Utc::now();
    let id = Uuid::new_v4();
    let events_json = serde_json::to_value(&input.events).unwrap();

    let new_webhook = crate::domain::NewWebhook {
        id,
        url: input.url.clone(),
        secret: secret.clone(),
        events: events_json,
        active: true,
        created_at: now.naive_utc(),
        updated_at: now.naive_utc(),
    };

    state
        .repos
        .webhooks_repo
        .create(new_webhook)
        .await
        .map_err(|e| {
            crate::otel::record_error("webhook_create_db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    crate::otel::add_event(
        "webhook_created",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("webhook.id", id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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

// ---------------------------------------------------------------------------
// GET /webhooks -- list webhooks
// ---------------------------------------------------------------------------

async fn list_webhooks(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
) -> Result<impl IntoResponse, ApiError> {
    let webhooks = state.repos.webhooks_repo.find_all().await.map_err(|e| {
        crate::otel::record_error("webhook_list_db_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let responses: Vec<WebhookResponse> = webhooks.into_iter().map(Into::into).collect();

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
    let webhook = state
        .repos
        .webhooks_repo
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("webhook_fetch_db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;

    let deliveries = state
        .repos
        .webhook_deliveries
        .find_by_webhook_id(id, 50)
        .await
        .map_err(|e| {
            crate::otel::record_error("webhook_deliveries_fetch_db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let delivery_responses: Vec<WebhookDeliveryResponse> =
        deliveries.into_iter().map(Into::into).collect();

    let detail = WebhookDetailResponse {
        webhook: webhook.into(),
        recent_deliveries: delivery_responses,
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
    // Check existence first
    state
        .repos
        .webhooks_repo
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("webhook_fetch_db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;

    // Validate URL if being updated
    if let Some(ref url) = input.url {
        validate_webhook_url(url)?;
    }

    let events_json = input
        .events
        .as_ref()
        .map(|e| serde_json::to_value(e).unwrap());
    let now = Utc::now();

    let changeset = crate::domain::UpdateWebhook {
        url: input.url.clone(),
        events: events_json,
        secret: input.secret.clone(),
        active: input.active,
        updated_at: Some(now.naive_utc()),
    };

    let updated = state
        .repos
        .webhooks_repo
        .update(id, changeset)
        .await
        .map_err(|e| {
            crate::otel::record_error("webhook_update_db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let response: WebhookResponse = updated.into();

    crate::otel::add_event(
        "webhook_updated",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("webhook.id", id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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
    state
        .repos
        .webhooks_repo
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("webhook_fetch_db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;

    state.repos.webhooks_repo.delete(id).await.map_err(|e| {
        crate::otel::record_error("webhook_delete_db_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    crate::otel::add_event(
        "webhook_deleted",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("admin.id", admin.id.to_string()),
            opentelemetry::KeyValue::new("webhook.id", id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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
    // Fetch webhook
    let webhook = state
        .repos
        .webhooks_repo
        .find_by_id(id)
        .await
        .map_err(|e| {
            crate::otel::record_error("webhook_fetch_db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Webhook not found"))?;

    // SSRF check before sending test delivery
    if !is_ssrf_safe(&webhook.url) {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Webhook URL must not point to internal or private networks",
        ));
    }

    let body = serde_json::json!({
        "event": "test",
        "payload": {
            "message": "This is a test webhook delivery",
            "triggered_by": admin.id,
        },
        "timestamp": Utc::now().to_rfc3339(),
        "webhook_id": webhook.id,
    });
    let body_str = serde_json::to_string(&body)
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Serialization error"))?;

    let signature = compute_signature(&webhook.secret, &body_str);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "HTTP client error"))?;

    let result = client
        .post(&webhook.url)
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
    let new_delivery = crate::domain::NewWebhookDelivery {
        id: Uuid::new_v4(),
        webhook_id: webhook.id,
        event_type: "test".to_string(),
        payload: body,
        status_code,
        response_body: response_body.clone(),
        success,
        attempt: 1,
        created_at: Utc::now().naive_utc(),
    };

    state
        .repos
        .webhook_deliveries
        .create(new_delivery)
        .await
        .map_err(|e| {
            crate::otel::record_error("webhook_test_delivery_record_db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

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
    fn is_ssrf_safe_allows_public_urls() {
        assert!(is_ssrf_safe("https://example.com/webhook"));
        assert!(is_ssrf_safe("https://hooks.slack.com/services/T00/B00/xxx"));
        assert!(is_ssrf_safe("http://203.0.113.50:8080/hook"));
    }

    #[test]
    fn is_ssrf_safe_blocks_localhost() {
        assert!(!is_ssrf_safe("http://localhost/hook"));
        assert!(!is_ssrf_safe("http://127.0.0.1/hook"));
        assert!(!is_ssrf_safe("http://0.0.0.0/hook"));
        assert!(!is_ssrf_safe("http://[::1]/hook"));
    }

    #[test]
    fn is_ssrf_safe_blocks_private_ips() {
        assert!(!is_ssrf_safe("http://10.0.0.1/hook"));
        assert!(!is_ssrf_safe("http://172.16.0.1/hook"));
        assert!(!is_ssrf_safe("http://192.168.1.1/hook"));
    }

    #[test]
    fn is_ssrf_safe_blocks_link_local_and_cgn() {
        assert!(!is_ssrf_safe("http://169.254.169.254/latest/meta-data/"));
        assert!(!is_ssrf_safe("http://100.64.0.1/hook"));
    }

    #[test]
    fn is_ssrf_safe_blocks_metadata_endpoint() {
        assert!(!is_ssrf_safe(
            "http://metadata.google.internal/computeMetadata/v1/"
        ));
    }

    #[test]
    fn is_ssrf_safe_rejects_invalid_urls() {
        assert!(!is_ssrf_safe("not-a-url"));
        assert!(!is_ssrf_safe(""));
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
