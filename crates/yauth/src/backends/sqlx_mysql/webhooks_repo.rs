use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};

#[derive(sqlx::FromRow)]
struct WebhookRow {
    id: String,
    url: String,
    secret: String,
    events: serde_json::Value,
    active: bool,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl WebhookRow {
    fn into_domain(self) -> domain::Webhook {
        domain::Webhook {
            id: uuid::Uuid::parse_str(&self.id).unwrap_or_default(),
            url: self.url,
            secret: self.secret,
            events: self.events,
            active: self.active,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct WebhookDeliveryRow {
    id: String,
    webhook_id: String,
    event_type: String,
    payload: serde_json::Value,
    status_code: Option<i16>,
    response_body: Option<String>,
    success: bool,
    attempt: i32,
    created_at: NaiveDateTime,
}

// ── Webhook ──

pub(crate) struct SqlxMysqlWebhookRepo {
    pool: MySqlPool,
}
impl SqlxMysqlWebhookRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlWebhookRepo {}

impl WebhookRepository for SqlxMysqlWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, WebhookRow>(
                "SELECT id, url, secret, events, active, created_at, updated_at \
                 FROM yauth_webhooks WHERE id = ?",
            )
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let rows: Vec<WebhookRow> = sqlx::query_as(
                "SELECT id, url, secret, events, active, created_at, updated_at \
                 FROM yauth_webhooks WHERE active = true",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let rows: Vec<WebhookRow> = sqlx::query_as(
                "SELECT id, url, secret, events, active, created_at, updated_at FROM yauth_webhooks",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewWebhook) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_webhooks (id, url, secret, events, active, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(&input.url)
            .bind(&input.secret)
            .bind(&input.events)
            .bind(input.active)
            .bind(input.created_at)
            .bind(input.updated_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        Box::pin(async move {
            // Build dynamic update
            let mut sets = Vec::new();

            macro_rules! push_set {
                ($field:expr, $col:expr) => {
                    if $field.is_some() {
                        sets.push(format!("{} = ?", $col));
                    }
                };
            }

            push_set!(changes.url, "url");
            push_set!(changes.secret, "secret");
            push_set!(changes.events, "events");
            push_set!(changes.active, "active");
            push_set!(changes.updated_at, "updated_at");

            if sets.is_empty() {
                let row = sqlx::query_as::<_, WebhookRow>(
                    "SELECT id, url, secret, events, active, created_at, updated_at \
                     FROM yauth_webhooks WHERE id = ?",
                )
                .bind(id.to_string())
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;
                return Ok(row.into_domain());
            }

            // MySQL: no RETURNING — UPDATE then SELECT
            let sql = format!("UPDATE yauth_webhooks SET {} WHERE id = ?", sets.join(", "));

            let mut query = sqlx::query(&sql);

            if let Some(ref url) = changes.url {
                query = query.bind(url.clone());
            }
            if let Some(ref secret) = changes.secret {
                query = query.bind(secret.clone());
            }
            if let Some(ref events) = changes.events {
                query = query.bind(events.clone());
            }
            if let Some(active) = changes.active {
                query = query.bind(active);
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(updated_at);
            }

            query
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;

            let row = sqlx::query_as::<_, WebhookRow>(
                "SELECT id, url, secret, events, active, created_at, updated_at \
                 FROM yauth_webhooks WHERE id = ?",
            )
            .bind(id.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_webhooks WHERE id = ?")
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── WebhookDelivery ──

pub(crate) struct SqlxMysqlWebhookDeliveryRepo {
    pool: MySqlPool,
}
impl SqlxMysqlWebhookDeliveryRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlWebhookDeliveryRepo {}

impl WebhookDeliveryRepository for SqlxMysqlWebhookDeliveryRepo {
    fn find_by_webhook_id(
        &self,
        webhook_id: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>> {
        Box::pin(async move {
            let rows: Vec<WebhookDeliveryRow> = sqlx::query_as(
                "SELECT id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at \
                 FROM yauth_webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC LIMIT ?",
            )
            .bind(webhook_id.to_string())
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows
                .into_iter()
                .map(|r| domain::WebhookDelivery {
                    id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
                    webhook_id: uuid::Uuid::parse_str(&r.webhook_id).unwrap_or_default(),
                    event_type: r.event_type,
                    payload: r.payload,
                    status_code: r.status_code,
                    response_body: r.response_body,
                    success: r.success,
                    attempt: r.attempt,
                    created_at: r.created_at,
                })
                .collect())
        })
    }

    fn create(&self, input: domain::NewWebhookDelivery) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_webhook_deliveries (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(input.webhook_id.to_string())
            .bind(&input.event_type)
            .bind(&input.payload)
            .bind(input.status_code)
            .bind(&input.response_body)
            .bind(input.success)
            .bind(input.attempt)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
