use chrono::NaiveDateTime;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};

#[derive(sqlx::FromRow)]
struct WebhookRow {
    id: Uuid,
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
            id: self.id,
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
    id: Uuid,
    webhook_id: Uuid,
    event_type: String,
    payload: serde_json::Value,
    status_code: Option<i16>,
    response_body: Option<String>,
    success: bool,
    attempt: i32,
    created_at: NaiveDateTime,
}

// ── Webhook ──

pub(crate) struct SqlxSqliteWebhookRepo {
    pool: SqlitePool,
}
impl SqlxSqliteWebhookRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteWebhookRepo {}

impl WebhookRepository for SqlxSqliteWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, WebhookRow>(
                "SELECT id, url, secret, events, active, created_at, updated_at \
                 FROM yauth_webhooks WHERE id = ?",
            )
            .bind(id)
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
            .bind(input.id)
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
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;
                return Ok(row.into_domain());
            }

            let sql = format!(
                "UPDATE yauth_webhooks SET {} WHERE id = ? \
                 RETURNING id, url, secret, events, active, created_at, updated_at",
                sets.join(", ")
            );

            let mut query = sqlx::query_as::<_, WebhookRow>(&sql);

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

            // WHERE id = ? — id bound last
            let row = query
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_webhooks WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── WebhookDelivery ──

pub(crate) struct SqlxSqliteWebhookDeliveryRepo {
    pool: SqlitePool,
}
impl SqlxSqliteWebhookDeliveryRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteWebhookDeliveryRepo {}

impl WebhookDeliveryRepository for SqlxSqliteWebhookDeliveryRepo {
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
            .bind(webhook_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows
                .into_iter()
                .map(|r| domain::WebhookDelivery {
                    id: r.id,
                    webhook_id: r.webhook_id,
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
            .bind(input.id)
            .bind(input.webhook_id)
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
