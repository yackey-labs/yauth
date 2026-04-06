use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{naive_to_utc, sqlx_err};
use crate::domain;
use crate::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};

#[derive(sqlx::FromRow)]
struct WebhookRow {
    id: Uuid,
    url: String,
    secret: String,
    events: serde_json::Value,
    active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl WebhookRow {
    fn into_domain(self) -> domain::Webhook {
        domain::Webhook {
            id: self.id,
            url: self.url,
            secret: self.secret,
            events: self.events,
            active: self.active,
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
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
    created_at: DateTime<Utc>,
}

// ── Webhook ──

pub(crate) struct SqlxPgWebhookRepo {
    pool: PgPool,
}
impl SqlxPgWebhookRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgWebhookRepo {}

impl WebhookRepository for SqlxPgWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let row = sqlx::query_as!(
                WebhookRow,
                "SELECT id, url, secret, events, active, created_at, updated_at \
                 FROM yauth_webhooks WHERE id = $1",
                id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let rows = sqlx::query_as!(
                WebhookRow,
                "SELECT id, url, secret, events, active, created_at, updated_at \
                 FROM yauth_webhooks WHERE active = true"
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let rows = sqlx::query_as!(
                WebhookRow,
                "SELECT id, url, secret, events, active, created_at, updated_at FROM yauth_webhooks"
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewWebhook) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "INSERT INTO yauth_webhooks (id, url, secret, events, active, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                input.id,
                input.url,
                input.secret,
                input.events,
                input.active,
                naive_to_utc(input.created_at),
                naive_to_utc(input.updated_at),
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        // Dynamic SET clause — must stay as runtime query()
        Box::pin(async move {
            let mut sets = Vec::new();
            let mut param_idx = 1u32;

            macro_rules! push_set {
                ($field:expr, $col:expr) => {
                    if $field.is_some() {
                        param_idx += 1;
                        sets.push(format!("{} = ${}", $col, param_idx));
                    }
                };
            }

            push_set!(changes.url, "url");
            push_set!(changes.secret, "secret");
            push_set!(changes.events, "events");
            push_set!(changes.active, "active");
            push_set!(changes.updated_at, "updated_at");

            if sets.is_empty() {
                let row = sqlx::query_as!(
                    WebhookRow,
                    "SELECT id, url, secret, events, active, created_at, updated_at \
                     FROM yauth_webhooks WHERE id = $1",
                    id
                )
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;
                return Ok(row.into_domain());
            }

            let sql = format!(
                "UPDATE yauth_webhooks SET {} WHERE id = $1 \
                 RETURNING id, url, secret, events, active, created_at, updated_at",
                sets.join(", ")
            );

            let mut query = sqlx::query_as::<_, WebhookRow>(&sql).bind(id);

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

            let row = query.fetch_one(&self.pool).await.map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!("DELETE FROM yauth_webhooks WHERE id = $1", id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── WebhookDelivery ──

pub(crate) struct SqlxPgWebhookDeliveryRepo {
    pool: PgPool,
}
impl SqlxPgWebhookDeliveryRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgWebhookDeliveryRepo {}

impl WebhookDeliveryRepository for SqlxPgWebhookDeliveryRepo {
    fn find_by_webhook_id(
        &self,
        webhook_id: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>> {
        Box::pin(async move {
            let rows = sqlx::query_as!(
                WebhookDeliveryRow,
                r#"SELECT id, webhook_id as "webhook_id!", event_type, payload, status_code, response_body, success, attempt, created_at
                   FROM yauth_webhook_deliveries WHERE webhook_id = $1 ORDER BY created_at DESC LIMIT $2"#,
                webhook_id,
                limit,
            )
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
                    created_at: r.created_at.naive_utc(),
                })
                .collect())
        })
    }

    fn create(&self, input: domain::NewWebhookDelivery) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "INSERT INTO yauth_webhook_deliveries (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                input.id,
                input.webhook_id,
                input.event_type,
                input.payload,
                input.status_code,
                input.response_body as Option<String>,
                input.success,
                input.attempt,
                naive_to_utc(input.created_at),
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
