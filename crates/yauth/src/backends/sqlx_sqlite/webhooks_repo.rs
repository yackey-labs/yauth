use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{dt_to_str, sqlx_err, str_to_dt, str_to_json, str_to_uuid};
use crate::domain;
use crate::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};

#[derive(sqlx::FromRow)]
struct WebhookRow {
    id: Option<String>,
    url: String,
    secret: String,
    events: String,
    active: i64,
    created_at: String,
    updated_at: String,
}

impl WebhookRow {
    fn into_domain(self) -> domain::Webhook {
        domain::Webhook {
            id: str_to_uuid(&self.id.unwrap_or_default()),
            url: self.url,
            secret: self.secret,
            events: str_to_json(&self.events),
            active: self.active != 0,
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}

#[derive(sqlx::FromRow)]
struct WebhookDeliveryRow {
    id: Option<String>,
    webhook_id: Option<String>,
    event_type: String,
    payload: String,
    status_code: Option<i64>,
    response_body: Option<String>,
    success: i64,
    attempt: i64,
    created_at: String,
}

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
            let id_str = id.to_string();
            let row = sqlx::query_as!(
                WebhookRow,
                "SELECT id, url, secret, events, active, created_at, updated_at \
                 FROM yauth_webhooks WHERE id = ? /* sqlite */",
                id_str
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
                 FROM yauth_webhooks WHERE active = true /* sqlite */"
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
                "SELECT id, url, secret, events, active, created_at, updated_at FROM yauth_webhooks /* sqlite */"
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewWebhook) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let events_str = input.events.to_string();
            let created_str = dt_to_str(input.created_at);
            let updated_str = dt_to_str(input.updated_at);
            sqlx::query!(
                "INSERT INTO yauth_webhooks (id, url, secret, events, active, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                input.url,
                input.secret,
                events_str,
                input.active,
                created_str,
                updated_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        Box::pin(async move {
            let id_str = id.to_string();

            // Dynamic update — must stay as runtime query()
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
                let row = sqlx::query_as!(
                    WebhookRow,
                    "SELECT id, url, secret, events, active, created_at, updated_at \
                     FROM yauth_webhooks WHERE id = ? /* sqlite */",
                    id_str
                )
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
                query = query.bind(events.to_string());
            }
            if let Some(active) = changes.active {
                query = query.bind(active as i64);
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(dt_to_str(updated_at));
            }

            let row = query
                .bind(&id_str)
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!(
                "DELETE FROM yauth_webhooks WHERE id = ? /* sqlite */",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

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
            let webhook_id_str = webhook_id.to_string();
            let rows = sqlx::query_as!(
                WebhookDeliveryRow,
                "SELECT id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at \
                 FROM yauth_webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC LIMIT ? /* sqlite */",
                webhook_id_str,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows
                .into_iter()
                .map(|r| domain::WebhookDelivery {
                    id: str_to_uuid(&r.id.unwrap_or_default()),
                    webhook_id: str_to_uuid(&r.webhook_id.unwrap_or_default()),
                    event_type: r.event_type,
                    payload: str_to_json(&r.payload),
                    status_code: r.status_code.map(|v| v as i16),
                    response_body: r.response_body,
                    success: r.success != 0,
                    attempt: r.attempt as i32,
                    created_at: str_to_dt(&r.created_at),
                })
                .collect())
        })
    }

    fn create(&self, input: domain::NewWebhookDelivery) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let webhook_id_str = input.webhook_id.to_string();
            let payload_str = input.payload.to_string();
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_webhook_deliveries (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                webhook_id_str,
                input.event_type,
                payload_str,
                input.status_code,
                input.response_body,
                input.success,
                input.attempt,
                created_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
