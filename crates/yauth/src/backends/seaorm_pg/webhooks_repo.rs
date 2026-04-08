use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, QueryOrder, QuerySelect, Set};
use uuid::Uuid;

use super::entities::{webhook_deliveries, webhooks};
use super::sea_err;
use crate::domain;
use crate::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};

// ── WebhookRepository ──

pub(crate) struct SeaOrmWebhookRepo {
    db: DatabaseConnection,
}

impl SeaOrmWebhookRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmWebhookRepo {}

impl WebhookRepository for SeaOrmWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let row = webhooks::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let rows = webhooks::Entity::find()
                .filter(webhooks::Column::Active.eq(true))
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows.into_iter().map(|m| m.into_domain()).collect())
        })
    }

    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let rows = webhooks::Entity::find()
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows.into_iter().map(|m| m.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewWebhook) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = webhooks::ActiveModel {
                id: Set(input.id),
                url: Set(input.url),
                secret: Set(input.secret),
                events: Set(input.events),
                active: Set(input.active),
                created_at: Set(super::to_tz(input.created_at)),
                updated_at: Set(super::to_tz(input.updated_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        Box::pin(async move {
            let existing = webhooks::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .map_err(sea_err)?
                .ok_or(crate::repo::RepoError::NotFound)?;

            let mut model: webhooks::ActiveModel = existing.into();

            if let Some(url) = changes.url {
                model.url = Set(url);
            }
            if let Some(secret) = changes.secret {
                model.secret = Set(secret);
            }
            if let Some(events) = changes.events {
                model.events = Set(events);
            }
            if let Some(active) = changes.active {
                model.active = Set(active);
            }
            if let Some(updated_at) = changes.updated_at {
                model.updated_at = Set(super::to_tz(updated_at));
            }

            let result = model.update(&self.db).await.map_err(sea_err)?;
            Ok(result.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            webhooks::Entity::delete_many()
                .filter(webhooks::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}

// ── WebhookDeliveryRepository ──

pub(crate) struct SeaOrmWebhookDeliveryRepo {
    db: DatabaseConnection,
}

impl SeaOrmWebhookDeliveryRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmWebhookDeliveryRepo {}

impl WebhookDeliveryRepository for SeaOrmWebhookDeliveryRepo {
    fn find_by_webhook_id(
        &self,
        webhook_id: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>> {
        Box::pin(async move {
            let rows = webhook_deliveries::Entity::find()
                .filter(webhook_deliveries::Column::WebhookId.eq(webhook_id))
                .order_by_desc(webhook_deliveries::Column::CreatedAt)
                .limit(Some(limit as u64))
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows.into_iter().map(|m| m.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewWebhookDelivery) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = webhook_deliveries::ActiveModel {
                id: Set(input.id),
                webhook_id: Set(input.webhook_id),
                event_type: Set(input.event_type),
                payload: Set(input.payload),
                status_code: Set(input.status_code),
                response_body: Set(input.response_body),
                success: Set(input.success),
                attempt: Set(input.attempt),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }
}
