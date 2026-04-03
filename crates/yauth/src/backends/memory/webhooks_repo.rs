use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use crate::domain;
use crate::repo::{RepoError, RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};

// ──────────────────────────────────────────────
// Webhook Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryWebhookRepo {
    webhooks: Arc<RwLock<HashMap<Uuid, domain::Webhook>>>,
}

impl InMemoryWebhookRepo {
    pub(crate) fn new(webhooks: Arc<RwLock<HashMap<Uuid, domain::Webhook>>>) -> Self {
        Self { webhooks }
    }
}

impl sealed::Sealed for InMemoryWebhookRepo {}

impl WebhookRepository for InMemoryWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let map = self.webhooks.read().unwrap();
            Ok(map.get(&id).cloned())
        })
    }

    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let map = self.webhooks.read().unwrap();
            Ok(map.values().filter(|w| w.active).cloned().collect())
        })
    }

    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let map = self.webhooks.read().unwrap();
            Ok(map.values().cloned().collect())
        })
    }

    fn create(&self, input: domain::NewWebhook) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let webhook = domain::Webhook {
                id: input.id,
                url: input.url,
                secret: input.secret,
                events: input.events,
                active: input.active,
                created_at: input.created_at,
                updated_at: input.updated_at,
            };
            let mut map = self.webhooks.write().unwrap();
            map.insert(webhook.id, webhook);
            Ok(())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        Box::pin(async move {
            let mut map = self.webhooks.write().unwrap();
            let webhook = map.get_mut(&id).ok_or(RepoError::NotFound)?;

            if let Some(url) = changes.url {
                webhook.url = url;
            }
            if let Some(secret) = changes.secret {
                webhook.secret = secret;
            }
            if let Some(events) = changes.events {
                webhook.events = events;
            }
            if let Some(active) = changes.active {
                webhook.active = active;
            }
            if let Some(updated_at) = changes.updated_at {
                webhook.updated_at = updated_at;
            } else {
                webhook.updated_at = Utc::now().naive_utc();
            }

            Ok(webhook.clone())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.webhooks.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Webhook Delivery Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryWebhookDeliveryRepo {
    deliveries: Arc<RwLock<HashMap<Uuid, domain::WebhookDelivery>>>,
}

impl InMemoryWebhookDeliveryRepo {
    pub(crate) fn new(deliveries: Arc<RwLock<HashMap<Uuid, domain::WebhookDelivery>>>) -> Self {
        Self { deliveries }
    }
}

impl sealed::Sealed for InMemoryWebhookDeliveryRepo {}

impl WebhookDeliveryRepository for InMemoryWebhookDeliveryRepo {
    fn find_by_webhook_id(
        &self,
        webhook_id: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>> {
        Box::pin(async move {
            let map = self.deliveries.read().unwrap();
            let mut results: Vec<domain::WebhookDelivery> = map
                .values()
                .filter(|d| d.webhook_id == webhook_id)
                .cloned()
                .collect();
            results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            results.truncate(limit as usize);
            Ok(results)
        })
    }

    fn create(&self, input: domain::NewWebhookDelivery) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let delivery = domain::WebhookDelivery {
                id: input.id,
                webhook_id: input.webhook_id,
                event_type: input.event_type,
                payload: input.payload,
                status_code: input.status_code,
                response_body: input.response_body,
                success: input.success,
                attempt: input.attempt,
                created_at: input.created_at,
            };
            let mut map = self.deliveries.write().unwrap();
            map.insert(delivery.id, delivery);
            Ok(())
        })
    }
}
