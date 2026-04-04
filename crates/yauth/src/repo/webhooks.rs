use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for webhook configurations.
pub trait WebhookRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>>;

    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>>;

    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>>;

    fn create(&self, input: domain::NewWebhook) -> RepoFuture<'_, ()>;

    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;
}

/// Repository for webhook delivery records.
pub trait WebhookDeliveryRepository: sealed::Sealed + Send + Sync {
    fn find_by_webhook_id(
        &self,
        webhook_id: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>>;

    fn create(&self, input: domain::NewWebhookDelivery) -> RepoFuture<'_, ()>;
}
