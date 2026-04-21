//! Toasty model for `yauth_webhooks`.
//!
//! Declares `#[has_many]` inverse relationship for webhook deliveries.

use super::YauthWebhookDelivery;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "webhooks"]
pub struct YauthWebhook {
    #[key]
    pub id: Uuid,

    pub url: String,
    pub secret: String,

    #[serialize(json)]
    pub events: Vec<String>,

    pub active: bool,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,

    #[has_many]
    pub deliveries: toasty::HasMany<YauthWebhookDelivery>,
}
