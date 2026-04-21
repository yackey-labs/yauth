//! Toasty model for `yauth_webhooks`.
//!
//! Inverse relationship (`has_many`) for deliveries is omitted — see `users.rs`
//! module doc. Use `YauthWebhookDelivery::filter_by_webhook_id()` instead.

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
}
