//! Toasty model for `yauth_webhooks`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "webhooks"]
pub struct YauthWebhook {
    #[key]
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    /// JSON events list, serialized as string.
    pub events: String,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
}
