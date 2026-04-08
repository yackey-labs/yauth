//! Toasty model for `yauth_webhook_deliveries`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "webhook_deliveries"]
pub struct YauthWebhookDelivery {
    #[key]
    pub id: Uuid,
    #[index]
    pub webhook_id: Uuid,
    pub event_type: String,
    /// JSON payload, serialized as string.
    pub payload: String,
    pub status_code: Option<i32>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: String,
}
