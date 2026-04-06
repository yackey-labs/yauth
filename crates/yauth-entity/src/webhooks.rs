use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    pub events: serde_json::Value,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWebhook {
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    pub events: serde_json::Value,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateWebhook {
    pub url: Option<String>,
    pub secret: Option<String>,
    pub events: Option<serde_json::Value>,
    pub active: Option<bool>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status_code: Option<i16>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status_code: Option<i16>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: NaiveDateTime,
}
