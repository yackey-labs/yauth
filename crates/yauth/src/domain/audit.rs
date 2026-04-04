use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub metadata: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub created_at: NaiveDateTime,
}
