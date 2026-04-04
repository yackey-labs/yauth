use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,
    pub credential: serde_json::Value,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWebauthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,
    pub credential: serde_json::Value,
    pub created_at: NaiveDateTime,
}
