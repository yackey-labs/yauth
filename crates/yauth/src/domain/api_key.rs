use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Option<serde_json::Value>,
    pub last_used_at: Option<NaiveDateTime>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Option<serde_json::Value>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}
