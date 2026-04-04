use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOauthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOauthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}
