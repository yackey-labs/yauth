use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "yauth_oauth2_clients")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    #[sea_orm(column_type = "Json")]
    pub redirect_uris: serde_json::Value,
    pub client_name: Option<String>,
    #[sea_orm(column_type = "Json")]
    pub grant_types: serde_json::Value,
    #[sea_orm(column_type = "Json", nullable)]
    pub scopes: Option<serde_json::Value>,
    pub is_public: bool,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
