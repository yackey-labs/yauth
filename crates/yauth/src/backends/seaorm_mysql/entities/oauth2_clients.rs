//! SeaORM entity for `yauth_oauth2_clients` (MySQL dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_oauth2_clients")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
    pub id: String,
    #[sea_orm(column_type = "Text", unique)]
    pub client_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub client_secret_hash: Option<String>,
    #[sea_orm(column_type = "Json")]
    pub redirect_uris: serde_json::Value,
    #[sea_orm(column_type = "Text", nullable)]
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

impl Model {
    pub fn into_domain(self) -> crate::domain::Oauth2Client {
        crate::domain::Oauth2Client {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            redirect_uris: self.redirect_uris,
            client_name: self.client_name,
            grant_types: self.grant_types,
            scopes: self.scopes,
            is_public: self.is_public,
            created_at: self.created_at.naive_utc(),
        }
    }
}
