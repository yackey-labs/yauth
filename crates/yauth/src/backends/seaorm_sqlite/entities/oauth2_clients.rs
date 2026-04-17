//! SeaORM entity for `yauth_oauth2_clients` (SQLite dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_oauth2_clients")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text", unique)]
    pub client_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub client_secret_hash: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub redirect_uris: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub client_name: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub grant_types: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub scopes: Option<String>,
    pub is_public: bool,
    pub created_at: DateTimeWithTimeZone,
    #[sea_orm(column_type = "Text", nullable)]
    pub token_endpoint_auth_method: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub public_key_pem: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub jwks_uri: Option<String>,
    #[sea_orm(nullable)]
    pub banned_at: Option<DateTimeWithTimeZone>,
    #[sea_orm(column_type = "Text", nullable)]
    pub banned_reason: Option<String>,
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
            redirect_uris: crate::backends::seaorm_common::str_to_json(&self.redirect_uris),
            client_name: self.client_name,
            grant_types: crate::backends::seaorm_common::str_to_json(&self.grant_types),
            scopes: self.scopes.and_then(|s| serde_json::from_str(&s).ok()),
            is_public: self.is_public,
            created_at: self.created_at.naive_utc(),
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            public_key_pem: self.public_key_pem,
            jwks_uri: self.jwks_uri,
            banned_at: self.banned_at.map(|dt| dt.naive_utc()),
            banned_reason: self.banned_reason,
        }
    }
}
