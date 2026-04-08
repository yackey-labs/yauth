//! SeaORM entity for `yauth_magic_links` (MySQL dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_magic_links")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub email: String,
    #[sea_orm(column_type = "Text")]
    pub token_hash: String,
    pub expires_at: DateTimeWithTimeZone,
    pub used: bool,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> crate::domain::MagicLink {
        crate::domain::MagicLink {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            email: self.email,
            token_hash: self.token_hash,
            expires_at: self.expires_at.naive_utc(),
            used: self.used,
            created_at: self.created_at.naive_utc(),
        }
    }
}
