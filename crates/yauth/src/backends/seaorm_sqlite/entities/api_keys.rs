//! SeaORM entity for `yauth_api_keys` (SQLite dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_api_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub key_prefix: String,
    #[sea_orm(column_type = "Text")]
    pub key_hash: String,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub scopes: Option<String>,
    pub last_used_at: Option<DateTimeWithTimeZone>,
    pub expires_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> crate::domain::ApiKey {
        crate::domain::ApiKey {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            user_id: crate::backends::seaorm_common::str_to_uuid(&self.user_id),
            key_prefix: self.key_prefix,
            key_hash: self.key_hash,
            name: self.name,
            scopes: self.scopes.and_then(|s| serde_json::from_str(&s).ok()),
            last_used_at: self.last_used_at.map(|dt| dt.naive_utc()),
            expires_at: self.expires_at.map(|dt| dt.naive_utc()),
            created_at: self.created_at.naive_utc(),
        }
    }
}
