//! SeaORM entity for `yauth_sessions` (MySQL dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
    pub id: String,
    #[sea_orm(column_type = "Char(Some(36))")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub token_hash: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub ip_address: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub user_agent: Option<String>,
    pub expires_at: DateTimeWithTimeZone,
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
    pub fn into_domain(self) -> crate::domain::Session {
        crate::domain::Session {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            user_id: crate::backends::seaorm_common::str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            expires_at: self.expires_at.naive_utc(),
            created_at: self.created_at.naive_utc(),
        }
    }
}
