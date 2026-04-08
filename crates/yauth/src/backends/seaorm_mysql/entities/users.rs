//! SeaORM entity for `yauth_users` (MySQL dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
    pub id: String,
    #[sea_orm(column_type = "Text", unique)]
    pub email: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub display_name: Option<String>,
    pub email_verified: bool,
    #[sea_orm(column_type = "Text")]
    pub role: String,
    pub banned: bool,
    #[sea_orm(column_type = "Text", nullable)]
    pub banned_reason: Option<String>,
    pub banned_until: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::sessions::Entity")]
    Sessions,
    #[sea_orm(has_many = "super::audit_log::Entity")]
    AuditLog,
}

impl Related<super::sessions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sessions.def()
    }
}

impl Related<super::audit_log::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuditLog.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> crate::domain::User {
        crate::domain::User {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            email: self.email,
            display_name: self.display_name,
            email_verified: self.email_verified,
            role: self.role,
            banned: self.banned,
            banned_reason: self.banned_reason,
            banned_until: self.banned_until.map(|dt| dt.naive_utc()),
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
        }
    }
}
