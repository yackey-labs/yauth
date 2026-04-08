//! SeaORM entity for `yauth_authorization_codes` (SQLite dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_authorization_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub code_hash: String,
    #[sea_orm(column_type = "Text")]
    pub client_id: String,
    #[sea_orm(column_type = "Text")]
    pub user_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub scopes: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub redirect_uri: String,
    #[sea_orm(column_type = "Text")]
    pub code_challenge: String,
    #[sea_orm(column_type = "Text")]
    pub code_challenge_method: String,
    pub expires_at: DateTimeWithTimeZone,
    pub used: bool,
    #[sea_orm(column_type = "Text", nullable)]
    pub nonce: Option<String>,
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
    pub fn into_domain(self) -> crate::domain::AuthorizationCode {
        crate::domain::AuthorizationCode {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            code_hash: self.code_hash,
            client_id: self.client_id,
            user_id: crate::backends::seaorm_common::str_to_uuid(&self.user_id),
            scopes: self.scopes.and_then(|s| serde_json::from_str(&s).ok()),
            redirect_uri: self.redirect_uri,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            expires_at: self.expires_at.naive_utc(),
            used: self.used,
            nonce: self.nonce,
            created_at: self.created_at.naive_utc(),
        }
    }
}
