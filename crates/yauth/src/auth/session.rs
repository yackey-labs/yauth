use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sea_orm::DatabaseConnection;

use super::crypto;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

pub async fn create_session(
    db: &DatabaseConnection,
    user_id: Uuid,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<(String, Uuid), sea_orm::DbErr> {
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let session_id = Uuid::new_v4();

    let now = Utc::now().fixed_offset();
    let expires_at = (Utc::now() + Duration::days(7)).fixed_offset();

    let session = yauth_entity::sessions::ActiveModel {
        id: Set(session_id),
        user_id: Set(user_id),
        token_hash: Set(token_hash),
        ip_address: Set(ip_address),
        user_agent: Set(user_agent),
        expires_at: Set(expires_at),
        created_at: Set(now),
    };

    session.insert(db).await?;
    Ok((token, session_id))
}

pub async fn validate_session(
    db: &DatabaseConnection,
    token: &str,
) -> Result<Option<SessionUser>, sea_orm::DbErr> {
    let token_hash = crypto::hash_token(token);

    let session = yauth_entity::sessions::Entity::find()
        .filter(yauth_entity::sessions::Column::TokenHash.eq(&token_hash))
        .one(db)
        .await?;

    match session {
        Some(s) => {
            let now = Utc::now().fixed_offset();
            if s.expires_at < now {
                // Session expired — clean it up
                yauth_entity::sessions::Entity::delete_by_id(s.id)
                    .exec(db)
                    .await?;
                Ok(None)
            } else {
                Ok(Some(SessionUser {
                    user_id: s.user_id,
                    session_id: s.id,
                }))
            }
        }
        None => Ok(None),
    }
}

pub async fn delete_session(db: &DatabaseConnection, token: &str) -> Result<bool, sea_orm::DbErr> {
    let token_hash = crypto::hash_token(token);

    let result = yauth_entity::sessions::Entity::delete_many()
        .filter(yauth_entity::sessions::Column::TokenHash.eq(&token_hash))
        .exec(db)
        .await?;
    Ok(result.rows_affected > 0)
}

pub async fn delete_all_user_sessions(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<u64, sea_orm::DbErr> {
    let result = yauth_entity::sessions::Entity::delete_many()
        .filter(yauth_entity::sessions::Column::UserId.eq(user_id))
        .exec(db)
        .await?;
    Ok(result.rows_affected)
}
