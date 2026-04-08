use sea_orm::prelude::*;
use sea_orm::sea_query::{Expr, Func};
use sea_orm::{ActiveModelTrait, ExprTrait, QueryOrder, QuerySelect, Set};
use uuid::Uuid;

use super::entities::{sessions, users};
use super::{sea_conflict, sea_err};
use crate::domain;
use crate::repo::{RepoFuture, SessionRepository, UserRepository, sealed};

pub(crate) struct SeaOrmUserRepo {
    db: DatabaseConnection,
}

impl SeaOrmUserRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmUserRepo {}

impl UserRepository for SeaOrmUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let row = users::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>> {
        let email = email.to_lowercase();
        Box::pin(async move {
            let row = users::Entity::find()
                .filter(Expr::expr(Func::lower(Expr::col(users::Column::Email))).eq(email))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let model = users::ActiveModel {
                id: Set(input.id.to_string()),
                email: Set(input.email),
                display_name: Set(input.display_name),
                email_verified: Set(input.email_verified),
                role: Set(input.role),
                banned: Set(input.banned),
                banned_reason: Set(input.banned_reason),
                banned_until: Set(super::opt_to_tz(input.banned_until)),
                created_at: Set(super::to_tz(input.created_at)),
                updated_at: Set(super::to_tz(input.updated_at)),
            };
            let result = model.insert(&self.db).await.map_err(sea_conflict)?;
            Ok(result.into_domain())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let existing = users::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?
                .ok_or(crate::repo::RepoError::NotFound)?;

            let mut model: users::ActiveModel = existing.into();

            if let Some(email) = changes.email {
                model.email = Set(email);
            }
            if let Some(display_name) = changes.display_name {
                model.display_name = Set(display_name);
            }
            if let Some(email_verified) = changes.email_verified {
                model.email_verified = Set(email_verified);
            }
            if let Some(role) = changes.role {
                model.role = Set(role);
            }
            if let Some(banned) = changes.banned {
                model.banned = Set(banned);
            }
            if let Some(banned_reason) = changes.banned_reason {
                model.banned_reason = Set(banned_reason);
            }
            if let Some(banned_until) = changes.banned_until {
                model.banned_until = Set(super::opt_to_tz(banned_until));
            }
            if let Some(updated_at) = changes.updated_at {
                model.updated_at = Set(super::to_tz(updated_at));
            }

            let result = model.update(&self.db).await.map_err(sea_err)?;
            Ok(result.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            users::Entity::delete_by_id(id.to_string())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn any_exists(&self) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let count = users::Entity::find()
                .count(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(count > 0)
        })
    }

    fn list(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::User>, i64)> {
        let search = search.map(|s| s.to_string());
        Box::pin(async move {
            let mut query = users::Entity::find();

            if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                query = query
                    .filter(Expr::expr(Func::lower(Expr::col(users::Column::Email))).like(pattern));
            }

            let total = query.clone().count(&self.db).await.map_err(sea_err)? as i64;

            let rows = query
                .order_by_desc(users::Column::CreatedAt)
                .limit(Some(limit as u64))
                .offset(Some(offset as u64))
                .all(&self.db)
                .await
                .map_err(sea_err)?;

            Ok((rows.into_iter().map(|m| m.into_domain()).collect(), total))
        })
    }
}

// -- Session Repository --

pub(crate) struct SeaOrmSessionRepo {
    db: DatabaseConnection,
}

impl SeaOrmSessionRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmSessionRepo {}

impl SessionRepository for SeaOrmSessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let row = sessions::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = sessions::ActiveModel {
                id: Set(input.id.to_string()),
                user_id: Set(input.user_id.to_string()),
                token_hash: Set(input.token_hash),
                ip_address: Set(input.ip_address),
                user_agent: Set(input.user_agent),
                expires_at: Set(super::to_tz(input.expires_at)),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sessions::Entity::delete_by_id(id.to_string())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn list(&self, limit: i64, offset: i64) -> RepoFuture<'_, (Vec<domain::Session>, i64)> {
        Box::pin(async move {
            let total = sessions::Entity::find()
                .count(&self.db)
                .await
                .map_err(sea_err)? as i64;

            let rows = sessions::Entity::find()
                .order_by_desc(sessions::Column::CreatedAt)
                .limit(Some(limit as u64))
                .offset(Some(offset as u64))
                .all(&self.db)
                .await
                .map_err(sea_err)?;

            Ok((rows.into_iter().map(|m| m.into_domain()).collect(), total))
        })
    }
}
