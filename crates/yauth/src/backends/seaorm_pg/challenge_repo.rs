use sea_orm::prelude::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ConnectionTrait, Schema, Set};

use super::entities::challenges;
use super::sea_err;
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};

pub(crate) struct SeaOrmChallengeRepo {
    db: DatabaseConnection,
    initialized: tokio::sync::OnceCell<()>,
}

impl SeaOrmChallengeRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                let schema = Schema::new(self.db.get_database_backend());
                let stmt = schema
                    .create_table_from_entity(challenges::Entity)
                    .if_not_exists()
                    .to_owned();
                let builder = self.db.get_database_backend();
                self.db
                    .execute_unprepared(&builder.build(&stmt).to_string())
                    .await
                    .map_err(sea_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl sealed::Sealed for SeaOrmChallengeRepo {}

impl ChallengeRepository for SeaOrmChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            // Cleanup expired
            challenges::Entity::delete_many()
                .filter(challenges::Column::ExpiresAt.lt(chrono::Utc::now().fixed_offset()))
                .exec(&self.db)
                .await
                .ok();

            let expires_at =
                chrono::Utc::now().fixed_offset() + chrono::Duration::seconds(ttl_secs as i64);

            let model = challenges::ActiveModel {
                key: Set(key),
                value: Set(value),
                expires_at: Set(expires_at),
            };

            challenges::Entity::insert(model)
                .on_conflict(
                    OnConflict::column(challenges::Column::Key)
                        .update_columns([challenges::Column::Value, challenges::Column::ExpiresAt])
                        .to_owned(),
                )
                .exec(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let row = challenges::Entity::find_by_id(&key)
                .filter(challenges::Column::ExpiresAt.gt(chrono::Utc::now().fixed_offset()))
                .one(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(row.map(|m| m.value))
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            challenges::Entity::delete_many()
                .filter(challenges::Column::Key.eq(&key))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(())
        })
    }
}
