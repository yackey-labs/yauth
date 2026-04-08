use sea_orm::Set;
use sea_orm::prelude::*;
use sea_orm::sea_query::OnConflict;

use super::entities::revocations;
use super::sea_err;
use crate::repo::{RepoFuture, RevocationRepository, sealed};

pub(crate) struct SeaOrmRevocationRepo {
    db: DatabaseConnection,
    initialized: tokio::sync::OnceCell<()>,
}

impl SeaOrmRevocationRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), crate::repo::RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                super::run_create_table(&self.db, revocations::Entity).await
            })
            .await
            .map(|_| ())
    }
}

impl sealed::Sealed for SeaOrmRevocationRepo {}

impl RevocationRepository for SeaOrmRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let expires_at =
                chrono::Utc::now().fixed_offset() + chrono::Duration::seconds(ttl.as_secs() as i64);

            let model = revocations::ActiveModel {
                key: Set(jti),
                expires_at: Set(expires_at),
            };

            revocations::Entity::insert(model)
                .on_conflict(
                    OnConflict::column(revocations::Column::Key)
                        .update_column(revocations::Column::ExpiresAt)
                        .to_owned(),
                )
                .exec(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(())
        })
    }

    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let row = revocations::Entity::find_by_id(&jti)
                .filter(revocations::Column::ExpiresAt.gt(chrono::Utc::now().fixed_offset()))
                .one(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(row.is_some())
        })
    }
}
