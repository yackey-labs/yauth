use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{ApiKeyRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

pub(crate) struct DieselApiKeyRepo {
    pool: DbPool,
}
impl DieselApiKeyRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselApiKeyRepo {}

impl ApiKeyRepository for DieselApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_api_keys::table
                .filter(yauth_api_keys::key_prefix.eq(&prefix))
                .select(DieselApiKey::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_api_keys::table
                .filter(
                    yauth_api_keys::id
                        .eq(id)
                        .and(yauth_api_keys::user_id.eq(user_id)),
                )
                .select(DieselApiKey::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let results: Vec<DieselApiKey> = yauth_api_keys::table
                .filter(yauth_api_keys::user_id.eq(user_id))
                .order(yauth_api_keys::created_at.desc())
                .select(DieselApiKey::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(results.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::insert_into(yauth_api_keys::table)
                .values(&DieselNewApiKey::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::delete(yauth_api_keys::table.filter(yauth_api_keys::id.eq(id)))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_api_keys::table.filter(yauth_api_keys::id.eq(id)))
                .set(yauth_api_keys::last_used_at.eq(chrono::Utc::now().naive_utc()))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }
}
