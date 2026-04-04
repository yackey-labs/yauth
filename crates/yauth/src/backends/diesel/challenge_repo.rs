use std::sync::atomic::{AtomicBool, Ordering};

use super::models::DieselChallenge;
use super::schema::yauth_challenges;
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

const CREATE_CHALLENGES_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_challenges (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

pub(crate) struct DieselChallengeRepo {
    pool: DbPool,
    initialized: AtomicBool,
}

impl DieselChallengeRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self {
            pool,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        if !self.initialized.load(Ordering::Relaxed) {
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(format!("pool error: {e}").into()))?;
            diesel::sql_query(CREATE_CHALLENGES_TABLE)
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(format!("failed to create table: {e}").into()))?;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), RepoError> {
        use diesel::prelude::*;
        use diesel_async_crate::RunQueryDsl;
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| RepoError::Internal(format!("pool error: {e}").into()))?;
        diesel::delete(
            yauth_challenges::table.filter(yauth_challenges::expires_at.lt(diesel::dsl::now)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| RepoError::Internal(format!("cleanup failed: {e}").into()))?;
        Ok(())
    }
}

impl sealed::Sealed for DieselChallengeRepo {}

impl ChallengeRepository for DieselChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;
            let _ = self.cleanup_expired().await;

            let sql = r#"
                INSERT INTO yauth_challenges (key, value, expires_at)
                VALUES ($1, $2, now() + make_interval(secs => $3))
                ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value,
                        expires_at = EXCLUDED.expires_at
            "#;

            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(format!("pool error: {e}").into()))?;
            diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(&key)
                .bind::<diesel::sql_types::Jsonb, _>(value)
                .bind::<diesel::sql_types::Float8, _>(ttl_secs as f64)
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(format!("challenge set failed: {e}").into()))?;
            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            use diesel::prelude::*;
            use diesel::result::OptionalExtension;
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(format!("pool error: {e}").into()))?;

            let result: Option<DieselChallenge> = yauth_challenges::table
                .filter(yauth_challenges::key.eq(&key))
                .filter(yauth_challenges::expires_at.gt(diesel::dsl::now))
                .select(DieselChallenge::as_select())
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(format!("challenge get failed: {e}").into()))?;
            Ok(result.map(|r| r.value))
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            use diesel::prelude::*;
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(format!("pool error: {e}").into()))?;
            diesel::delete(yauth_challenges::table.filter(yauth_challenges::key.eq(&key)))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(format!("challenge delete failed: {e}").into()))?;
            Ok(())
        })
    }
}
