use super::models::DieselChallenge;
use super::schema::yauth_challenges;
use crate::backends::diesel_common::{diesel_err, get_conn};
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
    initialized: tokio::sync::OnceCell<()>,
}

impl DieselChallengeRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                use diesel_async_crate::RunQueryDsl;
                let mut conn = get_conn(&self.pool).await?;
                diesel::sql_query(CREATE_CHALLENGES_TABLE)
                    .execute(&mut conn)
                    .await
                    .map_err(diesel_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
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

            let mut conn = get_conn(&self.pool).await?;

            // Cleanup expired in same connection
            {
                use diesel::prelude::*;
                use diesel_async_crate::RunQueryDsl;
                diesel::delete(
                    yauth_challenges::table
                        .filter(yauth_challenges::expires_at.lt(diesel::dsl::now)),
                )
                .execute(&mut conn)
                .await
                .ok();
            }

            let sql = r#"
                INSERT INTO yauth_challenges (key, value, expires_at)
                VALUES ($1, $2, now() + make_interval(secs => $3))
                ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value,
                        expires_at = EXCLUDED.expires_at
            "#;

            use diesel_async_crate::RunQueryDsl;
            diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(&key)
                .bind::<diesel::sql_types::Jsonb, _>(value)
                .bind::<diesel::sql_types::Float8, _>(ttl_secs as f64)
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
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
            let mut conn = get_conn(&self.pool).await?;

            let result: Option<DieselChallenge> = yauth_challenges::table
                .filter(yauth_challenges::key.eq(&key))
                .filter(yauth_challenges::expires_at.gt(diesel::dsl::now))
                .select(DieselChallenge::as_select())
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.value))
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            use diesel::prelude::*;
            use diesel_async_crate::RunQueryDsl;
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(yauth_challenges::table.filter(yauth_challenges::key.eq(&key)))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}
