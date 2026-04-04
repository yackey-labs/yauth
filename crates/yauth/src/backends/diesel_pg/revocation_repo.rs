use std::sync::atomic::{AtomicBool, Ordering};

use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::repo::{RepoError, RepoFuture, RevocationRepository, sealed};
use crate::state::DbPool;

const CREATE_REVOCATIONS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_revocations (
    key         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

pub(crate) struct DieselRevocationRepo {
    pool: DbPool,
    initialized: AtomicBool,
}

impl DieselRevocationRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self {
            pool,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        if !self.initialized.load(Ordering::Relaxed) {
            use diesel_async_crate::RunQueryDsl;
            let mut conn = get_conn(&self.pool).await?;
            let _ = diesel::sql_query(CREATE_REVOCATIONS_TABLE)
                .execute(&mut conn)
                .await;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl sealed::Sealed for DieselRevocationRepo {}

impl RevocationRepository for DieselRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let sql = r#"
                INSERT INTO yauth_revocations (key, expires_at)
                VALUES ($1, now() + make_interval(secs => $2))
                ON CONFLICT (key) DO UPDATE
                    SET expires_at = EXCLUDED.expires_at
            "#;

            use diesel_async_crate::RunQueryDsl;
            let mut conn = get_conn(&self.pool).await?;

            diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(&jti)
                .bind::<diesel::sql_types::Float8, _>(ttl.as_secs_f64())
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;

            Ok(())
        })
    }

    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let sql = r#"
                SELECT 1 AS found
                FROM yauth_revocations
                WHERE key = $1 AND expires_at > now()
            "#;

            use diesel::result::OptionalExtension;
            use diesel_async_crate::RunQueryDsl;

            #[derive(diesel::QueryableByName)]
            struct Found {
                #[diesel(sql_type = diesel::sql_types::Int4)]
                #[allow(dead_code)]
                found: i32,
            }

            let mut conn = get_conn(&self.pool).await?;

            let result: Option<Found> = diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(&jti)
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;

            Ok(result.is_some())
        })
    }
}
