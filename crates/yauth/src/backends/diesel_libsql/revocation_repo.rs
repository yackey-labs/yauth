use std::sync::atomic::{AtomicBool, Ordering};

use super::LibsqlPool;
use super::models::str_to_dt;
use crate::repo::{RepoError, RepoFuture, RevocationRepository, sealed};

const CREATE_REVOCATIONS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS yauth_revocations (\
    key TEXT PRIMARY KEY, \
    expires_at TEXT NOT NULL\
)";

fn pool_err(e: impl std::fmt::Display) -> RepoError {
    RepoError::Internal(format!("pool error: {e}").into())
}

pub(crate) struct LibsqlRevocationRepo {
    pool: LibsqlPool,
    initialized: AtomicBool,
}

impl LibsqlRevocationRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self {
            pool,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        if !self.initialized.load(Ordering::Relaxed) {
            use diesel_async_crate::SimpleAsyncConnection;
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            (*conn)
                .batch_execute(CREATE_REVOCATIONS_TABLE)
                .await
                .map_err(|e| RepoError::Internal(format!("failed to create table: {e}").into()))?;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl sealed::Sealed for LibsqlRevocationRepo {}

impl RevocationRepository for LibsqlRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let mut conn = self.pool.get().await.map_err(pool_err)?;
            {
                use diesel_async_crate::RunQueryDsl;
                diesel::sql_query(
                    "INSERT INTO yauth_revocations (key, expires_at) \
                     VALUES (?, datetime('now', '+' || ? || ' seconds')) \
                     ON CONFLICT (key) DO UPDATE \
                     SET expires_at = EXCLUDED.expires_at",
                )
                .bind::<diesel::sql_types::Text, _>(&jti)
                .bind::<diesel::sql_types::BigInt, _>(ttl.as_secs() as i64)
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    RepoError::Internal(format!("revocation insert failed: {e}").into())
                })?;
            }

            Ok(())
        })
    }

    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let mut conn = self.pool.get().await.map_err(pool_err)?;

            #[derive(diesel::QueryableByName)]
            struct Found {
                #[diesel(sql_type = diesel::sql_types::Text)]
                #[allow(dead_code)]
                expires_at: String,
            }

            let result: Vec<Found> = {
                use diesel_async_crate::RunQueryDsl;
                diesel::sql_query("SELECT expires_at FROM yauth_revocations WHERE key = ?")
                    .bind::<diesel::sql_types::Text, _>(&jti)
                    .load(&mut *conn)
                    .await
                    .map_err(|e| {
                        RepoError::Internal(format!("revocation check failed: {e}").into())
                    })?
            };

            match result.into_iter().next() {
                Some(row) => {
                    let expires_at = str_to_dt(&row.expires_at);
                    let now = chrono::Utc::now().naive_utc();
                    Ok(expires_at > now)
                }
                None => Ok(false),
            }
        })
    }
}
