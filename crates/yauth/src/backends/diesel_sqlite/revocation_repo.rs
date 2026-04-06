use super::SqlitePool;
use super::models::str_to_dt;
use crate::backends::diesel_common::{get_conn, lazy_init_table};
use crate::repo::{RepoError, RepoFuture, RevocationRepository, sealed};

const CREATE_REVOCATIONS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS yauth_revocations (\
    key TEXT PRIMARY KEY, \
    expires_at TEXT NOT NULL\
)";

pub(crate) struct SqliteRevocationRepo {
    pool: SqlitePool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqliteRevocationRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        let pool = &self.pool;
        lazy_init_table(&self.initialized, || async {
            use diesel_async_crate::SimpleAsyncConnection;
            let mut conn = get_conn(pool).await?;
            (*conn)
                .batch_execute(CREATE_REVOCATIONS_TABLE)
                .await
                .map_err(|e| {
                    RepoError::Internal(format!("revocation table init failed: {e}").into())
                })?;
            Ok(())
        })
        .await
    }
}

impl sealed::Sealed for SqliteRevocationRepo {}

impl RevocationRepository for SqliteRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let mut conn = get_conn(&self.pool).await?;
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

            let mut conn = get_conn(&self.pool).await?;

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
