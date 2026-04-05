use super::MysqlPool;
use crate::backends::diesel_common::{get_conn, lazy_init_table};
use crate::repo::{RepoError, RepoFuture, RevocationRepository, sealed};

const CREATE_REVOCATIONS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS yauth_revocations (\
    `key` VARCHAR(255) PRIMARY KEY, \
    expires_at DATETIME NOT NULL\
) ENGINE=InnoDB";

pub(crate) struct MysqlRevocationRepo {
    pool: MysqlPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl MysqlRevocationRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        let pool = &self.pool;
        lazy_init_table(&self.initialized, || async {
            use diesel_async_crate::AsyncMysqlConnection;
            use diesel_async_crate::SimpleAsyncConnection;
            let mut conn = get_conn(pool).await?;
            <AsyncMysqlConnection as SimpleAsyncConnection>::batch_execute(
                &mut *conn,
                CREATE_REVOCATIONS_TABLE,
            )
            .await
            .map_err(|e| {
                RepoError::Internal(format!("revocation table init failed: {e}").into())
            })?;
            Ok(())
        })
        .await
    }
}

impl sealed::Sealed for MysqlRevocationRepo {}

impl RevocationRepository for MysqlRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let mut conn = get_conn(&self.pool).await?;
            {
                use diesel_async_crate::RunQueryDsl;
                diesel::sql_query(
                    "INSERT INTO yauth_revocations (`key`, expires_at) \
                     VALUES (?, DATE_ADD(NOW(), INTERVAL ? SECOND)) \
                     AS new_row \
                     ON DUPLICATE KEY UPDATE \
                     `expires_at` = new_row.`expires_at`",
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
                #[diesel(sql_type = diesel::sql_types::Datetime)]
                #[allow(dead_code)]
                expires_at: chrono::NaiveDateTime,
            }

            let result: Option<Found> = {
                use diesel::result::OptionalExtension;
                use diesel_async_crate::RunQueryDsl;
                diesel::sql_query(
                    "SELECT expires_at FROM yauth_revocations \
                     WHERE `key` = ? AND expires_at > NOW() LIMIT 1",
                )
                .bind::<diesel::sql_types::Text, _>(&jti)
                .get_result(&mut *conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(format!("revocation check failed: {e}").into()))?
            };

            Ok(result.is_some())
        })
    }
}
