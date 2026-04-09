use super::MysqlPool;
use crate::backends::diesel_common::{get_conn, lazy_init_table};
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};

const CREATE_CHALLENGES_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS yauth_challenges (\
    `key` VARCHAR(255) PRIMARY KEY, \
    value JSON NOT NULL, \
    expires_at DATETIME NOT NULL\
) ENGINE=InnoDB";

pub(crate) struct MysqlChallengeRepo {
    pool: MysqlPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl MysqlChallengeRepo {
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
                CREATE_CHALLENGES_TABLE,
            )
            .await
            .map_err(|e| RepoError::Internal(format!("challenge table init failed: {e}").into()))?;
            Ok(())
        })
        .await
    }
}

impl sealed::Sealed for MysqlChallengeRepo {}

impl ChallengeRepository for MysqlChallengeRepo {
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
            {
                use diesel_async_crate::RunQueryDsl;

                let value_str =
                    serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());

                // MySQL uses ON DUPLICATE KEY UPDATE instead of ON CONFLICT.
                // Bind JSON value as Text — diesel's MySQL backend serializes it correctly
                // into the JSON column via implicit cast.
                diesel::sql_query(
                    "INSERT INTO yauth_challenges (`key`, value, expires_at) \
                     VALUES (?, CAST(? AS JSON), DATE_ADD(NOW(), INTERVAL ? SECOND)) \
                     AS new_row \
                     ON DUPLICATE KEY UPDATE \
                     `value` = new_row.`value`, `expires_at` = new_row.`expires_at`",
                )
                .bind::<diesel::sql_types::Text, _>(&key)
                .bind::<diesel::sql_types::Text, _>(&value_str)
                .bind::<diesel::sql_types::BigInt, _>(ttl_secs as i64)
                .execute(&mut *conn)
                .await
                .map_err(|e| RepoError::Internal(format!("challenge set failed: {e}").into()))?;
            }

            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let mut conn = get_conn(&self.pool).await?;

            #[derive(diesel::QueryableByName)]
            struct ChallengeRow {
                #[diesel(sql_type = diesel::sql_types::Text)]
                value: String,
            }

            let result: Option<ChallengeRow> = {
                use diesel::result::OptionalExtension;
                use diesel_async_crate::RunQueryDsl;
                diesel::sql_query(
                    "SELECT CAST(value AS CHAR) AS value FROM yauth_challenges \
                     WHERE `key` = ? AND expires_at > NOW() LIMIT 1",
                )
                .bind::<diesel::sql_types::Text, _>(&key)
                .get_result(&mut *conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(format!("challenge get failed: {e}").into()))?
            };

            match result {
                Some(row) => {
                    let v = serde_json::from_str(&row.value).unwrap_or(serde_json::Value::Null);
                    Ok(Some(v))
                }
                None => {
                    // Clean up any expired entry for this key
                    use diesel_async_crate::RunQueryDsl;
                    let _ = diesel::sql_query(
                        "DELETE FROM yauth_challenges WHERE `key` = ? AND expires_at <= NOW()",
                    )
                    .bind::<diesel::sql_types::Text, _>(&key)
                    .execute(&mut *conn)
                    .await;
                    Ok(None)
                }
            }
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let mut conn = get_conn(&self.pool).await?;
            {
                use diesel_async_crate::RunQueryDsl;
                diesel::sql_query("DELETE FROM yauth_challenges WHERE `key` = ?")
                    .bind::<diesel::sql_types::Text, _>(&key)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        RepoError::Internal(format!("challenge delete failed: {e}").into())
                    })?;
            }
            Ok(())
        })
    }
}
