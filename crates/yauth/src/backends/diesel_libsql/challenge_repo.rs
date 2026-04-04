use super::LibsqlPool;
use super::models::str_to_json;
use crate::backends::diesel_common::get_conn;
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};

const CREATE_CHALLENGES_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS yauth_challenges (\
    key TEXT PRIMARY KEY, \
    value TEXT NOT NULL, \
    expires_at TEXT NOT NULL\
)";

pub(crate) struct LibsqlChallengeRepo {
    pool: LibsqlPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl LibsqlChallengeRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) {
        self.initialized
            .get_or_init(|| async {
                use diesel_async_crate::SimpleAsyncConnection;
                if let Ok(mut conn) = get_conn(&self.pool).await {
                    let _ = (*conn).batch_execute(CREATE_CHALLENGES_TABLE).await;
                }
            })
            .await;
    }
}

impl sealed::Sealed for LibsqlChallengeRepo {}

impl ChallengeRepository for LibsqlChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await;

            // Cleanup expired entries
            let mut conn = get_conn(&self.pool).await?;
            {
                use diesel_async_crate::RunQueryDsl;
                let _ = diesel::sql_query(
                    "DELETE FROM yauth_challenges WHERE expires_at < datetime('now')",
                )
                .execute(&mut *conn)
                .await;

                let value_str =
                    serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());

                diesel::sql_query(
                    "INSERT INTO yauth_challenges (key, value, expires_at) \
                     VALUES (?, ?, datetime('now', '+' || ? || ' seconds')) \
                     ON CONFLICT (key) DO UPDATE \
                     SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at",
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
            self.ensure_init().await;

            let mut conn = get_conn(&self.pool).await?;

            #[derive(diesel::QueryableByName)]
            struct ChallengeRow {
                #[diesel(sql_type = diesel::sql_types::Text)]
                value: String,
            }

            let result: Vec<ChallengeRow> = {
                use diesel_async_crate::RunQueryDsl;
                diesel::sql_query(
                    "SELECT value FROM yauth_challenges \
                     WHERE key = ? AND expires_at > datetime('now')",
                )
                .bind::<diesel::sql_types::Text, _>(&key)
                .load(&mut *conn)
                .await
                .map_err(|e| RepoError::Internal(format!("challenge get failed: {e}").into()))?
            };

            match result.into_iter().next() {
                Some(row) => Ok(Some(str_to_json(&row.value))),
                None => {
                    // Clean up any expired entry for this key
                    use diesel_async_crate::RunQueryDsl;
                    let _ = diesel::sql_query(
                        "DELETE FROM yauth_challenges WHERE key = ? AND expires_at <= datetime('now')",
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
            self.ensure_init().await;

            let mut conn = get_conn(&self.pool).await?;
            {
                use diesel_async_crate::RunQueryDsl;
                diesel::sql_query("DELETE FROM yauth_challenges WHERE key = ?")
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
