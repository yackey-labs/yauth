use sqlx::MySqlPool;

use crate::backends::sqlx_common::sqlx_err;
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};

const CREATE_CHALLENGES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS yauth_challenges (
    `key`       VARCHAR(255) PRIMARY KEY,
    value       JSON NOT NULL,
    expires_at  DATETIME NOT NULL
) ENGINE=InnoDB
"#;

pub(crate) struct SqlxMysqlChallengeRepo {
    pool: MySqlPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxMysqlChallengeRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                sqlx::raw_sql(CREATE_CHALLENGES_TABLE)
                    .execute(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl sealed::Sealed for SqlxMysqlChallengeRepo {}

impl ChallengeRepository for SqlxMysqlChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            sqlx::query("DELETE FROM yauth_challenges WHERE expires_at < NOW()")
                .execute(&self.pool)
                .await
                .ok();

            sqlx::query(
                "INSERT INTO yauth_challenges (`key`, value, expires_at) \
                 VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND)) \
                 ON DUPLICATE KEY UPDATE value = VALUES(value), expires_at = VALUES(expires_at)",
            )
            .bind(&key)
            .bind(&value)
            .bind(ttl_secs as i64)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let row: Option<(serde_json::Value,)> = sqlx::query_as(
                "SELECT value FROM yauth_challenges WHERE `key` = ? AND expires_at > NOW()",
            )
            .bind(&key)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.0))
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            sqlx::query("DELETE FROM yauth_challenges WHERE `key` = ?")
                .bind(&key)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
