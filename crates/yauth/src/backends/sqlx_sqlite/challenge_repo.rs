use sqlx::SqlitePool;

use crate::backends::sqlx_common::sqlx_err;
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};

const CREATE_CHALLENGES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS yauth_challenges (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    expires_at  TEXT NOT NULL
)
"#;

pub(crate) struct SqlxSqliteChallengeRepo {
    pool: SqlitePool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxSqliteChallengeRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
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

impl sealed::Sealed for SqlxSqliteChallengeRepo {}

impl ChallengeRepository for SqlxSqliteChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            // Cleanup expired
            sqlx::query("DELETE FROM yauth_challenges WHERE expires_at < datetime('now')")
                .execute(&self.pool)
                .await
                .ok();

            sqlx::query(
                "INSERT INTO yauth_challenges (key, value, expires_at) \
                 VALUES (?, ?, datetime('now', '+' || ? || ' seconds')) \
                 ON CONFLICT (key) DO UPDATE \
                 SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at",
            )
            .bind(&key)
            .bind(&value)
            .bind(ttl_secs as f64)
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
                "SELECT value FROM yauth_challenges WHERE key = ? AND expires_at > datetime('now')",
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

            sqlx::query("DELETE FROM yauth_challenges WHERE key = ?")
                .bind(&key)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
