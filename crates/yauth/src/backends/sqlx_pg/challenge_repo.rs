use sqlx::PgPool;

use crate::backends::sqlx_common::sqlx_err;
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};

const CREATE_CHALLENGES_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_challenges (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

pub(crate) struct SqlxPgChallengeRepo {
    pool: PgPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxPgChallengeRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
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

impl sealed::Sealed for SqlxPgChallengeRepo {}

impl ChallengeRepository for SqlxPgChallengeRepo {
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
            sqlx::query!("DELETE FROM yauth_challenges WHERE expires_at < now()")
                .execute(&self.pool)
                .await
                .ok();

            let ttl = ttl_secs as f64;
            sqlx::query!(
                "INSERT INTO yauth_challenges (key, value, expires_at) \
                 VALUES ($1, $2, now() + make_interval(secs => $3)) \
                 ON CONFLICT (key) DO UPDATE \
                 SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at",
                key,
                value,
                ttl,
            )
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

            let row = sqlx::query!(
                "SELECT value FROM yauth_challenges WHERE key = $1 AND expires_at > now()",
                key
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.value))
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            sqlx::query!("DELETE FROM yauth_challenges WHERE key = $1", key)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
