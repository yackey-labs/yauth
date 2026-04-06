use sqlx::SqlitePool;

use crate::backends::sqlx_common::sqlx_err;
use crate::repo::{RepoError, RepoFuture, RevocationRepository, sealed};

const CREATE_REVOCATIONS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS yauth_revocations (
    key         TEXT PRIMARY KEY,
    expires_at  TEXT NOT NULL
)
"#;

pub(crate) struct SqlxSqliteRevocationRepo {
    pool: SqlitePool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxSqliteRevocationRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                sqlx::raw_sql(CREATE_REVOCATIONS_TABLE)
                    .execute(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl sealed::Sealed for SqlxSqliteRevocationRepo {}

impl RevocationRepository for SqlxSqliteRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            sqlx::query(
                "INSERT INTO yauth_revocations (key, expires_at) \
                 VALUES (?, datetime('now', '+' || ? || ' seconds')) \
                 ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at",
            )
            .bind(&jti)
            .bind(ttl.as_secs_f64())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let row: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 as found FROM yauth_revocations WHERE key = ? AND expires_at > datetime('now')",
            )
            .bind(&jti)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.is_some())
        })
    }
}
