use sqlx::MySqlPool;

use crate::backends::sqlx_common::sqlx_err;
use crate::repo::{RepoError, RepoFuture, RevocationRepository, sealed};

const CREATE_REVOCATIONS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS yauth_revocations (
    `key`       VARCHAR(255) PRIMARY KEY,
    expires_at  DATETIME NOT NULL
) ENGINE=InnoDB
"#;

pub(crate) struct SqlxMysqlRevocationRepo {
    pool: MySqlPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxMysqlRevocationRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
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

impl sealed::Sealed for SqlxMysqlRevocationRepo {}

impl RevocationRepository for SqlxMysqlRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            // Dynamic INTERVAL — keep as runtime query
            sqlx::query(
                "INSERT INTO yauth_revocations (`key`, expires_at) \
                 VALUES (?, DATE_ADD(NOW(), INTERVAL ? SECOND)) \
                 ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at)",
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

            // Runtime query — table created dynamically
            let row: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 as found FROM yauth_revocations WHERE `key` = ? AND expires_at > NOW()",
            )
            .bind(&jti)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.is_some())
        })
    }
}
