use sqlx::PgPool;

use crate::backends::sqlx_common::sqlx_err;
use crate::repo::{RepoError, RepoFuture, RevocationRepository, sealed};

const CREATE_REVOCATIONS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_revocations (
    key         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

pub(crate) struct SqlxPgRevocationRepo {
    pool: PgPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxPgRevocationRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
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

impl sealed::Sealed for SqlxPgRevocationRepo {}

impl RevocationRepository for SqlxPgRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let secs = ttl.as_secs_f64();
            sqlx::query!(
                "INSERT INTO yauth_revocations (key, expires_at) \
                 VALUES ($1, now() + make_interval(secs => $2)) \
                 ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at",
                jti,
                secs,
            )
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

            let row = sqlx::query!(
                "SELECT 1 as found FROM yauth_revocations WHERE key = $1 AND expires_at > now()",
                jti
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.is_some())
        })
    }
}
