use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};

use super::sea_err;
use crate::repo::{RepoError, RepoFuture, RevocationRepository, sealed};

const CREATE_REVOCATIONS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_revocations (
    key         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

pub(crate) struct SeaOrmRevocationRepo {
    db: DatabaseConnection,
    initialized: tokio::sync::OnceCell<()>,
}

impl SeaOrmRevocationRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                self.db
                    .execute_unprepared(CREATE_REVOCATIONS_TABLE)
                    .await
                    .map_err(sea_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl sealed::Sealed for SeaOrmRevocationRepo {}

impl RevocationRepository for SeaOrmRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let stmt = Statement::from_sql_and_values(
                self.db.get_database_backend(),
                r#"INSERT INTO yauth_revocations (key, expires_at)
                   VALUES ($1, now() + make_interval(secs => $2))
                   ON CONFLICT (key) DO UPDATE
                   SET expires_at = EXCLUDED.expires_at"#,
                [jti.into(), ttl.as_secs_f64().into()],
            );
            self.db.execute_raw(stmt).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let stmt = Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "SELECT 1 AS found FROM yauth_revocations WHERE key = $1 AND expires_at > now()",
                [jti.into()],
            );
            let result = self.db.query_one_raw(stmt).await.map_err(sea_err)?;
            Ok(result.is_some())
        })
    }
}
