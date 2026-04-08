use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};

use super::sea_err;
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};

const CREATE_CHALLENGES_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_challenges (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

pub(crate) struct SeaOrmChallengeRepo {
    db: DatabaseConnection,
    initialized: tokio::sync::OnceCell<()>,
}

impl SeaOrmChallengeRepo {
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
                    .execute_unprepared(CREATE_CHALLENGES_TABLE)
                    .await
                    .map_err(sea_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl sealed::Sealed for SeaOrmChallengeRepo {}

impl ChallengeRepository for SeaOrmChallengeRepo {
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
            self.db
                .execute_unprepared("DELETE FROM yauth_challenges WHERE expires_at < now()")
                .await
                .ok();

            let value_str = serde_json::to_string(&value)
                .map_err(|e| RepoError::Internal(e.to_string().into()))?;

            let stmt = Statement::from_sql_and_values(
                self.db.get_database_backend(),
                r#"INSERT INTO yauth_challenges (key, value, expires_at)
                   VALUES ($1, $2::jsonb, now() + make_interval(secs => $3))
                   ON CONFLICT (key) DO UPDATE
                   SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at"#,
                [key.into(), value_str.into(), (ttl_secs as f64).into()],
            );
            self.db.execute_raw(stmt).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let stmt = Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "SELECT value FROM yauth_challenges WHERE key = $1 AND expires_at > now()",
                [key.into()],
            );
            let row = self.db.query_one_raw(stmt).await.map_err(sea_err)?;
            match row {
                Some(r) => {
                    let val: serde_json::Value = r.try_get("", "value").map_err(sea_err)?;
                    Ok(Some(val))
                }
                None => Ok(None),
            }
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let stmt = Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "DELETE FROM yauth_challenges WHERE key = $1",
                [key.into()],
            );
            self.db.execute_raw(stmt).await.map_err(sea_err)?;
            Ok(())
        })
    }
}
