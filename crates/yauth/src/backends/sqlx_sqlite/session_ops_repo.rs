use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{dt_to_str, sqlx_err, str_to_dt, str_to_uuid};
use crate::domain;
use crate::repo::{RepoFuture, SessionOpsRepository, sealed};

#[derive(sqlx::FromRow)]
struct StoredSessionRow {
    id: Option<String>,
    user_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_at: String,
    created_at: String,
}

pub(crate) struct SqlxSqliteSessionOpsRepo {
    pool: SqlitePool,
}

impl SqlxSqliteSessionOpsRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxSqliteSessionOpsRepo {}

impl SessionOpsRepository for SqlxSqliteSessionOpsRepo {
    fn create_session(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: std::time::Duration,
    ) -> RepoFuture<'_, Uuid> {
        Box::pin(async move {
            let session_id = Uuid::now_v7();
            let now = Utc::now();
            let expires_at =
                now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7));

            let session_id_str = session_id.to_string();
            let user_id_str = user_id.to_string();
            let expires_str = dt_to_str(expires_at.naive_utc());
            let now_str = dt_to_str(now.naive_utc());
            sqlx::query!(
                "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                session_id_str,
                user_id_str,
                token_hash,
                ip_address,
                user_agent,
                expires_str,
                now_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;

            Ok(session_id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                StoredSessionRow,
                "SELECT id, user_id, ip_address, user_agent, expires_at, created_at \
                 FROM yauth_sessions WHERE token_hash = ? /* sqlite */",
                token_hash
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;

            match row {
                Some(s) => {
                    let now = Utc::now().naive_utc();
                    let expires = str_to_dt(&s.expires_at);
                    if expires < now {
                        let id_str = s.id.clone().unwrap_or_default();
                        sqlx::query!(
                            "DELETE FROM yauth_sessions WHERE id = ? /* sqlite */",
                            id_str
                        )
                        .execute(&self.pool)
                        .await
                        .map_err(sqlx_err)?;
                        Ok(None)
                    } else {
                        Ok(Some(domain::StoredSession {
                            id: str_to_uuid(&s.id.unwrap_or_default()),
                            user_id: str_to_uuid(&s.user_id),
                            ip_address: s.ip_address,
                            user_agent: s.user_agent,
                            expires_at: expires,
                            created_at: str_to_dt(&s.created_at),
                        }))
                    }
                }
                None => Ok(None),
            }
        })
    }

    fn delete_session(&self, token_hash: &str) -> RepoFuture<'_, bool> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let result = sqlx::query!(
                "DELETE FROM yauth_sessions WHERE token_hash = ? /* sqlite */",
                token_hash
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(result.rows_affected() > 0)
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let result = sqlx::query!(
                "DELETE FROM yauth_sessions WHERE user_id = ? /* sqlite */",
                user_id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(result.rows_affected())
        })
    }

    fn delete_other_sessions_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> RepoFuture<'_, u64> {
        let keep_hash = keep_hash.to_string();
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let result = sqlx::query!(
                "DELETE FROM yauth_sessions WHERE user_id = ? AND token_hash != ? /* sqlite */",
                user_id_str,
                keep_hash
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(result.rows_affected())
        })
    }
}
