use chrono::{NaiveDateTime, Utc};
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{RepoFuture, SessionOpsRepository, sealed};

#[derive(sqlx::FromRow)]
struct StoredSessionRow {
    id: String,
    user_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_at: NaiveDateTime,
    created_at: NaiveDateTime,
}

pub(crate) struct SqlxMysqlSessionOpsRepo {
    pool: MySqlPool,
}

impl SqlxMysqlSessionOpsRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxMysqlSessionOpsRepo {}

impl SessionOpsRepository for SqlxMysqlSessionOpsRepo {
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

            sqlx::query(
                "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(session_id.to_string())
            .bind(user_id.to_string())
            .bind(&token_hash)
            .bind(&ip_address)
            .bind(&user_agent)
            .bind(expires_at.naive_utc())
            .bind(now.naive_utc())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;

            Ok(session_id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, StoredSessionRow>(
                "SELECT id, user_id, ip_address, user_agent, expires_at, created_at \
                 FROM yauth_sessions WHERE token_hash = ?",
            )
            .bind(&token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;

            match row {
                Some(s) => {
                    let now = Utc::now().naive_utc();
                    if s.expires_at < now {
                        // Expired — clean up
                        sqlx::query("DELETE FROM yauth_sessions WHERE id = ?")
                            .bind(s.id)
                            .execute(&self.pool)
                            .await
                            .map_err(sqlx_err)?;
                        Ok(None)
                    } else {
                        Ok(Some(domain::StoredSession {
                            id: uuid::Uuid::parse_str(&s.id).unwrap_or_default(),
                            user_id: uuid::Uuid::parse_str(&s.user_id).unwrap_or_default(),
                            ip_address: s.ip_address,
                            user_agent: s.user_agent,
                            expires_at: s.expires_at,
                            created_at: s.created_at,
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
            let result = sqlx::query("DELETE FROM yauth_sessions WHERE token_hash = ?")
                .bind(&token_hash)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(result.rows_affected() > 0)
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let result = sqlx::query("DELETE FROM yauth_sessions WHERE user_id = ?")
                .bind(user_id.to_string())
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
            let result =
                sqlx::query("DELETE FROM yauth_sessions WHERE user_id = ? AND token_hash != ?")
                    .bind(user_id.to_string())
                    .bind(&keep_hash)
                    .execute(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
            Ok(result.rows_affected())
        })
    }
}
