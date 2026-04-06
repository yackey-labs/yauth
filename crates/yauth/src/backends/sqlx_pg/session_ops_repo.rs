use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{RepoFuture, SessionOpsRepository, sealed};

#[derive(sqlx::FromRow)]
struct StoredSessionRow {
    id: Uuid,
    user_id: Uuid,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

pub(crate) struct SqlxPgSessionOpsRepo {
    pool: PgPool,
}

impl SqlxPgSessionOpsRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxPgSessionOpsRepo {}

impl SessionOpsRepository for SqlxPgSessionOpsRepo {
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
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(session_id)
            .bind(user_id)
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
                 FROM yauth_sessions WHERE token_hash = $1",
            )
            .bind(&token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;

            match row {
                Some(s) => {
                    let now = Utc::now().naive_utc();
                    if s.expires_at.naive_utc() < now {
                        // Expired — clean up
                        sqlx::query("DELETE FROM yauth_sessions WHERE id = $1")
                            .bind(s.id)
                            .execute(&self.pool)
                            .await
                            .map_err(sqlx_err)?;
                        Ok(None)
                    } else {
                        Ok(Some(domain::StoredSession {
                            id: s.id,
                            user_id: s.user_id,
                            ip_address: s.ip_address,
                            user_agent: s.user_agent,
                            expires_at: s.expires_at.naive_utc(),
                            created_at: s.created_at.naive_utc(),
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
            let result = sqlx::query("DELETE FROM yauth_sessions WHERE token_hash = $1")
                .bind(&token_hash)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(result.rows_affected() > 0)
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let result = sqlx::query("DELETE FROM yauth_sessions WHERE user_id = $1")
                .bind(user_id)
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
                sqlx::query("DELETE FROM yauth_sessions WHERE user_id = $1 AND token_hash != $2")
                    .bind(user_id)
                    .bind(&keep_hash)
                    .execute(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
            Ok(result.rows_affected())
        })
    }
}
