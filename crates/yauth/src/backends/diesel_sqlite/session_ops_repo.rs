use chrono::Utc;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::SqlitePool;
use super::models::{SqliteSession, dt_to_str, str_to_dt, str_to_uuid, uuid_to_str};
use super::schema::yauth_sessions;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{RepoFuture, SessionOpsRepository, sealed};

pub(crate) struct SqliteSessionOpsRepo {
    pool: SqlitePool,
}

impl SqliteSessionOpsRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqliteSessionOpsRepo {}

impl SessionOpsRepository for SqliteSessionOpsRepo {
    fn create_session(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: std::time::Duration,
    ) -> RepoFuture<'_, Uuid> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;

            let session_id = Uuid::now_v7();
            let now = Utc::now();
            let expires_at =
                now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7));

            diesel::sql_query(
                "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind::<diesel::sql_types::Text, _>(uuid_to_str(session_id))
            .bind::<diesel::sql_types::Text, _>(uuid_to_str(user_id))
            .bind::<diesel::sql_types::Text, _>(&token_hash)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ip_address)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&user_agent)
            .bind::<diesel::sql_types::Text, _>(dt_to_str(expires_at.naive_utc()))
            .bind::<diesel::sql_types::Text, _>(dt_to_str(now.naive_utc()))
            .execute(&mut *conn)
            .await
            .map_err(diesel_err)?;

            Ok(session_id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;

            let session: Option<SqliteSession> = yauth_sessions::table
                .filter(yauth_sessions::token_hash.eq(&token_hash))
                .select(SqliteSession::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;

            match session {
                Some(s) => {
                    let expires_at = str_to_dt(&s.expires_at);
                    let now = Utc::now().naive_utc();
                    if expires_at < now {
                        // Expired -- clean up
                        diesel::delete(yauth_sessions::table.filter(yauth_sessions::id.eq(&s.id)))
                            .execute(&mut *conn)
                            .await
                            .map_err(diesel_err)?;
                        return Ok(None);
                    }

                    Ok(Some(domain::StoredSession {
                        id: str_to_uuid(&s.id),
                        user_id: str_to_uuid(&s.user_id),
                        ip_address: s.ip_address,
                        user_agent: s.user_agent,
                        expires_at,
                        created_at: str_to_dt(&s.created_at),
                    }))
                }
                None => Ok(None),
            }
        })
    }

    fn delete_session(&self, token_hash: &str) -> RepoFuture<'_, bool> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;

            let rows = diesel::delete(
                yauth_sessions::table.filter(yauth_sessions::token_hash.eq(&token_hash)),
            )
            .execute(&mut *conn)
            .await
            .map_err(diesel_err)?;

            Ok(rows > 0)
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let user_id_str = uuid_to_str(user_id);

            let rows = diesel::delete(
                yauth_sessions::table.filter(yauth_sessions::user_id.eq(&user_id_str)),
            )
            .execute(&mut *conn)
            .await
            .map_err(diesel_err)?;

            Ok(rows as u64)
        })
    }

    fn delete_other_sessions_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> RepoFuture<'_, u64> {
        let keep_hash = keep_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let user_id_str = uuid_to_str(user_id);

            let rows = diesel::delete(
                yauth_sessions::table
                    .filter(yauth_sessions::user_id.eq(&user_id_str))
                    .filter(yauth_sessions::token_hash.ne(&keep_hash)),
            )
            .execute(&mut *conn)
            .await
            .map_err(diesel_err)?;

            Ok(rows as u64)
        })
    }
}
