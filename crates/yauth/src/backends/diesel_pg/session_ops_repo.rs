use chrono::Utc;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::{DieselNewSession, DieselSession};
use super::schema::yauth_sessions;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{RepoFuture, SessionOpsRepository, sealed};
use crate::state::DbPool;

pub(crate) struct DieselSessionOpsRepo {
    pool: DbPool,
}

impl DieselSessionOpsRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselSessionOpsRepo {}

impl SessionOpsRepository for DieselSessionOpsRepo {
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

            let new_session = DieselNewSession {
                id: session_id,
                user_id,
                token_hash,
                ip_address,
                user_agent,
                expires_at: expires_at.naive_utc(),
                created_at: now.naive_utc(),
            };

            let mut conn = get_conn(&self.pool).await?;

            diesel::insert_into(yauth_sessions::table)
                .values(&new_session)
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;

            Ok(session_id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;

            let session: Option<DieselSession> = yauth_sessions::table
                .filter(yauth_sessions::token_hash.eq(&token_hash))
                .select(DieselSession::as_select())
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;

            match session {
                Some(s) => {
                    let now = Utc::now().naive_utc();
                    if s.expires_at < now {
                        // Expired -- clean up the row
                        diesel::delete(yauth_sessions::table.filter(yauth_sessions::id.eq(s.id)))
                            .execute(&mut conn)
                            .await
                            .map_err(diesel_err)?;
                        return Ok(None);
                    }

                    Ok(Some(domain::StoredSession {
                        id: s.id,
                        user_id: s.user_id,
                        ip_address: s.ip_address,
                        user_agent: s.user_agent,
                        expires_at: s.expires_at,
                        created_at: s.created_at,
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
            .execute(&mut conn)
            .await
            .map_err(diesel_err)?;

            Ok(rows > 0)
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;

            let rows =
                diesel::delete(yauth_sessions::table.filter(yauth_sessions::user_id.eq(user_id)))
                    .execute(&mut conn)
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

            let rows = diesel::delete(
                yauth_sessions::table
                    .filter(yauth_sessions::user_id.eq(user_id))
                    .filter(yauth_sessions::token_hash.ne(&keep_hash)),
            )
            .execute(&mut conn)
            .await
            .map_err(diesel_err)?;

            Ok(rows as u64)
        })
    }
}
