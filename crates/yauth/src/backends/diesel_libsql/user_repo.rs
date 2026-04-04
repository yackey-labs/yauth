use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::LibsqlPool;
use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{RepoError, RepoFuture, SessionRepository, UserRepository, sealed};

fn pool_err(e: impl std::fmt::Display) -> RepoError {
    RepoError::Internal(format!("pool error: {e}").into())
}

fn diesel_err(e: diesel::result::Error) -> RepoError {
    RepoError::Internal(e.into())
}

pub(crate) struct LibsqlUserRepo {
    pool: LibsqlPool,
}

impl LibsqlUserRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for LibsqlUserRepo {}

impl UserRepository for LibsqlUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let id_str = uuid_to_str(id);
            let result = yauth_users::table
                .find(&id_str)
                .select(LibsqlUser::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>> {
        let email = email.to_lowercase();
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let result = yauth_users::table
                .filter(yauth_users::email.eq(&email))
                .select(LibsqlUser::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let u = LibsqlNewUser::from_domain(input);
            // Use sql_query because diesel-libsql doesn't support Insertable derive
            let result = diesel::sql_query(
                "INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 RETURNING id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at"
            )
            .bind::<diesel::sql_types::Text, _>(&u.id)
            .bind::<diesel::sql_types::Text, _>(&u.email)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&u.display_name)
            .bind::<diesel::sql_types::Bool, _>(u.email_verified)
            .bind::<diesel::sql_types::Text, _>(&u.role)
            .bind::<diesel::sql_types::Bool, _>(u.banned)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&u.banned_reason)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&u.banned_until)
            .bind::<diesel::sql_types::Text, _>(&u.created_at)
            .bind::<diesel::sql_types::Text, _>(&u.updated_at)
            .get_result::<LibsqlUserByName>(&mut *conn)
            .await;

            match result {
                Ok(user) => Ok(user.into_domain()),
                Err(diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    info,
                )) => Err(RepoError::Conflict(info.message().to_string())),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("UNIQUE constraint failed") {
                        Err(RepoError::Conflict(msg))
                    } else {
                        Err(RepoError::Internal(e.into()))
                    }
                }
            }
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let id_str = uuid_to_str(id);
            let libsql_changes = LibsqlUpdateUser::from_domain(changes);
            // Use Diesel's AsChangeset (which doesn't have the Insertable issue)
            let result = diesel::update(yauth_users::table.find(&id_str))
                .set(&libsql_changes)
                .returning(LibsqlUser::as_returning())
                .get_result(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(result.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let id_str = uuid_to_str(id);
            diesel::delete(yauth_users::table.find(&id_str))
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn any_exists(&self) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let exists: Option<String> = yauth_users::table
                .select(yauth_users::id)
                .first::<String>(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(exists.is_some())
        })
    }

    fn list(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::User>, i64)> {
        let search = search.map(|s| s.to_string());
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let total: i64 = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                yauth_users::table
                    .filter(yauth_users::email.like(&pattern))
                    .count()
                    .get_result(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_users::table
                    .count()
                    .get_result(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            };

            let users: Vec<LibsqlUser> = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                yauth_users::table
                    .filter(yauth_users::email.like(&pattern))
                    .order(yauth_users::created_at.desc())
                    .limit(limit)
                    .offset(offset)
                    .select(LibsqlUser::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_users::table
                    .order(yauth_users::created_at.desc())
                    .limit(limit)
                    .offset(offset)
                    .select(LibsqlUser::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            };

            Ok((users.into_iter().map(|u| u.into_domain()).collect(), total))
        })
    }
}

// ──────────────────────────────────────────────
// Session Repository
// ──────────────────────────────────────────────

pub(crate) struct LibsqlSessionRepo {
    pool: LibsqlPool,
}

impl LibsqlSessionRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for LibsqlSessionRepo {}

impl SessionRepository for LibsqlSessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let id_str = uuid_to_str(id);
            let result = yauth_sessions::table
                .find(&id_str)
                .select(LibsqlSession::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|s| s.into_domain()))
        })
    }

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let s = LibsqlNewSession::from_domain(input);
            diesel::sql_query(
                "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind::<diesel::sql_types::Text, _>(&s.id)
            .bind::<diesel::sql_types::Text, _>(&s.user_id)
            .bind::<diesel::sql_types::Text, _>(&s.token_hash)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&s.ip_address)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&s.user_agent)
            .bind::<diesel::sql_types::Text, _>(&s.expires_at)
            .bind::<diesel::sql_types::Text, _>(&s.created_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let id_str = uuid_to_str(id);
            diesel::delete(yauth_sessions::table.find(&id_str))
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn list(&self, limit: i64, offset: i64) -> RepoFuture<'_, (Vec<domain::Session>, i64)> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let total: i64 = yauth_sessions::table
                .count()
                .get_result(&mut *conn)
                .await
                .map_err(diesel_err)?;
            let sessions: Vec<LibsqlSession> = yauth_sessions::table
                .order(yauth_sessions::created_at.desc())
                .limit(limit)
                .offset(offset)
                .select(LibsqlSession::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok((
                sessions.into_iter().map(|s| s.into_domain()).collect(),
                total,
            ))
        })
    }
}
