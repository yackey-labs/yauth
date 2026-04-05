use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::MysqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_conflict_mysql, diesel_err, get_conn};
use crate::domain;
use crate::repo::{RepoFuture, SessionRepository, UserRepository, sealed};

pub(crate) struct MysqlUserRepo {
    pool: MysqlPool,
}

impl MysqlUserRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for MysqlUserRepo {}

impl UserRepository for MysqlUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let result = yauth_users::table
                .find(&id_str)
                .select(MysqlUser::as_select())
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
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_users::table
                .filter(yauth_users::email.eq(&email))
                .select(MysqlUser::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let u = MysqlNewUser::from_domain(input);
            let id = u.id.clone();

            // MySQL does not support RETURNING — INSERT then SELECT
            diesel::sql_query(
                "INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind::<diesel::sql_types::Text, _>(&u.id)
            .bind::<diesel::sql_types::Text, _>(&u.email)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&u.display_name)
            .bind::<diesel::sql_types::Bool, _>(u.email_verified)
            .bind::<diesel::sql_types::Text, _>(&u.role)
            .bind::<diesel::sql_types::Bool, _>(u.banned)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&u.banned_reason)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Datetime>, _>(&u.banned_until)
            .bind::<diesel::sql_types::Datetime, _>(&u.created_at)
            .bind::<diesel::sql_types::Datetime, _>(&u.updated_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_mysql)?;

            // SELECT back the inserted row using typed query
            let result = yauth_users::table
                .find(&id)
                .select(MysqlUser::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;

            Ok(result.into_domain())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let mysql_changes = MysqlUpdateUser::from_domain(changes);

            // MySQL does not support RETURNING — UPDATE then SELECT
            diesel::update(yauth_users::table.find(&id_str))
                .set(&mysql_changes)
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;

            let result = yauth_users::table
                .find(&id_str)
                .select(MysqlUser::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;

            Ok(result.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
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
            let mut conn = get_conn(&self.pool).await?;
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
            let mut conn = get_conn(&self.pool).await?;
            let pattern = search.as_ref().map(|s| format!("%{}%", s.to_lowercase()));
            let total: i64 = if let Some(ref p) = pattern {
                yauth_users::table
                    .filter(yauth_users::email.like(p))
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

            let users: Vec<MysqlUser> = if let Some(ref p) = pattern {
                yauth_users::table
                    .filter(yauth_users::email.like(p))
                    .order(yauth_users::created_at.desc())
                    .limit(limit)
                    .offset(offset)
                    .select(MysqlUser::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_users::table
                    .order(yauth_users::created_at.desc())
                    .limit(limit)
                    .offset(offset)
                    .select(MysqlUser::as_select())
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

pub(crate) struct MysqlSessionRepo {
    pool: MysqlPool,
}

impl MysqlSessionRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for MysqlSessionRepo {}

impl SessionRepository for MysqlSessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let result = yauth_sessions::table
                .find(&id_str)
                .select(MysqlSession::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|s| s.into_domain()))
        })
    }

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let s = MysqlNewSession::from_domain(input);
            diesel::sql_query(
                "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind::<diesel::sql_types::Text, _>(&s.id)
            .bind::<diesel::sql_types::Text, _>(&s.user_id)
            .bind::<diesel::sql_types::Text, _>(&s.token_hash)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&s.ip_address)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&s.user_agent)
            .bind::<diesel::sql_types::Datetime, _>(&s.expires_at)
            .bind::<diesel::sql_types::Datetime, _>(&s.created_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_mysql)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
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
            let mut conn = get_conn(&self.pool).await?;
            let total: i64 = yauth_sessions::table
                .count()
                .get_result(&mut *conn)
                .await
                .map_err(diesel_err)?;
            let sessions: Vec<MysqlSession> = yauth_sessions::table
                .order(yauth_sessions::created_at.desc())
                .limit(limit)
                .offset(offset)
                .select(MysqlSession::as_select())
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
