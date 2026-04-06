use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::SqlitePool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_conflict_sqlite, diesel_err, get_conn};
use crate::domain;
use crate::repo::{RepoFuture, SessionRepository, UserRepository, sealed};

pub(crate) struct SqliteUserRepo {
    pool: SqlitePool,
}

impl SqliteUserRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqliteUserRepo {}

impl UserRepository for SqliteUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let result = yauth_users::table
                .find(&id_str)
                .select(SqliteUser::as_select())
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
            // SQLite `=` is case-sensitive by default, so use LOWER() on the column
            // with a parameterized bind to avoid SQL injection.
            let result = diesel::sql_query(
                "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                 FROM yauth_users WHERE LOWER(email) = ?",
            )
            .bind::<diesel::sql_types::Text, _>(&email)
            .get_result::<SqliteUserByName>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let u = SqliteNewUser::from_domain(input);
            let id = u.id.clone();

            // SQLite does not support RETURNING — INSERT then SELECT
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
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&u.banned_until)
            .bind::<diesel::sql_types::Text, _>(&u.created_at)
            .bind::<diesel::sql_types::Text, _>(&u.updated_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_sqlite)?;

            // SELECT back the inserted row
            let result = yauth_users::table
                .find(&id)
                .select(SqliteUser::as_select())
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
            let sqlite_changes = SqliteUpdateUser::from_domain(changes);

            // SQLite does not support RETURNING — UPDATE then SELECT
            diesel::update(yauth_users::table.find(&id_str))
                .set(&sqlite_changes)
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;

            let result = yauth_users::table
                .find(&id_str)
                .select(SqliteUser::as_select())
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

            let users: Vec<SqliteUser> = if let Some(ref p) = pattern {
                yauth_users::table
                    .filter(yauth_users::email.like(p))
                    .order(yauth_users::created_at.desc())
                    .limit(limit)
                    .offset(offset)
                    .select(SqliteUser::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_users::table
                    .order(yauth_users::created_at.desc())
                    .limit(limit)
                    .offset(offset)
                    .select(SqliteUser::as_select())
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

pub(crate) struct SqliteSessionRepo {
    pool: SqlitePool,
}

impl SqliteSessionRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqliteSessionRepo {}

impl SessionRepository for SqliteSessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let result = yauth_sessions::table
                .find(&id_str)
                .select(SqliteSession::as_select())
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
            let s = SqliteNewSession::from_domain(input);
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
            let sessions: Vec<SqliteSession> = yauth_sessions::table
                .order(yauth_sessions::created_at.desc())
                .limit(limit)
                .offset(offset)
                .select(SqliteSession::as_select())
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
