use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_conflict, diesel_err, get_conn};
use crate::domain;
use crate::repo::{RepoFuture, SessionRepository, UserRepository, sealed};
use crate::state::DbPool;

pub(crate) struct DieselUserRepo {
    pool: DbPool,
}

impl DieselUserRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselUserRepo {}

impl UserRepository for DieselUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_users::table
                .find(id)
                .select(DieselUser::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>> {
        let email = email.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Case-insensitive lookup per UserRepository trait contract.
            // ILIKE is Postgres-specific; the email is exact (no wildcards).
            let result = yauth_users::table
                .filter(yauth_users::email.ilike(&email))
                .select(DieselUser::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let diesel_input = DieselNewUser::from_domain(input);
            let result = diesel::insert_into(yauth_users::table)
                .values(&diesel_input)
                .returning(DieselUser::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(diesel_conflict)?;
            Ok(result.into_domain())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let diesel_changes = DieselUpdateUser::from_domain(changes);
            let result = diesel::update(yauth_users::table.find(id))
                .set(&diesel_changes)
                .returning(DieselUser::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(result.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(yauth_users::table.find(id))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn any_exists(&self) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let exists: Option<Uuid> = yauth_users::table
                .select(yauth_users::id)
                .first::<Uuid>(&mut conn)
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

            let total: i64 = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                yauth_users::table
                    .filter(yauth_users::email.ilike(&pattern))
                    .count()
                    .get_result(&mut conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_users::table
                    .count()
                    .get_result(&mut conn)
                    .await
                    .map_err(diesel_err)?
            };

            let users: Vec<DieselUser> = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                yauth_users::table
                    .filter(yauth_users::email.ilike(&pattern))
                    .order(yauth_users::created_at.desc())
                    .limit(limit)
                    .offset(offset)
                    .select(DieselUser::as_select())
                    .load(&mut conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_users::table
                    .order(yauth_users::created_at.desc())
                    .limit(limit)
                    .offset(offset)
                    .select(DieselUser::as_select())
                    .load(&mut conn)
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

pub(crate) struct DieselSessionRepo {
    pool: DbPool,
}

impl DieselSessionRepo {
    #[allow(dead_code)]
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselSessionRepo {}

impl SessionRepository for DieselSessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_sessions::table
                .find(id)
                .select(DieselSession::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|s| s.into_domain()))
        })
    }

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let diesel_input = DieselNewSession::from_domain(input);
            diesel::insert_into(yauth_sessions::table)
                .values(&diesel_input)
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(yauth_sessions::table.find(id))
                .execute(&mut conn)
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
                .get_result(&mut conn)
                .await
                .map_err(diesel_err)?;
            let sessions: Vec<DieselSession> = yauth_sessions::table
                .order(yauth_sessions::created_at.desc())
                .limit(limit)
                .offset(offset)
                .select(DieselSession::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok((
                sessions.into_iter().map(|s| s.into_domain()).collect(),
                total,
            ))
        })
    }
}
