use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{MagicLinkRepository, RepoFuture, sealed};
use crate::state::DbPool;

pub(crate) struct DieselMagicLinkRepo {
    pool: DbPool,
}
impl DieselMagicLinkRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselMagicLinkRepo {}

impl MagicLinkRepository for DieselMagicLinkRepo {
    fn find_unused_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::MagicLink>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_magic_links::table
                .filter(
                    yauth_magic_links::token_hash
                        .eq(&token_hash)
                        .and(yauth_magic_links::used.eq(false))
                        .and(yauth_magic_links::expires_at.gt(chrono::Utc::now().naive_utc())),
                )
                .select(DieselMagicLink::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::insert_into(yauth_magic_links::table)
                .values(&DieselNewMagicLink::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::update(yauth_magic_links::table.find(id))
                .set(yauth_magic_links::used.eq(true))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(yauth_magic_links::table.find(id))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn delete_unused_for_email(&self, email: &str) -> RepoFuture<'_, ()> {
        let email = email.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(
                yauth_magic_links::table.filter(
                    yauth_magic_links::email
                        .eq(&email)
                        .and(yauth_magic_links::used.eq(false)),
                ),
            )
            .execute(&mut conn)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
}
