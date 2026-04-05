use super::MysqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{MagicLinkRepository, RepoFuture, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

pub(crate) struct MysqlMagicLinkRepo {
    pool: MysqlPool,
}
impl MysqlMagicLinkRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlMagicLinkRepo {}
impl MagicLinkRepository for MysqlMagicLinkRepo {
    fn find_unused_by_token_hash(&self, th: &str) -> RepoFuture<'_, Option<domain::MagicLink>> {
        let th = th.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = chrono::Utc::now().naive_utc();
            let r = yauth_magic_links::table
                .filter(
                    yauth_magic_links::token_hash
                        .eq(&th)
                        .and(yauth_magic_links::used.eq(false))
                        .and(yauth_magic_links::expires_at.gt(now)),
                )
                .select(MysqlMagicLink::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, em, th, ea, ca) = (
                uuid_to_str(input.id),
                input.email,
                input.token_hash,
                input.expires_at,
                input.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_magic_links \
                 (id, email, token_hash, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&em)
            .bind::<diesel::sql_types::Text, _>(&th)
            .bind::<diesel::sql_types::Datetime, _>(&ea)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_magic_links::table.find(&ids))
                .set(yauth_magic_links::used.eq(true))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::delete(yauth_magic_links::table.find(&ids))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete_unused_for_email(&self, email: &str) -> RepoFuture<'_, ()> {
        let em = email.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            diesel::delete(
                yauth_magic_links::table.filter(
                    yauth_magic_links::email
                        .eq(&em)
                        .and(yauth_magic_links::used.eq(false)),
                ),
            )
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
}
