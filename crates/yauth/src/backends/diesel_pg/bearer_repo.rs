use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoFuture, sealed};
use crate::state::DbPool;

pub(crate) struct DieselRefreshTokenRepo {
    pool: DbPool,
}
impl DieselRefreshTokenRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselRefreshTokenRepo {}

impl RefreshTokenRepository for DieselRefreshTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::RefreshToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_refresh_tokens::table
                .filter(yauth_refresh_tokens::token_hash.eq(&token_hash))
                .select(DieselRefreshToken::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::insert_into(yauth_refresh_tokens::table)
                .values(&DieselNewRefreshToken::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::update(yauth_refresh_tokens::table.filter(yauth_refresh_tokens::id.eq(id)))
                .set(yauth_refresh_tokens::revoked.eq(true))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::update(
                yauth_refresh_tokens::table.filter(yauth_refresh_tokens::family_id.eq(family_id)),
            )
            .set(yauth_refresh_tokens::revoked.eq(true))
            .execute(&mut conn)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn find_password_hash_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<String>> {
        Box::pin(async move {
            #[cfg(feature = "email-password")]
            {
                let mut conn = get_conn(&self.pool).await?;
                use super::schema::yauth_passwords;
                let result = yauth_passwords::table
                    .find(user_id)
                    .select(yauth_passwords::password_hash)
                    .first::<String>(&mut conn)
                    .await
                    .optional()
                    .map_err(diesel_err)?;
                Ok(result)
            }
            #[cfg(not(feature = "email-password"))]
            {
                let _ = user_id;
                Ok(None)
            }
        })
    }
}
