use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoError, RepoFuture, sealed};
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
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_refresh_tokens::table
                .filter(yauth_refresh_tokens::token_hash.eq(&token_hash))
                .select(DieselRefreshToken::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::insert_into(yauth_refresh_tokens::table)
                .values(&DieselNewRefreshToken::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_refresh_tokens::table.filter(yauth_refresh_tokens::id.eq(id)))
                .set(yauth_refresh_tokens::revoked.eq(true))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(
                yauth_refresh_tokens::table.filter(yauth_refresh_tokens::family_id.eq(family_id)),
            )
            .set(yauth_refresh_tokens::revoked.eq(true))
            .execute(&mut conn)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn find_password_hash_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<String>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            #[derive(diesel::QueryableByName)]
            struct PasswordRow {
                #[diesel(sql_type = diesel::sql_types::Text)]
                password_hash: String,
            }
            let result =
                diesel::sql_query("SELECT password_hash FROM yauth_passwords WHERE user_id = $1")
                    .bind::<diesel::sql_types::Uuid, _>(user_id)
                    .get_result::<PasswordRow>(&mut conn)
                    .await
                    .optional()
                    .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.password_hash))
        })
    }
}
