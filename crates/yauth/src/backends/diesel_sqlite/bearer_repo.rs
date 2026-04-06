use super::SqlitePool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoFuture, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_refresh_tokens)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct SqliteRefreshToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub family_id: String,
    pub expires_at: String,
    pub revoked: bool,
    pub created_at: String,
}
impl SqliteRefreshToken {
    fn into_domain(self) -> domain::RefreshToken {
        domain::RefreshToken {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            family_id: str_to_uuid(&self.family_id),
            expires_at: str_to_dt(&self.expires_at),
            revoked: self.revoked,
            created_at: str_to_dt(&self.created_at),
        }
    }
}
pub(crate) struct SqliteRefreshTokenRepo {
    pool: SqlitePool,
}
impl SqliteRefreshTokenRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqliteRefreshTokenRepo {}
impl RefreshTokenRepository for SqliteRefreshTokenRepo {
    fn find_by_token_hash(&self, th: &str) -> RepoFuture<'_, Option<domain::RefreshToken>> {
        let th = th.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_refresh_tokens::table
                .filter(yauth_refresh_tokens::token_hash.eq(&th))
                .select(SqliteRefreshToken::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, th, fid, ea, rev, ca) = (
                uuid_to_str(input.id),
                uuid_to_str(input.user_id),
                input.token_hash,
                uuid_to_str(input.family_id),
                dt_to_str(input.expires_at),
                input.revoked,
                dt_to_str(input.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&th).bind::<diesel::sql_types::Text, _>(&fid).bind::<diesel::sql_types::Text, _>(&ea).bind::<diesel::sql_types::Bool, _>(rev).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_refresh_tokens::table.filter(yauth_refresh_tokens::id.eq(&ids)))
                .set(yauth_refresh_tokens::revoked.eq(true))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn revoke_family(&self, fid: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let f = uuid_to_str(fid);
            diesel::update(
                yauth_refresh_tokens::table.filter(yauth_refresh_tokens::family_id.eq(&f)),
            )
            .set(yauth_refresh_tokens::revoked.eq(true))
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn find_password_hash_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<String>> {
        Box::pin(async move {
            #[cfg(feature = "email-password")]
            {
                let mut c = get_conn(&self.pool).await?;
                let uid = uuid_to_str(user_id);
                use super::schema::yauth_passwords;
                let r = yauth_passwords::table
                    .find(&uid)
                    .select(yauth_passwords::password_hash)
                    .first::<String>(&mut *c)
                    .await
                    .optional()
                    .map_err(diesel_err)?;
                Ok(r)
            }
            #[cfg(not(feature = "email-password"))]
            {
                let _ = user_id;
                Ok(None)
            }
        })
    }
}
