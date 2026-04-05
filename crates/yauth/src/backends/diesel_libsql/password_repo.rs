use super::LibsqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{
    EmailVerificationRepository, PasswordRepository, PasswordResetRepository, RepoFuture, sealed,
};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

pub(crate) struct LibsqlPasswordRepo {
    pool: LibsqlPool,
}
impl LibsqlPasswordRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlPasswordRepo {}
impl PasswordRepository for LibsqlPasswordRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::Password>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let r = yauth_passwords::table
                .find(&uid)
                .select(LibsqlPassword::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let p = LibsqlNewPassword::from_domain(input);
            diesel::sql_query("INSERT INTO yauth_passwords (user_id, password_hash) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET password_hash = excluded.password_hash")
                .bind::<diesel::sql_types::Text, _>(&p.user_id)
                .bind::<diesel::sql_types::Text, _>(&p.password_hash)
                .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct LibsqlEmailVerificationRepo {
    pool: LibsqlPool,
}
impl LibsqlEmailVerificationRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlEmailVerificationRepo {}
impl EmailVerificationRepository for LibsqlEmailVerificationRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::EmailVerification>> {
        let th = token_hash.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_email_verifications::table
                .filter(yauth_email_verifications::token_hash.eq(&th))
                .select(LibsqlEmailVerification::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let v = LibsqlNewEmailVerification::from_domain(input);
            diesel::sql_query("INSERT INTO yauth_email_verifications (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
                .bind::<diesel::sql_types::Text, _>(&v.id).bind::<diesel::sql_types::Text, _>(&v.user_id).bind::<diesel::sql_types::Text, _>(&v.token_hash).bind::<diesel::sql_types::Text, _>(&v.expires_at).bind::<diesel::sql_types::Text, _>(&v.created_at)
                .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::delete(yauth_email_verifications::table.find(&ids))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            diesel::delete(
                yauth_email_verifications::table
                    .filter(yauth_email_verifications::user_id.eq(&uid)),
            )
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct LibsqlPasswordResetRepo {
    pool: LibsqlPool,
}
impl LibsqlPasswordResetRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlPasswordResetRepo {}
impl PasswordResetRepository for LibsqlPasswordResetRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::PasswordReset>> {
        let th = token_hash.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_password_resets::table
                .filter(
                    yauth_password_resets::token_hash
                        .eq(&th)
                        .and(yauth_password_resets::used_at.is_null()),
                )
                .select(LibsqlPasswordReset::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let p = LibsqlNewPasswordReset::from_domain(input);
            diesel::sql_query("INSERT INTO yauth_password_resets (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
                .bind::<diesel::sql_types::Text, _>(&p.id).bind::<diesel::sql_types::Text, _>(&p.user_id).bind::<diesel::sql_types::Text, _>(&p.token_hash).bind::<diesel::sql_types::Text, _>(&p.expires_at).bind::<diesel::sql_types::Text, _>(&p.created_at)
                .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            diesel::delete(
                yauth_password_resets::table.filter(
                    yauth_password_resets::user_id
                        .eq(&uid)
                        .and(yauth_password_resets::used_at.is_null()),
                ),
            )
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
}
