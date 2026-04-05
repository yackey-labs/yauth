use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{
    EmailVerificationRepository, PasswordRepository, PasswordResetRepository, RepoFuture, sealed,
};
use crate::state::DbPool;

// ──────────────────────────────────────────────
// Password
// ──────────────────────────────────────────────

pub(crate) struct DieselPasswordRepo {
    pool: DbPool,
}

impl DieselPasswordRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselPasswordRepo {}

impl PasswordRepository for DieselPasswordRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::Password>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_passwords::table
                .find(user_id)
                .select(DieselPassword::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let diesel_input = DieselNewPassword::from_domain(input);
            diesel::insert_into(yauth_passwords::table)
                .values(&diesel_input)
                .on_conflict(yauth_passwords::user_id)
                .do_update()
                .set(yauth_passwords::password_hash.eq(&diesel_input.password_hash))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Email Verification
// ──────────────────────────────────────────────

pub(crate) struct DieselEmailVerificationRepo {
    pool: DbPool,
}

impl DieselEmailVerificationRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselEmailVerificationRepo {}

impl EmailVerificationRepository for DieselEmailVerificationRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::EmailVerification>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_email_verifications::table
                .filter(yauth_email_verifications::token_hash.eq(&token_hash))
                .select(DieselEmailVerification::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let diesel_input = DieselNewEmailVerification::from_domain(input);
            diesel::insert_into(yauth_email_verifications::table)
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
            diesel::delete(yauth_email_verifications::table.find(id))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(
                yauth_email_verifications::table
                    .filter(yauth_email_verifications::user_id.eq(user_id)),
            )
            .execute(&mut conn)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Password Reset
// ──────────────────────────────────────────────

pub(crate) struct DieselPasswordResetRepo {
    pool: DbPool,
}

impl DieselPasswordResetRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselPasswordResetRepo {}

impl PasswordResetRepository for DieselPasswordResetRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::PasswordReset>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_password_resets::table
                .filter(
                    yauth_password_resets::token_hash
                        .eq(&token_hash)
                        .and(yauth_password_resets::used_at.is_null()),
                )
                .select(DieselPasswordReset::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let diesel_input = DieselNewPasswordReset::from_domain(input);
            diesel::insert_into(yauth_password_resets::table)
                .values(&diesel_input)
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(
                yauth_password_resets::table.filter(
                    yauth_password_resets::user_id
                        .eq(user_id)
                        .and(yauth_password_resets::used_at.is_null()),
                ),
            )
            .execute(&mut conn)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
}
