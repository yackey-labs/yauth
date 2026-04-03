use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{BackupCodeRepository, RepoError, RepoFuture, TotpRepository, sealed};
use crate::state::DbPool;

pub(crate) struct DieselTotpRepo {
    pool: DbPool,
}
impl DieselTotpRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselTotpRepo {}

impl TotpRepository for DieselTotpRepo {
    fn find_by_user_id(
        &self,
        user_id: Uuid,
        verified: Option<bool>,
    ) -> RepoFuture<'_, Option<domain::TotpSecret>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = match verified {
                Some(v) => yauth_totp_secrets::table
                    .filter(
                        yauth_totp_secrets::user_id
                            .eq(user_id)
                            .and(yauth_totp_secrets::verified.eq(v)),
                    )
                    .select(DieselTotpSecret::as_select())
                    .first(&mut conn)
                    .await
                    .optional()
                    .map_err(|e| RepoError::Internal(e.into()))?,
                None => yauth_totp_secrets::table
                    .filter(yauth_totp_secrets::user_id.eq(user_id))
                    .select(DieselTotpSecret::as_select())
                    .first(&mut conn)
                    .await
                    .optional()
                    .map_err(|e| RepoError::Internal(e.into()))?,
            };
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewTotpSecret) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::insert_into(yauth_totp_secrets::table)
                .values(&DieselNewTotpSecret::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn delete_for_user(&self, user_id: Uuid, verified_only: Option<bool>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            match verified_only {
                Some(v) => {
                    diesel::delete(
                        yauth_totp_secrets::table.filter(
                            yauth_totp_secrets::user_id
                                .eq(user_id)
                                .and(yauth_totp_secrets::verified.eq(v)),
                        ),
                    )
                    .execute(&mut conn)
                    .await
                    .map_err(|e| RepoError::Internal(e.into()))?;
                }
                None => {
                    diesel::delete(
                        yauth_totp_secrets::table.filter(yauth_totp_secrets::user_id.eq(user_id)),
                    )
                    .execute(&mut conn)
                    .await
                    .map_err(|e| RepoError::Internal(e.into()))?;
                }
            };
            Ok(())
        })
    }

    fn mark_verified(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_totp_secrets::table.find(id))
                .set(yauth_totp_secrets::verified.eq(true))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }
}

pub(crate) struct DieselBackupCodeRepo {
    pool: DbPool,
}
impl DieselBackupCodeRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselBackupCodeRepo {}

impl BackupCodeRepository for DieselBackupCodeRepo {
    fn find_unused_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::BackupCode>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let results: Vec<DieselBackupCode> = yauth_backup_codes::table
                .filter(
                    yauth_backup_codes::user_id
                        .eq(user_id)
                        .and(yauth_backup_codes::used.eq(false)),
                )
                .select(DieselBackupCode::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(results.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewBackupCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::insert_into(yauth_backup_codes::table)
                .values(&DieselNewBackupCode::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::delete(
                yauth_backup_codes::table.filter(yauth_backup_codes::user_id.eq(user_id)),
            )
            .execute(&mut conn)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_backup_codes::table.find(id))
                .set(yauth_backup_codes::used.eq(true))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }
}
