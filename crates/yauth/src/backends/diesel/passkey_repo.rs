use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{PasskeyRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

pub(crate) struct DieselPasskeyRepo {
    pool: DbPool,
}

impl DieselPasskeyRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselPasskeyRepo {}

impl PasskeyRepository for DieselPasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let results: Vec<DieselWebauthnCredential> = yauth_webauthn_credentials::table
                .filter(yauth_webauthn_credentials::user_id.eq(user_id))
                .select(DieselWebauthnCredential::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(results.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::WebauthnCredential>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_webauthn_credentials::table
                .filter(
                    yauth_webauthn_credentials::id
                        .eq(id)
                        .and(yauth_webauthn_credentials::user_id.eq(user_id)),
                )
                .select(DieselWebauthnCredential::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewWebauthnCredential) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let diesel_input = DieselNewWebauthnCredential::from_domain(input);
            diesel::insert_into(yauth_webauthn_credentials::table)
                .values(&diesel_input)
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(
                yauth_webauthn_credentials::table
                    .filter(yauth_webauthn_credentials::user_id.eq(user_id)),
            )
            .set(yauth_webauthn_credentials::last_used_at.eq(chrono::Utc::now().naive_utc()))
            .execute(&mut conn)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::delete(
                yauth_webauthn_credentials::table.filter(yauth_webauthn_credentials::id.eq(id)),
            )
            .execute(&mut conn)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }
}
