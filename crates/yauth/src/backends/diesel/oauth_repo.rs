use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{OauthAccountRepository, OauthStateRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

pub(crate) struct DieselOauthAccountRepo {
    pool: DbPool,
}
impl DieselOauthAccountRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselOauthAccountRepo {}

impl OauthAccountRepository for DieselOauthAccountRepo {
    fn find_by_provider_and_provider_user_id(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        let provider_user_id = provider_user_id.to_string();
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_oauth_accounts::table
                .filter(
                    yauth_oauth_accounts::provider
                        .eq(&provider)
                        .and(yauth_oauth_accounts::provider_user_id.eq(&provider_user_id)),
                )
                .select(DieselOauthAccount::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let results: Vec<DieselOauthAccount> = yauth_oauth_accounts::table
                .filter(yauth_oauth_accounts::user_id.eq(user_id))
                .select(DieselOauthAccount::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(results.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_oauth_accounts::table
                .filter(
                    yauth_oauth_accounts::user_id
                        .eq(user_id)
                        .and(yauth_oauth_accounts::provider.eq(&provider)),
                )
                .select(DieselOauthAccount::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::insert_into(yauth_oauth_accounts::table)
                .values(&DieselNewOauthAccount::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn update_tokens(
        &self,
        id: Uuid,
        access_token_enc: Option<&str>,
        refresh_token_enc: Option<&str>,
        expires_at: Option<NaiveDateTime>,
    ) -> RepoFuture<'_, ()> {
        let access_token_enc = access_token_enc.map(|s| s.to_string());
        let refresh_token_enc = refresh_token_enc.map(|s| s.to_string());
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_oauth_accounts::table.filter(yauth_oauth_accounts::id.eq(id)))
                .set((
                    yauth_oauth_accounts::access_token_enc.eq(&access_token_enc),
                    yauth_oauth_accounts::refresh_token_enc.eq(&refresh_token_enc),
                    yauth_oauth_accounts::expires_at.eq(expires_at),
                    yauth_oauth_accounts::updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
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
            diesel::delete(yauth_oauth_accounts::table.filter(yauth_oauth_accounts::id.eq(id)))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }
}

pub(crate) struct DieselOauthStateRepo {
    pool: DbPool,
}
impl DieselOauthStateRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselOauthStateRepo {}

impl OauthStateRepository for DieselOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::insert_into(yauth_oauth_states::table)
                .values(&DieselNewOauthState::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>> {
        let state = state.to_string();
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_oauth_states::table
                .filter(yauth_oauth_states::state.eq(&state))
                .select(DieselOauthState::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            if result.is_some() {
                diesel::delete(
                    yauth_oauth_states::table.filter(yauth_oauth_states::state.eq(&state)),
                )
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            }
            match result {
                Some(r) => {
                    let domain = r.into_domain();
                    if domain.expires_at < chrono::Utc::now().naive_utc() {
                        Ok(None)
                    } else {
                        Ok(Some(domain))
                    }
                }
                None => Ok(None),
            }
        })
    }
}
