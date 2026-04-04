use super::LibsqlPool;
use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{OauthAccountRepository, OauthStateRepository, RepoError, RepoFuture, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_oauth_accounts)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct L {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub updated_at: String,
}
impl L {
    fn d(self) -> domain::OauthAccount {
        domain::OauthAccount {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            provider: self.provider,
            provider_user_id: self.provider_user_id,
            access_token_enc: self.access_token_enc,
            refresh_token_enc: self.refresh_token_enc,
            created_at: str_to_dt(&self.created_at),
            expires_at: opt_str_to_dt(self.expires_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_oauth_states)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LS {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}
impl LS {
    fn d(self) -> domain::OauthState {
        domain::OauthState {
            state: self.state,
            provider: self.provider,
            redirect_url: self.redirect_url,
            expires_at: str_to_dt(&self.expires_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

fn pe(e: impl std::fmt::Display) -> RepoError {
    RepoError::Internal(format!("{e}").into())
}
fn de(e: diesel::result::Error) -> RepoError {
    RepoError::Internal(e.into())
}

pub(crate) struct LibsqlOauthAccountRepo {
    pool: LibsqlPool,
}
impl LibsqlOauthAccountRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlOauthAccountRepo {}
impl OauthAccountRepository for LibsqlOauthAccountRepo {
    fn find_by_provider_and_provider_user_id(
        &self,
        provider: &str,
        puid: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let (p, pu) = (provider.to_string(), puid.to_string());
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let r = yauth_oauth_accounts::table
                .filter(
                    yauth_oauth_accounts::provider
                        .eq(&p)
                        .and(yauth_oauth_accounts::provider_user_id.eq(&pu)),
                )
                .select(L::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(de)?;
            Ok(r.map(|r| r.d()))
        })
    }
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let uid = uuid_to_str(user_id);
            let r: Vec<L> = yauth_oauth_accounts::table
                .filter(yauth_oauth_accounts::user_id.eq(&uid))
                .select(L::as_select())
                .load(&mut *c)
                .await
                .map_err(de)?;
            Ok(r.into_iter().map(|r| r.d()).collect())
        })
    }
    fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let p = provider.to_string();
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let uid = uuid_to_str(user_id);
            let r = yauth_oauth_accounts::table
                .filter(
                    yauth_oauth_accounts::user_id
                        .eq(&uid)
                        .and(yauth_oauth_accounts::provider.eq(&p)),
                )
                .select(L::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(de)?;
            Ok(r.map(|r| r.d()))
        })
    }
    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let (id, uid, p, pu, at, rt, ca, ea, ua) = (
                uuid_to_str(input.id),
                uuid_to_str(input.user_id),
                input.provider,
                input.provider_user_id,
                input.access_token_enc,
                input.refresh_token_enc,
                dt_to_str(input.created_at),
                opt_dt_to_str(input.expires_at),
                dt_to_str(input.updated_at),
            );
            diesel::sql_query("INSERT INTO yauth_oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&p).bind::<diesel::sql_types::Text, _>(&pu)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&at).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&rt)
            .bind::<diesel::sql_types::Text, _>(&ca).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ea).bind::<diesel::sql_types::Text, _>(&ua)
            .execute(&mut *c).await.map_err(de)?;
            Ok(())
        })
    }
    fn update_tokens(
        &self,
        id: Uuid,
        at: Option<&str>,
        rt: Option<&str>,
        ea: Option<chrono::NaiveDateTime>,
    ) -> RepoFuture<'_, ()> {
        let (at, rt) = (at.map(|s| s.to_string()), rt.map(|s| s.to_string()));
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let ids = uuid_to_str(id);
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(yauth_oauth_accounts::table.filter(yauth_oauth_accounts::id.eq(&ids)))
                .set((
                    yauth_oauth_accounts::access_token_enc.eq(&at),
                    yauth_oauth_accounts::refresh_token_enc.eq(&rt),
                    yauth_oauth_accounts::expires_at.eq(opt_dt_to_str(ea)),
                    yauth_oauth_accounts::updated_at.eq(&now),
                ))
                .execute(&mut *c)
                .await
                .map_err(de)?;
            Ok(())
        })
    }
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let ids = uuid_to_str(id);
            diesel::delete(yauth_oauth_accounts::table.filter(yauth_oauth_accounts::id.eq(&ids)))
                .execute(&mut *c)
                .await
                .map_err(de)?;
            Ok(())
        })
    }
}

pub(crate) struct LibsqlOauthStateRepo {
    pool: LibsqlPool,
}
impl LibsqlOauthStateRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlOauthStateRepo {}
impl OauthStateRepository for LibsqlOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let (st, p, ru, ea, ca) = (
                input.state,
                input.provider,
                input.redirect_url,
                dt_to_str(input.expires_at),
                dt_to_str(input.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_oauth_states (state, provider, redirect_url, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&st).bind::<diesel::sql_types::Text, _>(&p).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ru).bind::<diesel::sql_types::Text, _>(&ea).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(de)?;
            Ok(())
        })
    }
    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>> {
        let st = state.to_string();
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let now = chrono::Utc::now().naive_utc();
            let now_str = super::models::dt_to_str(now);

            // Atomic SELECT + DELETE in a transaction to prevent TOCTOU race.
            // Only consume non-expired states (expires_at > now).
            use diesel_async_crate::SimpleAsyncConnection;
            (*c).batch_execute("BEGIN").await.map_err(de)?;

            let r = yauth_oauth_states::table
                .filter(
                    yauth_oauth_states::state
                        .eq(&st)
                        .and(yauth_oauth_states::expires_at.gt(&now_str)),
                )
                .select(LS::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(de)?;

            if r.is_some() {
                diesel::delete(yauth_oauth_states::table.filter(yauth_oauth_states::state.eq(&st)))
                    .execute(&mut *c)
                    .await
                    .map_err(de)?;
            }

            (*c).batch_execute("COMMIT").await.map_err(de)?;

            Ok(r.map(|r| r.d()))
        })
    }
}
