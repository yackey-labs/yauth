use super::MysqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{OauthAccountRepository, OauthStateRepository, RepoFuture, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

pub(crate) struct MysqlOauthAccountRepo {
    pool: MysqlPool,
}
impl MysqlOauthAccountRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlOauthAccountRepo {}
impl OauthAccountRepository for MysqlOauthAccountRepo {
    fn find_by_provider_and_provider_user_id(
        &self,
        provider: &str,
        puid: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let (p, pu) = (provider.to_string(), puid.to_string());
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_oauth_accounts::table
                .filter(
                    yauth_oauth_accounts::provider
                        .eq(&p)
                        .and(yauth_oauth_accounts::provider_user_id.eq(&pu)),
                )
                .select(MysqlOauthAccount::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let r: Vec<MysqlOauthAccount> = yauth_oauth_accounts::table
                .filter(yauth_oauth_accounts::user_id.eq(&uid))
                .select(MysqlOauthAccount::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.into_domain()).collect())
        })
    }
    fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let p = provider.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let r = yauth_oauth_accounts::table
                .filter(
                    yauth_oauth_accounts::user_id
                        .eq(&uid)
                        .and(yauth_oauth_accounts::provider.eq(&p)),
                )
                .select(MysqlOauthAccount::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, p, pu, at, rt, ca, ea, ua) = (
                uuid_to_str(input.id),
                uuid_to_str(input.user_id),
                input.provider,
                input.provider_user_id,
                input.access_token_enc,
                input.refresh_token_enc,
                input.created_at,
                input.expires_at,
                input.updated_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_oauth_accounts \
                 (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, \
                  created_at, expires_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Text, _>(&p)
            .bind::<diesel::sql_types::Text, _>(&pu)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&at)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&rt)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Datetime>, _>(&ea)
            .bind::<diesel::sql_types::Datetime, _>(&ua)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
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
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let now = chrono::Utc::now().naive_utc();
            diesel::update(yauth_oauth_accounts::table.filter(yauth_oauth_accounts::id.eq(&ids)))
                .set((
                    yauth_oauth_accounts::access_token_enc.eq(&at),
                    yauth_oauth_accounts::refresh_token_enc.eq(&rt),
                    yauth_oauth_accounts::expires_at.eq(ea),
                    yauth_oauth_accounts::updated_at.eq(now),
                ))
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
            diesel::delete(yauth_oauth_accounts::table.filter(yauth_oauth_accounts::id.eq(&ids)))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct MysqlOauthStateRepo {
    pool: MysqlPool,
}
impl MysqlOauthStateRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlOauthStateRepo {}
impl OauthStateRepository for MysqlOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (st, p, ru, ea, ca) = (
                input.state,
                input.provider,
                input.redirect_url,
                input.expires_at,
                input.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_oauth_states \
                 (state, provider, redirect_url, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&st)
            .bind::<diesel::sql_types::Text, _>(&p)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ru)
            .bind::<diesel::sql_types::Datetime, _>(&ea)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>> {
        let st = state.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = chrono::Utc::now().naive_utc();

            use diesel_async_crate::AsyncConnection;
            use diesel_async_crate::scoped_futures::ScopedFutureExt;

            let result = (*c)
                .transaction::<_, diesel::result::Error, _>(|conn| {
                    let st = st.clone();
                    async move {
                        let r = yauth_oauth_states::table
                            .filter(
                                yauth_oauth_states::state
                                    .eq(&st)
                                    .and(yauth_oauth_states::expires_at.gt(now)),
                            )
                            .select(MysqlOauthState::as_select())
                            .first(conn)
                            .await
                            .optional()?;

                        if r.is_some() {
                            diesel::delete(
                                yauth_oauth_states::table.filter(yauth_oauth_states::state.eq(&st)),
                            )
                            .execute(conn)
                            .await?;
                        }

                        Ok(r)
                    }
                    .scope_boxed()
                })
                .await
                .map_err(diesel_err)?;

            Ok(result.map(|r| r.into_domain()))
        })
    }
}
