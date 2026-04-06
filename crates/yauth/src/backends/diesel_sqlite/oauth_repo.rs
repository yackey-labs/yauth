use super::SqlitePool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{OauthAccountRepository, OauthStateRepository, RepoFuture, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_oauth_accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct SqliteOauthAccount {
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
impl SqliteOauthAccount {
    fn into_domain(self) -> domain::OauthAccount {
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
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct SqliteOauthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}
impl SqliteOauthState {
    fn into_domain(self) -> domain::OauthState {
        domain::OauthState {
            state: self.state,
            provider: self.provider,
            redirect_url: self.redirect_url,
            expires_at: str_to_dt(&self.expires_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

pub(crate) struct SqliteOauthAccountRepo {
    pool: SqlitePool,
}
impl SqliteOauthAccountRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqliteOauthAccountRepo {}
impl OauthAccountRepository for SqliteOauthAccountRepo {
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
                .select(SqliteOauthAccount::as_select())
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
            let r: Vec<SqliteOauthAccount> = yauth_oauth_accounts::table
                .filter(yauth_oauth_accounts::user_id.eq(&uid))
                .select(SqliteOauthAccount::as_select())
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
                .select(SqliteOauthAccount::as_select())
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
                dt_to_str(input.created_at),
                opt_dt_to_str(input.expires_at),
                dt_to_str(input.updated_at),
            );
            diesel::sql_query("INSERT INTO yauth_oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&p).bind::<diesel::sql_types::Text, _>(&pu)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&at).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&rt)
            .bind::<diesel::sql_types::Text, _>(&ca).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ea).bind::<diesel::sql_types::Text, _>(&ua)
            .execute(&mut *c).await.map_err(diesel_err)?;
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

pub(crate) struct SqliteOauthStateRepo {
    pool: SqlitePool,
}
impl SqliteOauthStateRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqliteOauthStateRepo {}
impl OauthStateRepository for SqliteOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (st, p, ru, ea, ca) = (
                input.state,
                input.provider,
                input.redirect_url,
                dt_to_str(input.expires_at),
                dt_to_str(input.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_oauth_states (state, provider, redirect_url, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&st).bind::<diesel::sql_types::Text, _>(&p).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ru).bind::<diesel::sql_types::Text, _>(&ea).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>> {
        let st = state.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = chrono::Utc::now().naive_utc();
            let now_str = super::models::dt_to_str(now);

            // Atomic SELECT + DELETE in a transaction to prevent TOCTOU race.
            // Only consume non-expired states (expires_at > now).
            // Ensure ROLLBACK on any error path to avoid leaking an open transaction.
            use diesel_async_crate::SimpleAsyncConnection;
            (*c).batch_execute("BEGIN").await.map_err(diesel_err)?;

            let txn_result: Result<Option<SqliteOauthState>, _> = async {
                let r = yauth_oauth_states::table
                    .filter(
                        yauth_oauth_states::state
                            .eq(&st)
                            .and(yauth_oauth_states::expires_at.gt(&now_str)),
                    )
                    .select(SqliteOauthState::as_select())
                    .first(&mut *c)
                    .await
                    .optional()
                    .map_err(diesel_err)?;

                if r.is_some() {
                    diesel::delete(
                        yauth_oauth_states::table.filter(yauth_oauth_states::state.eq(&st)),
                    )
                    .execute(&mut *c)
                    .await
                    .map_err(diesel_err)?;
                }

                Ok(r)
            }
            .await;

            match txn_result {
                Ok(r) => {
                    (*c).batch_execute("COMMIT").await.map_err(diesel_err)?;
                    Ok(r.map(|r| r.into_domain()))
                }
                Err(e) => {
                    let _ = (*c).batch_execute("ROLLBACK").await;
                    Err(e)
                }
            }
        })
    }
}
