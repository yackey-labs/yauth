use chrono::NaiveDateTime;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{
    dt_to_str, opt_dt_to_str, opt_str_to_dt, sqlx_err, str_to_dt, str_to_uuid,
};
use crate::domain;
use crate::repo::{OauthAccountRepository, OauthStateRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct OauthAccountRow {
    id: Option<String>,
    user_id: Option<String>,
    provider: String,
    provider_user_id: String,
    access_token_enc: Option<String>,
    refresh_token_enc: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    updated_at: String,
}

impl OauthAccountRow {
    fn into_domain(self) -> domain::OauthAccount {
        domain::OauthAccount {
            id: str_to_uuid(&self.id.unwrap_or_default()),
            user_id: str_to_uuid(&self.user_id.unwrap_or_default()),
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

#[derive(sqlx::FromRow)]
struct OauthStateRow {
    state: Option<String>,
    provider: String,
    redirect_url: Option<String>,
    expires_at: String,
    created_at: String,
}

pub(crate) struct SqlxSqliteOauthAccountRepo {
    pool: SqlitePool,
}
impl SqlxSqliteOauthAccountRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteOauthAccountRepo {}

impl OauthAccountRepository for SqlxSqliteOauthAccountRepo {
    fn find_by_provider_and_provider_user_id(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        let provider_user_id = provider_user_id.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                OauthAccountRow,
                "SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at \
                 FROM yauth_oauth_accounts WHERE provider = ? AND provider_user_id = ? /* sqlite */",
                provider,
                provider_user_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let rows = sqlx::query_as!(
                OauthAccountRow,
                "SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at \
                 FROM yauth_oauth_accounts WHERE user_id = ? /* sqlite */",
                user_id_str
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let row = sqlx::query_as!(
                OauthAccountRow,
                "SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at \
                 FROM yauth_oauth_accounts WHERE user_id = ? AND provider = ? /* sqlite */",
                user_id_str,
                provider
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let created_str = dt_to_str(input.created_at);
            let expires_str = opt_dt_to_str(input.expires_at);
            let updated_str = dt_to_str(input.updated_at);
            sqlx::query!(
                "INSERT INTO yauth_oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.provider,
                input.provider_user_id,
                input.access_token_enc,
                input.refresh_token_enc,
                created_str,
                expires_str,
                updated_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
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
            let id_str = id.to_string();
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let expires_str = opt_dt_to_str(expires_at);
            sqlx::query!(
                "UPDATE yauth_oauth_accounts SET access_token_enc = ?, refresh_token_enc = ?, expires_at = ?, updated_at = ? WHERE id = ? /* sqlite */",
                access_token_enc,
                refresh_token_enc,
                expires_str,
                now,
                id_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!(
                "DELETE FROM yauth_oauth_accounts WHERE id = ? /* sqlite */",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

pub(crate) struct SqlxSqliteOauthStateRepo {
    pool: SqlitePool,
}
impl SqlxSqliteOauthStateRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteOauthStateRepo {}

impl OauthStateRepository for SqlxSqliteOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_oauth_states (state, provider, redirect_url, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?) /* sqlite */",
                input.state,
                input.provider,
                input.redirect_url,
                expires_str,
                created_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>> {
        let state = state.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                OauthStateRow,
                "SELECT state, provider, redirect_url, expires_at, created_at \
                 FROM yauth_oauth_states WHERE state = ? /* sqlite */",
                state
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;

            if row.is_some() {
                sqlx::query!(
                    "DELETE FROM yauth_oauth_states WHERE state = ? /* sqlite */",
                    state
                )
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            }

            match row {
                Some(r) => {
                    let expires = str_to_dt(&r.expires_at);
                    if expires < chrono::Utc::now().naive_utc() {
                        Ok(None)
                    } else {
                        Ok(Some(domain::OauthState {
                            state: r.state.unwrap_or_default(),
                            provider: r.provider,
                            redirect_url: r.redirect_url,
                            expires_at: expires,
                            created_at: str_to_dt(&r.created_at),
                        }))
                    }
                }
                None => Ok(None),
            }
        })
    }
}
