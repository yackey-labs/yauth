use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{naive_to_utc, opt_naive_to_utc, sqlx_err};
use crate::domain;
use crate::repo::{OauthAccountRepository, OauthStateRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct OauthAccountRow {
    id: Uuid,
    user_id: Uuid,
    provider: String,
    provider_user_id: String,
    access_token_enc: Option<String>,
    refresh_token_enc: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl OauthAccountRow {
    fn into_domain(self) -> domain::OauthAccount {
        domain::OauthAccount {
            id: self.id,
            user_id: self.user_id,
            provider: self.provider,
            provider_user_id: self.provider_user_id,
            access_token_enc: self.access_token_enc,
            refresh_token_enc: self.refresh_token_enc,
            created_at: self.created_at.naive_utc(),
            expires_at: self.expires_at.map(|dt| dt.naive_utc()),
            updated_at: self.updated_at.naive_utc(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct OauthStateRow {
    state: String,
    provider: String,
    redirect_url: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

// ── OauthAccount ──

pub(crate) struct SqlxPgOauthAccountRepo {
    pool: PgPool,
}
impl SqlxPgOauthAccountRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgOauthAccountRepo {}

impl OauthAccountRepository for SqlxPgOauthAccountRepo {
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
                r#"SELECT id, user_id as "user_id!", provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at
                   FROM yauth_oauth_accounts WHERE provider = $1 AND provider_user_id = $2"#,
                provider,
                provider_user_id,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>> {
        Box::pin(async move {
            let rows = sqlx::query_as!(
                OauthAccountRow,
                r#"SELECT id, user_id as "user_id!", provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at
                   FROM yauth_oauth_accounts WHERE user_id = $1"#,
                user_id
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
            let row = sqlx::query_as!(
                OauthAccountRow,
                r#"SELECT id, user_id as "user_id!", provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at
                   FROM yauth_oauth_accounts WHERE user_id = $1 AND provider = $2"#,
                user_id,
                provider,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "INSERT INTO yauth_oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                input.id,
                input.user_id,
                input.provider,
                input.provider_user_id,
                input.access_token_enc as Option<String>,
                input.refresh_token_enc as Option<String>,
                naive_to_utc(input.created_at),
                opt_naive_to_utc(input.expires_at) as Option<DateTime<Utc>>,
                naive_to_utc(input.updated_at),
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
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_oauth_accounts SET access_token_enc = $1, refresh_token_enc = $2, expires_at = $3, updated_at = $4 WHERE id = $5",
                access_token_enc as Option<String>,
                refresh_token_enc as Option<String>,
                opt_naive_to_utc(expires_at) as Option<DateTime<Utc>>,
                now,
                id,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!("DELETE FROM yauth_oauth_accounts WHERE id = $1", id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── OauthState ──

pub(crate) struct SqlxPgOauthStateRepo {
    pool: PgPool,
}
impl SqlxPgOauthStateRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgOauthStateRepo {}

impl OauthStateRepository for SqlxPgOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "INSERT INTO yauth_oauth_states (state, provider, redirect_url, expires_at, created_at) \
                 VALUES ($1, $2, $3, $4, $5)",
                input.state,
                input.provider,
                input.redirect_url as Option<String>,
                naive_to_utc(input.expires_at),
                naive_to_utc(input.created_at),
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
                 FROM yauth_oauth_states WHERE state = $1",
                state
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;

            if row.is_some() {
                sqlx::query!("DELETE FROM yauth_oauth_states WHERE state = $1", state)
                    .execute(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
            }

            match row {
                Some(r) => {
                    if r.expires_at.naive_utc() < chrono::Utc::now().naive_utc() {
                        Ok(None)
                    } else {
                        Ok(Some(domain::OauthState {
                            state: r.state,
                            provider: r.provider,
                            redirect_url: r.redirect_url,
                            expires_at: r.expires_at.naive_utc(),
                            created_at: r.created_at.naive_utc(),
                        }))
                    }
                }
                None => Ok(None),
            }
        })
    }
}
