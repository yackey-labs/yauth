use chrono::{NaiveDateTime, Utc};
use toasty::Db;
use uuid::Uuid;

use crate::entities::{YauthOauthAccount, YauthOauthState};
use crate::helpers::*;
use yauth::repo::{OauthAccountRepository, OauthStateRepository, RepoFuture, sealed};
use yauth_entity as domain;

// -- OauthAccountRepository --

pub(crate) struct ToastyOauthAccountRepo {
    db: Db,
}

impl ToastyOauthAccountRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyOauthAccountRepo {}

impl OauthAccountRepository for ToastyOauthAccountRepo {
    fn find_by_provider_and_provider_user_id(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        let provider_user_id = provider_user_id.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthOauthAccount> = YauthOauthAccount::filter_by_provider(&provider)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows
                .into_iter()
                .find(|r| r.provider_user_id == provider_user_id)
                .map(oauth_account_to_domain))
        })
    }

    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthOauthAccount> = YauthOauthAccount::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows.into_iter().map(oauth_account_to_domain).collect())
        })
    }

    fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthOauthAccount> = YauthOauthAccount::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows
                .into_iter()
                .find(|r| r.provider == provider)
                .map(oauth_account_to_domain))
        })
    }

    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthOauthAccount {
                id: input.id,
                user_id: input.user_id,
                provider: input.provider,
                provider_user_id: input.provider_user_id,
                access_token_enc: input.access_token_enc,
                refresh_token_enc: input.refresh_token_enc,
                created_at: chrono_to_jiff(input.created_at),
                expires_at: opt_chrono_to_jiff(input.expires_at),
                updated_at: chrono_to_jiff(input.updated_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
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
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthOauthAccount::get_by_id(&mut db, &id).await {
                row.update()
                    .access_token_enc(access_token_enc)
                    .refresh_token_enc(refresh_token_enc)
                    .expires_at(opt_chrono_to_jiff(expires_at))
                    .updated_at(chrono_to_jiff(Utc::now().naive_utc()))
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(row) = YauthOauthAccount::get_by_id(&mut db, &id).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }
}

// -- OauthStateRepository --

pub(crate) struct ToastyOauthStateRepo {
    db: Db,
}

impl ToastyOauthStateRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyOauthStateRepo {}

impl OauthStateRepository for ToastyOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthOauthState {
                state: input.state,
                provider: input.provider,
                redirect_url: input.redirect_url,
                expires_at: chrono_to_jiff(input.expires_at),
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>> {
        let state = state.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthOauthState::get_by_state(&mut db, &state).await {
                Ok(row) => {
                    let now = Utc::now().naive_utc();
                    if jiff_to_chrono(row.expires_at) < now {
                        let _ = row.delete().exec(&mut db).await;
                        return Ok(None);
                    }
                    let domain = domain::OauthState {
                        state: row.state.clone(),
                        provider: row.provider.clone(),
                        redirect_url: row.redirect_url.clone(),
                        expires_at: jiff_to_chrono(row.expires_at),
                        created_at: jiff_to_chrono(row.created_at),
                    };
                    // Delete MUST succeed before returning the state value;
                    // otherwise the same state can be replayed (CSRF bypass).
                    row.delete().exec(&mut db).await.map_err(toasty_err)?;
                    Ok(Some(domain))
                }
                Err(_) => Ok(None),
            }
        })
    }
}

fn oauth_account_to_domain(m: YauthOauthAccount) -> domain::OauthAccount {
    domain::OauthAccount {
        id: m.id,
        user_id: m.user_id,
        provider: m.provider,
        provider_user_id: m.provider_user_id,
        access_token_enc: m.access_token_enc,
        refresh_token_enc: m.refresh_token_enc,
        created_at: jiff_to_chrono(m.created_at),
        expires_at: opt_jiff_to_chrono(m.expires_at),
        updated_at: jiff_to_chrono(m.updated_at),
    }
}
