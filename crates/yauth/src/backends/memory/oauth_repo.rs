use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{NaiveDateTime, Utc};
use uuid::Uuid;

use crate::domain;
use crate::repo::{OauthAccountRepository, OauthStateRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// OAuth Account Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryOauthAccountRepo {
    accounts: Arc<RwLock<HashMap<Uuid, domain::OauthAccount>>>,
}

impl InMemoryOauthAccountRepo {
    pub(crate) fn new(accounts: Arc<RwLock<HashMap<Uuid, domain::OauthAccount>>>) -> Self {
        Self { accounts }
    }
}

impl sealed::Sealed for InMemoryOauthAccountRepo {}

impl OauthAccountRepository for InMemoryOauthAccountRepo {
    fn find_by_provider_and_provider_user_id(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        let provider_user_id = provider_user_id.to_string();
        Box::pin(async move {
            let map = self.accounts.read().unwrap();
            Ok(map
                .values()
                .find(|a| a.provider == provider && a.provider_user_id == provider_user_id)
                .cloned())
        })
    }

    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>> {
        Box::pin(async move {
            let map = self.accounts.read().unwrap();
            Ok(map
                .values()
                .filter(|a| a.user_id == user_id)
                .cloned()
                .collect())
        })
    }

    fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        Box::pin(async move {
            let map = self.accounts.read().unwrap();
            Ok(map
                .values()
                .find(|a| a.user_id == user_id && a.provider == provider)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.accounts.write().unwrap();
            // Enforce (provider, provider_user_id) uniqueness
            if map.values().any(|a| {
                a.provider == input.provider && a.provider_user_id == input.provider_user_id
            }) {
                return Err(RepoError::Conflict(
                    "duplicate oauth account (provider, provider_user_id)".to_string(),
                ));
            }

            let account = domain::OauthAccount {
                id: input.id,
                user_id: input.user_id,
                provider: input.provider,
                provider_user_id: input.provider_user_id,
                access_token_enc: input.access_token_enc,
                refresh_token_enc: input.refresh_token_enc,
                created_at: input.created_at,
                expires_at: input.expires_at,
                updated_at: input.updated_at,
            };
            map.insert(account.id, account);
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
            let mut map = self.accounts.write().unwrap();
            if let Some(account) = map.get_mut(&id) {
                if let Some(at) = access_token_enc {
                    account.access_token_enc = Some(at);
                }
                if let Some(rt) = refresh_token_enc {
                    account.refresh_token_enc = Some(rt);
                }
                if let Some(ea) = expires_at {
                    account.expires_at = Some(ea);
                }
                account.updated_at = Utc::now().naive_utc();
            }
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.accounts.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// OAuth State Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryOauthStateRepo {
    states: Arc<RwLock<HashMap<String, domain::OauthState>>>,
}

impl InMemoryOauthStateRepo {
    pub(crate) fn new(states: Arc<RwLock<HashMap<String, domain::OauthState>>>) -> Self {
        Self { states }
    }
}

impl sealed::Sealed for InMemoryOauthStateRepo {}

impl OauthStateRepository for InMemoryOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let state = domain::OauthState {
                state: input.state.clone(),
                provider: input.provider,
                redirect_url: input.redirect_url,
                expires_at: input.expires_at,
                created_at: input.created_at,
            };
            let mut map = self.states.write().unwrap();
            map.insert(input.state, state);
            Ok(())
        })
    }

    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>> {
        let state = state.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let mut map = self.states.write().unwrap();
            let entry = map.remove(&state);
            // Return None if expired
            Ok(entry.filter(|s| s.expires_at > now))
        })
    }
}
