use super::{RepoFuture, sealed};
use crate::domain;
use chrono::NaiveDateTime;
use uuid::Uuid;

/// Repository for OAuth account links.
///
/// # Invariants
///
/// - **Uniqueness**: (provider, provider_user_id) pair must be unique.
pub trait OauthAccountRepository: sealed::Sealed + Send + Sync {
    fn find_by_provider_and_provider_user_id(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>>;

    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>>;

    fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>>;

    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()>;

    fn update_tokens(
        &self,
        id: Uuid,
        access_token_enc: Option<&str>,
        refresh_token_enc: Option<&str>,
        expires_at: Option<NaiveDateTime>,
    ) -> RepoFuture<'_, ()>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;
}

/// Repository for OAuth CSRF state tokens.
///
/// # Invariants
///
/// - **Expiration on read**: `find_and_delete` MUST return `None` if expired.
pub trait OauthStateRepository: sealed::Sealed + Send + Sync {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()>;

    /// Find by state token and delete it in one operation (consume-once).
    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>>;
}
