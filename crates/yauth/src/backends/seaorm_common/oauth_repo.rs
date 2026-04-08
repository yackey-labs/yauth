use chrono::{NaiveDateTime, Utc};
use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, ConnectionTrait, Set, Statement};
use uuid::Uuid;

use super::entities::{oauth_accounts, oauth_states};
use super::sea_err;
use crate::domain;
use crate::repo::{OauthAccountRepository, OauthStateRepository, RepoFuture, sealed};

// ── OauthAccountRepository ──

pub(crate) struct SeaOrmOauthAccountRepo {
    db: DatabaseConnection,
}

impl SeaOrmOauthAccountRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmOauthAccountRepo {}

impl OauthAccountRepository for SeaOrmOauthAccountRepo {
    fn find_by_provider_and_provider_user_id(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        let provider_user_id = provider_user_id.to_string();
        Box::pin(async move {
            let row = oauth_accounts::Entity::find()
                .filter(oauth_accounts::Column::Provider.eq(&provider))
                .filter(oauth_accounts::Column::ProviderUserId.eq(&provider_user_id))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::OauthAccount>> {
        Box::pin(async move {
            let rows = oauth_accounts::Entity::find()
                .filter(oauth_accounts::Column::UserId.eq(user_id))
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows.into_iter().map(|m| m.into_domain()).collect())
        })
    }

    fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> RepoFuture<'_, Option<domain::OauthAccount>> {
        let provider = provider.to_string();
        Box::pin(async move {
            let row = oauth_accounts::Entity::find()
                .filter(oauth_accounts::Column::UserId.eq(user_id))
                .filter(oauth_accounts::Column::Provider.eq(&provider))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewOauthAccount) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = oauth_accounts::ActiveModel {
                id: Set(input.id),
                user_id: Set(input.user_id),
                provider: Set(input.provider),
                provider_user_id: Set(input.provider_user_id),
                access_token_enc: Set(input.access_token_enc),
                refresh_token_enc: Set(input.refresh_token_enc),
                created_at: Set(super::to_tz(input.created_at)),
                expires_at: Set(super::opt_to_tz(input.expires_at)),
                updated_at: Set(super::to_tz(input.updated_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
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
            oauth_accounts::Entity::update_many()
                .col_expr(
                    oauth_accounts::Column::AccessTokenEnc,
                    Expr::value(access_token_enc),
                )
                .col_expr(
                    oauth_accounts::Column::RefreshTokenEnc,
                    Expr::value(refresh_token_enc),
                )
                .col_expr(
                    oauth_accounts::Column::ExpiresAt,
                    Expr::value(super::opt_to_tz(expires_at)),
                )
                .col_expr(
                    oauth_accounts::Column::UpdatedAt,
                    Expr::value(Utc::now().fixed_offset()),
                )
                .filter(oauth_accounts::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            oauth_accounts::Entity::delete_many()
                .filter(oauth_accounts::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}

// ── OauthStateRepository ──

pub(crate) struct SeaOrmOauthStateRepo {
    db: DatabaseConnection,
}

impl SeaOrmOauthStateRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmOauthStateRepo {}

impl OauthStateRepository for SeaOrmOauthStateRepo {
    fn create(&self, input: domain::NewOauthState) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = oauth_states::ActiveModel {
                state: Set(input.state),
                provider: Set(input.provider),
                redirect_url: Set(input.redirect_url),
                expires_at: Set(super::to_tz(input.expires_at)),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::OauthState>> {
        let state = state.to_string();
        Box::pin(async move {
            let stmt = Statement::from_sql_and_values(
                self.db.get_database_backend(),
                r#"DELETE FROM yauth_oauth_states WHERE state = $1 AND expires_at > now() RETURNING *"#,
                [state.into()],
            );
            let row = self.db.query_one_raw(stmt).await.map_err(sea_err)?;
            match row {
                Some(r) => {
                    let domain = domain::OauthState {
                        state: r.try_get("", "state").map_err(sea_err)?,
                        provider: r.try_get("", "provider").map_err(sea_err)?,
                        redirect_url: r.try_get("", "redirect_url").map_err(sea_err)?,
                        expires_at: r
                            .try_get::<chrono::DateTime<chrono::Utc>>("", "expires_at")
                            .map_err(sea_err)?
                            .naive_utc(),
                        created_at: r
                            .try_get::<chrono::DateTime<chrono::Utc>>("", "created_at")
                            .map_err(sea_err)?
                            .naive_utc(),
                    };
                    Ok(Some(domain))
                }
                None => Ok(None),
            }
        })
    }
}
