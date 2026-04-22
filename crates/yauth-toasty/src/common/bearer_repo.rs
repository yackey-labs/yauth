use toasty::Db;
use uuid::Uuid;

use crate::entities::YauthRefreshToken;
use crate::helpers::{chrono_to_jiff, jiff_to_chrono, toasty_err};
use yauth::repo::{RefreshTokenRepository, RepoFuture, sealed};
use yauth_entity as domain;

pub(crate) struct ToastyRefreshTokenRepo {
    db: Db,
}

impl ToastyRefreshTokenRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyRefreshTokenRepo {}

impl RefreshTokenRepository for ToastyRefreshTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::RefreshToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthRefreshToken::filter_by_token_hash(&token_hash)
                .get(&mut db)
                .await
            {
                Ok(row) => Ok(Some(refresh_token_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthRefreshToken {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                family_id: input.family_id,
                expires_at: chrono_to_jiff(input.expires_at),
                revoked: input.revoked,
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthRefreshToken::get_by_id(&mut db, &id).await {
                row.update()
                    .revoked(true)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthRefreshToken> = YauthRefreshToken::filter_by_family_id(family_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            for mut row in rows {
                if !row.revoked {
                    row.update()
                        .revoked(true)
                        .exec(&mut db)
                        .await
                        .map_err(toasty_err)?;
                }
            }
            Ok(())
        })
    }

    fn find_password_hash_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<String>> {
        Box::pin(async move {
            #[cfg(feature = "email-password")]
            {
                let mut db = self.db.clone();
                use crate::entities::YauthPassword;
                match YauthPassword::get_by_user_id(&mut db, &user_id).await {
                    Ok(row) => Ok(Some(row.password_hash)),
                    Err(_) => Ok(None),
                }
            }
            #[cfg(not(feature = "email-password"))]
            {
                let _ = user_id;
                Ok(None)
            }
        })
    }
}

fn refresh_token_to_domain(m: YauthRefreshToken) -> domain::RefreshToken {
    domain::RefreshToken {
        id: m.id,
        user_id: m.user_id,
        token_hash: m.token_hash,
        family_id: m.family_id,
        expires_at: jiff_to_chrono(m.expires_at),
        revoked: m.revoked,
        created_at: jiff_to_chrono(m.created_at),
    }
}
