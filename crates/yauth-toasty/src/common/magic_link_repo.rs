use toasty::Db;
use uuid::Uuid;

use crate::entities::YauthMagicLink;
use crate::helpers::{chrono_to_jiff, jiff_to_chrono, toasty_err};
use yauth::repo::{MagicLinkRepository, RepoFuture, sealed};
use yauth_entity as domain;

pub(crate) struct ToastyMagicLinkRepo {
    db: Db,
}

impl ToastyMagicLinkRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyMagicLinkRepo {}

impl MagicLinkRepository for ToastyMagicLinkRepo {
    fn find_unused_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::MagicLink>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthMagicLink::filter_by_token_hash(&token_hash)
                .get(&mut db)
                .await
            {
                Ok(row) => {
                    if row.expires_at < jiff::Timestamp::now() || row.used {
                        Ok(None)
                    } else {
                        Ok(Some(magic_link_to_domain(row)))
                    }
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthMagicLink {
                id: input.id,
                email: input.email,
                token_hash: input.token_hash,
                expires_at: chrono_to_jiff(input.expires_at),
                used: false,
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthMagicLink::get_by_id(&mut db, &id).await {
                row.update()
                    .used(true)
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
            if let Ok(row) = YauthMagicLink::get_by_id(&mut db, &id).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }

    fn delete_unused_for_email(&self, email: &str) -> RepoFuture<'_, ()> {
        let email = email.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthMagicLink> = YauthMagicLink::filter_by_email(&email)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            for row in rows {
                if !row.used {
                    let _ = row.delete().exec(&mut db).await;
                }
            }
            Ok(())
        })
    }
}

fn magic_link_to_domain(m: YauthMagicLink) -> domain::MagicLink {
    domain::MagicLink {
        id: m.id,
        email: m.email,
        token_hash: m.token_hash,
        expires_at: jiff_to_chrono(m.expires_at),
        used: m.used,
        created_at: jiff_to_chrono(m.created_at),
    }
}
