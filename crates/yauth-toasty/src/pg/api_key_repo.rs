use chrono::Utc;
use toasty::Db;
use uuid::Uuid;

use crate::entities::YauthApiKey;
use crate::helpers::*;
use yauth::repo::{ApiKeyRepository, RepoFuture, sealed};
use yauth_entity as domain;

pub(crate) struct ToastyApiKeyRepo {
    db: Db,
}

impl ToastyApiKeyRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyApiKeyRepo {}

impl ApiKeyRepository for ToastyApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthApiKey::filter_by_key_prefix(&prefix)
                .get(&mut db)
                .await
            {
                Ok(row) => {
                    let now = Utc::now().naive_utc();
                    if let Some(ref exp) = row.expires_at
                        && str_to_dt(exp) < now
                    {
                        return Ok(None);
                    }
                    Ok(Some(api_key_to_domain(row)))
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthApiKey::get_by_id(&mut db, &id).await {
                Ok(row) if row.user_id == user_id => Ok(Some(api_key_to_domain(row))),
                _ => Ok(None),
            }
        })
    }

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthApiKey> = YauthApiKey::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows.into_iter().map(api_key_to_domain).collect())
        })
    }

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthApiKey {
                id: input.id,
                user_id: input.user_id,
                key_prefix: input.key_prefix,
                key_hash: input.key_hash,
                name: input.name,
                scopes: opt_json_to_str(input.scopes.as_ref()),
                last_used_at: Option::<String>::None,
                expires_at: opt_dt_to_str(input.expires_at),
                created_at: dt_to_str(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(row) = YauthApiKey::get_by_id(&mut db, &id).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthApiKey::get_by_id(&mut db, &id).await {
                row.update()
                    .last_used_at(Some(dt_to_str(Utc::now().naive_utc())))
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }
}

fn api_key_to_domain(m: YauthApiKey) -> domain::ApiKey {
    domain::ApiKey {
        id: m.id,
        user_id: m.user_id,
        key_prefix: m.key_prefix,
        key_hash: m.key_hash,
        name: m.name,
        scopes: opt_str_to_json(m.scopes.as_deref()),
        last_used_at: opt_str_to_dt(m.last_used_at.as_deref()),
        expires_at: opt_str_to_dt(m.expires_at.as_deref()),
        created_at: str_to_dt(&m.created_at),
    }
}
