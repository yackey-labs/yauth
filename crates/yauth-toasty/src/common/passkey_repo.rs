use toasty::Db;
use uuid::Uuid;

use crate::entities::YauthPasskey;
use crate::helpers::*;
use yauth::repo::{PasskeyRepository, RepoFuture, sealed};
use yauth_entity as domain;

pub(crate) struct ToastyPasskeyRepo {
    db: Db,
}

impl ToastyPasskeyRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyPasskeyRepo {}

impl PasskeyRepository for ToastyPasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthPasskey> = YauthPasskey::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows.into_iter().map(passkey_to_domain).collect())
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::WebauthnCredential>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthPasskey::get_by_id(&mut db, &id).await {
                Ok(row) if row.user_id == user_id => Ok(Some(passkey_to_domain(row))),
                _ => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewWebauthnCredential) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthPasskey {
                id: input.id,
                user_id: input.user_id,
                name: input.name,
                aaguid: input.aaguid,
                device_name: input.device_name,
                credential: input.credential,
                created_at: chrono_to_jiff(input.created_at),
                last_used_at: Option::<jiff::Timestamp>::None,
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthPasskey> = YauthPasskey::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            let now_ts = jiff::Timestamp::now();
            for mut row in rows {
                row.update()
                    .last_used_at(Some(now_ts))
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
            if let Ok(row) = YauthPasskey::get_by_id(&mut db, &id).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }
}

fn passkey_to_domain(m: YauthPasskey) -> domain::WebauthnCredential {
    domain::WebauthnCredential {
        id: m.id,
        user_id: m.user_id,
        name: m.name,
        aaguid: m.aaguid,
        device_name: m.device_name,
        credential: m.credential,
        created_at: jiff_to_chrono(m.created_at),
        last_used_at: opt_jiff_to_chrono(m.last_used_at),
    }
}
