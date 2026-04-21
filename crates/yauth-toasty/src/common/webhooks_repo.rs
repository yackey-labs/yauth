use toasty::Db;
use uuid::Uuid;

use crate::entities::{YauthWebhook, YauthWebhookDelivery};
use crate::helpers::*;
use yauth::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};
use yauth_entity as domain;

// -- WebhookRepository --

pub(crate) struct ToastyWebhookRepo {
    db: Db,
}

impl ToastyWebhookRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyWebhookRepo {}

impl WebhookRepository for ToastyWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthWebhook::get_by_id(&mut db, &id).await {
                Ok(row) => Ok(Some(webhook_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let all: Vec<YauthWebhook> = YauthWebhook::all()
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(all
                .into_iter()
                .filter(|w| w.active)
                .map(webhook_to_domain)
                .collect())
        })
    }

    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let all: Vec<YauthWebhook> = YauthWebhook::all()
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(all.into_iter().map(webhook_to_domain).collect())
        })
    }

    fn create(&self, input: domain::NewWebhook) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthWebhook {
                id: input.id,
                url: input.url,
                secret: input.secret,
                events: serde_json::from_value(input.events).unwrap_or_default(),
                active: input.active,
                created_at: chrono_to_jiff(input.created_at),
                updated_at: chrono_to_jiff(input.updated_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let mut row = YauthWebhook::get_by_id(&mut db, &id)
                .await
                .map_err(toasty_err)?;

            let mut update = row.update();

            if let Some(url) = changes.url {
                update = update.url(url);
            }
            if let Some(secret) = changes.secret {
                update = update.secret(secret);
            }
            if let Some(events) = changes.events {
                update = update.events(serde_json::from_value(events).unwrap_or_default());
            }
            if let Some(active) = changes.active {
                update = update.active(active);
            }
            if let Some(updated_at) = changes.updated_at {
                update = update.updated_at(chrono_to_jiff(updated_at));
            }

            update.exec(&mut db).await.map_err(toasty_err)?;

            let updated = YauthWebhook::get_by_id(&mut db, &id)
                .await
                .map_err(toasty_err)?;
            Ok(webhook_to_domain(updated))
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(row) = YauthWebhook::get_by_id(&mut db, &id).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }
}

// -- WebhookDeliveryRepository --

pub(crate) struct ToastyWebhookDeliveryRepo {
    db: Db,
}

impl ToastyWebhookDeliveryRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyWebhookDeliveryRepo {}

impl WebhookDeliveryRepository for ToastyWebhookDeliveryRepo {
    fn find_by_webhook_id(
        &self,
        webhook_id: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthWebhookDelivery> =
                YauthWebhookDelivery::filter_by_webhook_id(webhook_id)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            Ok(rows
                .into_iter()
                .take(limit as usize)
                .map(webhook_delivery_to_domain)
                .collect())
        })
    }

    fn create(&self, input: domain::NewWebhookDelivery) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthWebhookDelivery {
                id: input.id,
                webhook_id: input.webhook_id,
                event_type: input.event_type,
                payload: input.payload,
                status_code: input.status_code.map(|c| c as i32),
                response_body: input.response_body,
                success: input.success,
                attempt: input.attempt,
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }
}

fn webhook_to_domain(m: YauthWebhook) -> domain::Webhook {
    domain::Webhook {
        id: m.id,
        url: m.url,
        secret: m.secret,
        events: serde_json::to_value(m.events).unwrap_or_default(),
        active: m.active,
        created_at: jiff_to_chrono(m.created_at),
        updated_at: jiff_to_chrono(m.updated_at),
    }
}

fn webhook_delivery_to_domain(m: YauthWebhookDelivery) -> domain::WebhookDelivery {
    domain::WebhookDelivery {
        id: m.id,
        webhook_id: m.webhook_id,
        event_type: m.event_type,
        payload: m.payload,
        status_code: m.status_code.map(|c| c as i16),
        response_body: m.response_body,
        success: m.success,
        attempt: m.attempt,
        created_at: jiff_to_chrono(m.created_at),
    }
}
