use toasty::Db;
use uuid::Uuid;

use crate::entities::{YauthSession, YauthUser};
use crate::helpers::*;
use yauth::repo::{RepoFuture, SessionRepository, UserRepository, sealed};
use yauth_entity as domain;

// ── UserRepository ──

pub(crate) struct ToastyUserRepo {
    db: Db,
}

impl ToastyUserRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyUserRepo {}

impl UserRepository for ToastyUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthUser::get_by_id(&mut db, &id).await {
                Ok(row) => Ok(Some(user_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>> {
        let email = email.to_lowercase();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthUser::filter_by_email(&email).get(&mut db).await {
                Ok(row) => Ok(Some(user_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let row = toasty::create!(YauthUser {
                id: input.id,
                email: input.email.to_lowercase(),
                display_name: input.display_name,
                email_verified: input.email_verified,
                role: input.role,
                banned: input.banned,
                banned_reason: input.banned_reason,
                banned_until: opt_dt_to_str(input.banned_until),
                created_at: dt_to_str(input.created_at),
                updated_at: dt_to_str(input.updated_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_conflict)?;
            Ok(user_to_domain(row))
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let mut user = YauthUser::get_by_id(&mut db, &id)
                .await
                .map_err(toasty_err)?;

            let mut update = user.update();

            if let Some(email) = changes.email {
                update = update.email(email.to_lowercase());
            }
            if let Some(display_name) = changes.display_name {
                update = update.display_name(display_name);
            }
            if let Some(email_verified) = changes.email_verified {
                update = update.email_verified(email_verified);
            }
            if let Some(role) = changes.role {
                update = update.role(role);
            }
            if let Some(banned) = changes.banned {
                update = update.banned(banned);
            }
            if let Some(banned_reason) = changes.banned_reason {
                update = update.banned_reason(banned_reason);
            }
            if let Some(banned_until) = changes.banned_until {
                update = update.banned_until(opt_dt_to_str(banned_until));
            }
            if let Some(updated_at) = changes.updated_at {
                update = update.updated_at(dt_to_str(updated_at));
            }

            update.exec(&mut db).await.map_err(toasty_err)?;

            // Re-fetch to get updated values
            let updated = YauthUser::get_by_id(&mut db, &id)
                .await
                .map_err(toasty_err)?;
            Ok(user_to_domain(updated))
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(user) = YauthUser::get_by_id(&mut db, &id).await {
                user.delete().exec(&mut db).await.map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn any_exists(&self) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let users: Vec<YauthUser> = YauthUser::all().exec(&mut db).await.map_err(toasty_err)?;
            Ok(!users.is_empty())
        })
    }

    fn list(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::User>, i64)> {
        let search = search.map(|s| s.to_lowercase());
        Box::pin(async move {
            let mut db = self.db.clone();
            let all_users: Vec<YauthUser> =
                YauthUser::all().exec(&mut db).await.map_err(toasty_err)?;

            // Filter in application layer (Toasty doesn't support ILIKE)
            let filtered: Vec<domain::User> = all_users
                .into_iter()
                .filter(|u| {
                    if let Some(ref s) = search {
                        u.email.to_lowercase().contains(s)
                    } else {
                        true
                    }
                })
                .map(user_to_domain)
                .collect();

            let total = filtered.len() as i64;

            let paged = filtered
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();

            Ok((paged, total))
        })
    }
}

// ── SessionRepository ──

pub(crate) struct ToastySessionRepo {
    db: Db,
}

impl ToastySessionRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastySessionRepo {}

impl SessionRepository for ToastySessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthSession::get_by_id(&mut db, &id).await {
                Ok(row) => Ok(Some(session_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthSession {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                ip_address: input.ip_address,
                user_agent: input.user_agent,
                expires_at: dt_to_str(input.expires_at),
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
            if let Ok(session) = YauthSession::get_by_id(&mut db, &id).await {
                session.delete().exec(&mut db).await.map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn list(&self, limit: i64, offset: i64) -> RepoFuture<'_, (Vec<domain::Session>, i64)> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let all: Vec<YauthSession> = YauthSession::all()
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            let total = all.len() as i64;
            let paged: Vec<domain::Session> = all
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(session_to_domain)
                .collect();
            Ok((paged, total))
        })
    }
}

// ── Conversion helpers ──

fn user_to_domain(m: YauthUser) -> domain::User {
    domain::User {
        id: m.id,
        email: m.email,
        display_name: m.display_name,
        email_verified: m.email_verified,
        role: m.role,
        banned: m.banned,
        banned_reason: m.banned_reason,
        banned_until: opt_str_to_dt(m.banned_until.as_deref()),
        created_at: str_to_dt(&m.created_at),
        updated_at: str_to_dt(&m.updated_at),
    }
}

fn session_to_domain(m: YauthSession) -> domain::Session {
    domain::Session {
        id: m.id,
        user_id: m.user_id,
        token_hash: m.token_hash,
        ip_address: m.ip_address,
        user_agent: m.user_agent,
        expires_at: str_to_dt(&m.expires_at),
        created_at: str_to_dt(&m.created_at),
    }
}
