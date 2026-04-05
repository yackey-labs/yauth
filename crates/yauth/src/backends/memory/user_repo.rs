use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use super::Storage;
use crate::domain;
use crate::repo::{
    AuditLogRepository, RepoError, RepoFuture, SessionRepository, UserRepository, sealed,
};

// ──────────────────────────────────────────────
// User Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryUserRepo {
    storage: Storage,
}

impl InMemoryUserRepo {
    pub(crate) fn new(storage: Storage) -> Self {
        Self { storage }
    }
}

impl sealed::Sealed for InMemoryUserRepo {}

impl UserRepository for InMemoryUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let map = self.storage.users.read().unwrap();
            Ok(map.get(&id).cloned())
        })
    }

    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>> {
        let email_lower = email.to_lowercase();
        Box::pin(async move {
            let map = self.storage.users.read().unwrap();
            Ok(map
                .values()
                .find(|u| u.email.to_lowercase() == email_lower)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut map = self.storage.users.write().unwrap();
            let email_lower = input.email.to_lowercase();

            // Check case-insensitive email uniqueness
            if map.values().any(|u| u.email.to_lowercase() == email_lower) {
                return Err(RepoError::Conflict(
                    "duplicate key value violates unique constraint \"yauth_users_email_key\""
                        .to_string(),
                ));
            }

            let user = domain::User {
                id: input.id,
                email: input.email,
                display_name: input.display_name,
                email_verified: input.email_verified,
                role: input.role,
                banned: input.banned,
                banned_reason: input.banned_reason,
                banned_until: input.banned_until,
                created_at: input.created_at,
                updated_at: input.updated_at,
            };
            map.insert(user.id, user.clone());
            Ok(user)
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut map = self.storage.users.write().unwrap();
            let user = map.get_mut(&id).ok_or(RepoError::NotFound)?;

            if let Some(email) = changes.email {
                user.email = email;
            }
            if let Some(display_name) = changes.display_name {
                user.display_name = display_name;
            }
            if let Some(email_verified) = changes.email_verified {
                user.email_verified = email_verified;
            }
            if let Some(role) = changes.role {
                user.role = role;
            }
            if let Some(banned) = changes.banned {
                user.banned = banned;
            }
            if let Some(banned_reason) = changes.banned_reason {
                user.banned_reason = banned_reason;
            }
            if let Some(banned_until) = changes.banned_until {
                user.banned_until = banned_until;
            }
            if let Some(updated_at) = changes.updated_at {
                user.updated_at = updated_at;
            } else {
                user.updated_at = Utc::now().naive_utc();
            }

            Ok(user.clone())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Look up user email before removal (needed for magic link cascade)
            #[cfg(feature = "magic-link")]
            let user_email = {
                let map = self.storage.users.read().unwrap();
                map.get(&id).map(|u| u.email.to_lowercase())
            };

            // Remove the user
            {
                let mut map = self.storage.users.write().unwrap();
                map.remove(&id);
            }

            // Cascade: sessions (persistent session table)
            {
                let mut map = self.storage.sessions.write().unwrap();
                map.retain(|_, s| s.user_id != id);
            }

            // Cascade: session_ops (ephemeral session store)
            {
                let mut map = self.storage.session_ops.write().await;
                map.retain(|_, s| s.user_id != id);
            }

            // Cascade: email-password entities
            #[cfg(feature = "email-password")]
            {
                {
                    let mut map = self.storage.passwords.write().unwrap();
                    map.remove(&id);
                }
                {
                    let mut map = self.storage.email_verifications.write().unwrap();
                    map.retain(|_, v| v.user_id != id);
                }
                {
                    let mut map = self.storage.password_resets.write().unwrap();
                    map.retain(|_, r| r.user_id != id);
                }
            }

            // Cascade: passkeys
            #[cfg(feature = "passkey")]
            {
                let mut map = self.storage.passkeys.write().unwrap();
                map.retain(|_, p| p.user_id != id);
            }

            // Cascade: MFA
            #[cfg(feature = "mfa")]
            {
                {
                    let mut map = self.storage.totp_secrets.write().unwrap();
                    map.retain(|_, t| t.user_id != id);
                }
                {
                    let mut map = self.storage.backup_codes.write().unwrap();
                    map.retain(|_, b| b.user_id != id);
                }
            }

            // Cascade: OAuth accounts
            #[cfg(feature = "oauth")]
            {
                let mut map = self.storage.oauth_accounts.write().unwrap();
                map.retain(|_, o| o.user_id != id);
            }

            // Cascade: API keys
            #[cfg(feature = "api-key")]
            {
                let mut map = self.storage.api_keys.write().unwrap();
                map.retain(|_, k| k.user_id != id);
            }

            // Cascade: refresh tokens
            #[cfg(feature = "bearer")]
            {
                let mut map = self.storage.refresh_tokens.write().unwrap();
                map.retain(|_, t| t.user_id != id);
            }

            // Cascade: account locks + unlock tokens
            #[cfg(feature = "account-lockout")]
            {
                {
                    let mut map = self.storage.account_locks.write().unwrap();
                    map.retain(|_, l| l.user_id != id);
                }
                {
                    let mut map = self.storage.unlock_tokens.write().unwrap();
                    map.retain(|_, t| t.user_id != id);
                }
            }

            // Cascade: magic links (keyed by email, not user_id)
            #[cfg(feature = "magic-link")]
            if let Some(ref email) = user_email {
                let mut map = self.storage.magic_links.write().unwrap();
                map.retain(|_, l| l.email.to_lowercase() != *email);
            }

            Ok(())
        })
    }

    fn any_exists(&self) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let map = self.storage.users.read().unwrap();
            Ok(!map.is_empty())
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
            let map = self.storage.users.read().unwrap();
            let mut users: Vec<domain::User> = if let Some(ref pattern) = search {
                map.values()
                    .filter(|u| u.email.to_lowercase().contains(pattern))
                    .cloned()
                    .collect()
            } else {
                map.values().cloned().collect()
            };

            // Sort by created_at descending (matching Diesel impl)
            users.sort_by(|a, b| b.created_at.cmp(&a.created_at));

            let total = users.len() as i64;
            let offset = offset as usize;
            let limit = limit as usize;
            let page = users.into_iter().skip(offset).take(limit).collect();

            Ok((page, total))
        })
    }
}

// ──────────────────────────────────────────────
// Session Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemorySessionRepo {
    sessions: Arc<RwLock<HashMap<Uuid, domain::Session>>>,
}

impl InMemorySessionRepo {
    pub(crate) fn new(sessions: Arc<RwLock<HashMap<Uuid, domain::Session>>>) -> Self {
        Self { sessions }
    }
}

impl sealed::Sealed for InMemorySessionRepo {}

impl SessionRepository for InMemorySessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let map = self.sessions.read().unwrap();
            Ok(map.get(&id).cloned())
        })
    }

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let session = domain::Session {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                ip_address: input.ip_address,
                user_agent: input.user_agent,
                expires_at: input.expires_at,
                created_at: input.created_at,
            };
            let mut map = self.sessions.write().unwrap();
            map.insert(session.id, session);
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.sessions.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn list(&self, limit: i64, offset: i64) -> RepoFuture<'_, (Vec<domain::Session>, i64)> {
        Box::pin(async move {
            let map = self.sessions.read().unwrap();
            let mut sessions: Vec<domain::Session> = map.values().cloned().collect();
            sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            let total = sessions.len() as i64;
            let page = sessions
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            Ok((page, total))
        })
    }
}

// ──────────────────────────────────────────────
// Audit Log Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryAuditLogRepo {
    logs: Arc<RwLock<Vec<domain::NewAuditLog>>>,
}

impl InMemoryAuditLogRepo {
    pub(crate) fn new(logs: Arc<RwLock<Vec<domain::NewAuditLog>>>) -> Self {
        Self { logs }
    }
}

impl sealed::Sealed for InMemoryAuditLogRepo {}

const AUDIT_LOG_MAX: usize = 10_000;
const AUDIT_LOG_EVICT: usize = 1_000;

impl AuditLogRepository for InMemoryAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut logs = self.logs.write().unwrap();
            if logs.len() >= AUDIT_LOG_MAX {
                logs.drain(..AUDIT_LOG_EVICT);
            }
            logs.push(input);
            Ok(())
        })
    }
}
