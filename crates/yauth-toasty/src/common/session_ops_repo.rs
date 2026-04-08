use chrono::Utc;
use toasty::Db;
use uuid::Uuid;

use crate::entities::YauthSession;
use crate::helpers::*;
use yauth::repo::{RepoFuture, SessionOpsRepository, sealed};
use yauth_entity as domain;

pub(crate) struct ToastySessionOpsRepo {
    db: Db,
}

impl ToastySessionOpsRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastySessionOpsRepo {}

impl SessionOpsRepository for ToastySessionOpsRepo {
    fn create_session(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: std::time::Duration,
    ) -> RepoFuture<'_, Uuid> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let session_id = Uuid::now_v7();
            let now = Utc::now().naive_utc();
            let expires_at =
                now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7));

            toasty::create!(YauthSession {
                id: session_id,
                user_id: user_id,
                token_hash: token_hash,
                ip_address: ip_address,
                user_agent: user_agent,
                expires_at: dt_to_str(expires_at),
                created_at: dt_to_str(now),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;

            Ok(session_id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let session = match YauthSession::filter_by_token_hash(&token_hash)
                .get(&mut db)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };

            let now = Utc::now().naive_utc();
            let expires = str_to_dt(&session.expires_at);
            if expires < now {
                // Expired -- clean up (best-effort)
                let _ = session.delete().exec(&mut db).await;
                return Ok(None);
            }

            Ok(Some(domain::StoredSession {
                id: session.id,
                user_id: session.user_id,
                ip_address: session.ip_address,
                user_agent: session.user_agent,
                expires_at: expires,
                created_at: str_to_dt(&session.created_at),
            }))
        })
    }

    fn delete_session(&self, token_hash: &str) -> RepoFuture<'_, bool> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthSession::filter_by_token_hash(&token_hash)
                .get(&mut db)
                .await
            {
                Ok(session) => {
                    session.delete().exec(&mut db).await.map_err(toasty_err)?;
                    Ok(true)
                }
                Err(_) => Ok(false),
            }
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let sessions: Vec<YauthSession> = YauthSession::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            let count = sessions.len() as u64;
            YauthSession::filter_by_user_id(user_id)
                .delete()
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(count)
        })
    }

    fn delete_other_sessions_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> RepoFuture<'_, u64> {
        let keep_hash = keep_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let sessions: Vec<YauthSession> = YauthSession::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            let mut count = 0u64;
            for session in sessions {
                if session.token_hash != keep_hash {
                    let _ = session.delete().exec(&mut db).await;
                    count += 1;
                }
            }
            Ok(count)
        })
    }
}
