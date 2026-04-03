use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use crate::domain;
use crate::repo::{
    AuthorizationCodeRepository, ConsentRepository, DeviceCodeRepository, Oauth2ClientRepository,
    RepoFuture, sealed,
};

// ──────────────────────────────────────────────
// OAuth2 Client Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryOauth2ClientRepo {
    clients: Arc<RwLock<HashMap<Uuid, domain::Oauth2Client>>>,
}

impl InMemoryOauth2ClientRepo {
    pub(crate) fn new(clients: Arc<RwLock<HashMap<Uuid, domain::Oauth2Client>>>) -> Self {
        Self { clients }
    }
}

impl sealed::Sealed for InMemoryOauth2ClientRepo {}

impl Oauth2ClientRepository for InMemoryOauth2ClientRepo {
    fn find_by_client_id(&self, client_id: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let map = self.clients.read().unwrap();
            Ok(map.values().find(|c| c.client_id == client_id).cloned())
        })
    }

    fn create(&self, input: domain::NewOauth2Client) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let client = domain::Oauth2Client {
                id: input.id,
                client_id: input.client_id,
                client_secret_hash: input.client_secret_hash,
                redirect_uris: input.redirect_uris,
                client_name: input.client_name,
                grant_types: input.grant_types,
                scopes: input.scopes,
                is_public: input.is_public,
                created_at: input.created_at,
            };
            let mut map = self.clients.write().unwrap();
            map.insert(client.id, client);
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Authorization Code Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryAuthorizationCodeRepo {
    codes: Arc<RwLock<HashMap<Uuid, domain::AuthorizationCode>>>,
}

impl InMemoryAuthorizationCodeRepo {
    pub(crate) fn new(codes: Arc<RwLock<HashMap<Uuid, domain::AuthorizationCode>>>) -> Self {
        Self { codes }
    }
}

impl sealed::Sealed for InMemoryAuthorizationCodeRepo {}

impl AuthorizationCodeRepository for InMemoryAuthorizationCodeRepo {
    fn find_by_code_hash(
        &self,
        code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::AuthorizationCode>> {
        let code_hash = code_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let map = self.codes.read().unwrap();
            // Return None if expired or already used
            Ok(map
                .values()
                .find(|c| c.code_hash == code_hash && !c.used && c.expires_at > now)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewAuthorizationCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let code = domain::AuthorizationCode {
                id: input.id,
                code_hash: input.code_hash,
                client_id: input.client_id,
                user_id: input.user_id,
                scopes: input.scopes,
                redirect_uri: input.redirect_uri,
                code_challenge: input.code_challenge,
                code_challenge_method: input.code_challenge_method,
                expires_at: input.expires_at,
                used: input.used,
                nonce: input.nonce,
                created_at: input.created_at,
            };
            let mut map = self.codes.write().unwrap();
            map.insert(code.id, code);
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.codes.write().unwrap();
            if let Some(code) = map.get_mut(&id) {
                code.used = true;
            }
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Consent Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryConsentRepo {
    consents: Arc<RwLock<HashMap<Uuid, domain::Consent>>>,
}

impl InMemoryConsentRepo {
    pub(crate) fn new(consents: Arc<RwLock<HashMap<Uuid, domain::Consent>>>) -> Self {
        Self { consents }
    }
}

impl sealed::Sealed for InMemoryConsentRepo {}

impl ConsentRepository for InMemoryConsentRepo {
    fn find_by_user_and_client(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> RepoFuture<'_, Option<domain::Consent>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let map = self.consents.read().unwrap();
            Ok(map
                .values()
                .find(|c| c.user_id == user_id && c.client_id == client_id)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewConsent) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let consent = domain::Consent {
                id: input.id,
                user_id: input.user_id,
                client_id: input.client_id,
                scopes: input.scopes,
                created_at: input.created_at,
            };
            let mut map = self.consents.write().unwrap();
            map.insert(consent.id, consent);
            Ok(())
        })
    }

    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.consents.write().unwrap();
            if let Some(consent) = map.get_mut(&id) {
                consent.scopes = scopes;
            }
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Device Code Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryDeviceCodeRepo {
    codes: Arc<RwLock<HashMap<Uuid, domain::DeviceCode>>>,
}

impl InMemoryDeviceCodeRepo {
    pub(crate) fn new(codes: Arc<RwLock<HashMap<Uuid, domain::DeviceCode>>>) -> Self {
        Self { codes }
    }
}

impl sealed::Sealed for InMemoryDeviceCodeRepo {}

impl DeviceCodeRepository for InMemoryDeviceCodeRepo {
    fn find_by_user_code_pending(
        &self,
        user_code: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let user_code = user_code.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let map = self.codes.read().unwrap();
            Ok(map
                .values()
                .find(|c| c.user_code == user_code && c.status == "pending" && c.expires_at > now)
                .cloned())
        })
    }

    fn find_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let device_code_hash = device_code_hash.to_string();
        Box::pin(async move {
            let map = self.codes.read().unwrap();
            Ok(map
                .values()
                .find(|c| c.device_code_hash == device_code_hash)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewDeviceCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let code = domain::DeviceCode {
                id: input.id,
                device_code_hash: input.device_code_hash,
                user_code: input.user_code,
                client_id: input.client_id,
                scopes: input.scopes,
                user_id: input.user_id,
                status: input.status,
                interval: input.interval,
                expires_at: input.expires_at,
                last_polled_at: None,
                created_at: input.created_at,
            };
            let mut map = self.codes.write().unwrap();
            map.insert(code.id, code);
            Ok(())
        })
    }

    fn update_status(&self, id: Uuid, status: &str, user_id: Option<Uuid>) -> RepoFuture<'_, ()> {
        let status = status.to_string();
        Box::pin(async move {
            let mut map = self.codes.write().unwrap();
            if let Some(code) = map.get_mut(&id) {
                code.status = status;
                if let Some(uid) = user_id {
                    code.user_id = Some(uid);
                }
            }
            Ok(())
        })
    }

    fn update_last_polled(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let mut map = self.codes.write().unwrap();
            if let Some(code) = map.get_mut(&id) {
                code.last_polled_at = Some(now);
            }
            Ok(())
        })
    }

    fn update_interval(&self, id: Uuid, interval: i32) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.codes.write().unwrap();
            if let Some(code) = map.get_mut(&id) {
                code.interval = interval;
            }
            Ok(())
        })
    }
}
