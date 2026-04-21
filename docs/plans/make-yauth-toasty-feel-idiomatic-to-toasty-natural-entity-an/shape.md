# Shape: yauth-toasty — Idiomatic Toasty Backend

> **shape_type:** `api_signature`
>
> Typed Rust function signatures for a Toasty ORM backend that feels native to Toasty's entity/query model while implementing yauth's plugin-driven `DatabaseBackend` trait.

---

## 1. Toasty Entity Models (Natural Toasty Definitions)

These live in a new crate `crates/yauth-toasty-models/` — they are the Toasty-native representations. Feature-gated per plugin to match yauth's model.

### Core Entities (always compiled)

```rust
// crates/yauth-toasty-models/src/user.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_users")]
pub struct User {
    #[key]
    pub id: String,  // UUIDv7 as TEXT (Toasty uses String keys for portability)

    #[unique]
    pub email: String,

    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<String>,  // ISO 8601 datetime
    pub created_at: String,
    pub updated_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/session.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_sessions")]
pub struct Session {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    #[unique]
    pub token_hash: String,

    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/audit_log.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_audit_log")]
pub struct AuditLog {
    #[key]
    pub id: String,

    #[index]
    pub user_id: Option<String>,

    pub event_type: String,
    pub metadata: Option<String>,  // JSON serialized
    pub ip_address: Option<String>,
    pub created_at: String,
}
```

### Email-Password Plugin (`#[cfg(feature = "email-password")]`)

```rust
// crates/yauth-toasty-models/src/password.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_passwords")]
pub struct Password {
    #[key]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    pub password_hash: String,
}
```

```rust
// crates/yauth-toasty-models/src/email_verification.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_email_verifications")]
pub struct EmailVerification {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    #[unique]
    pub token_hash: String,

    pub expires_at: String,
    pub created_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/password_reset.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_password_resets")]
pub struct PasswordReset {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    #[unique]
    pub token_hash: String,

    pub expires_at: String,
    pub used_at: Option<String>,
    pub created_at: String,
}
```

### Passkey Plugin (`#[cfg(feature = "passkey")]`)

```rust
// crates/yauth-toasty-models/src/webauthn_credential.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_webauthn_credentials")]
pub struct WebauthnCredential {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,
    pub credential: String,  // JSON serialized
    pub created_at: String,
    pub last_used_at: Option<String>,
}
```

### MFA Plugin (`#[cfg(feature = "mfa")]`)

```rust
// crates/yauth-toasty-models/src/totp_secret.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_totp_secrets")]
pub struct TotpSecret {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/backup_code.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_backup_codes")]
pub struct BackupCode {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    pub code_hash: String,
    pub used: bool,
    pub created_at: String,
}
```

### OAuth Plugin (`#[cfg(feature = "oauth")]`)

```rust
// crates/yauth-toasty-models/src/oauth_account.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_oauth_accounts")]
pub struct OauthAccount {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    #[index(fields(provider, provider_user_id))]
    pub provider: String,
    pub provider_user_id: String,

    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/oauth_state.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_oauth_states")]
pub struct OauthState {
    #[key]
    pub state: String,

    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}
```

### API Key Plugin (`#[cfg(feature = "api-key")]`)

```rust
// crates/yauth-toasty-models/src/api_key.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_api_keys")]
pub struct ApiKey {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    #[unique]
    pub key_prefix: String,

    pub key_hash: String,
    pub name: String,
    pub scopes: Option<String>,  // JSON
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
}
```

### Bearer Plugin (`#[cfg(feature = "bearer")]`)

```rust
// crates/yauth-toasty-models/src/refresh_token.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_refresh_tokens")]
pub struct RefreshToken {
    #[key]
    pub id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    #[unique]
    pub token_hash: String,

    #[index]
    pub family_id: String,

    pub expires_at: String,
    pub revoked: bool,
    pub created_at: String,
}
```

### OAuth2 Server Plugin (`#[cfg(feature = "oauth2-server")]`)

```rust
// crates/yauth-toasty-models/src/oauth2_client.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_oauth2_clients")]
pub struct Oauth2Client {
    #[key]
    pub id: String,

    #[unique]
    pub client_id: String,

    pub client_secret_hash: Option<String>,
    pub redirect_uris: String,  // JSON array
    pub client_name: Option<String>,
    pub grant_types: String,    // JSON array
    pub scopes: Option<String>, // JSON
    pub is_public: bool,
    pub token_endpoint_auth_method: Option<String>,
    pub public_key_pem: Option<String>,
    pub jwks_uri: Option<String>,
    pub banned_at: Option<String>,
    pub banned_reason: Option<String>,
    pub created_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/authorization_code.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_authorization_codes")]
pub struct AuthorizationCode {
    #[key]
    pub id: String,

    #[unique]
    pub code_hash: String,

    pub client_id: String,

    #[index]
    pub user_id: String,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<User>,

    pub scopes: Option<String>,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: String,
    pub used: bool,
    pub nonce: Option<String>,
    pub created_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/consent.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_consents")]
pub struct Consent {
    #[key]
    pub id: String,

    #[index(fields(user_id, client_id))]
    pub user_id: String,
    pub client_id: String,

    pub scopes: Option<String>,  // JSON
    pub created_at: String,
    pub updated_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/device_code.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_device_codes")]
pub struct DeviceCode {
    #[key]
    pub id: String,

    #[unique]
    pub device_code_hash: String,

    #[unique]
    pub user_code: String,

    pub client_id: String,
    pub scopes: Option<String>,
    pub status: String,

    #[index]
    pub user_id: Option<String>,

    pub expires_at: String,
    pub interval: i32,
    pub last_polled_at: Option<String>,
    pub created_at: String,
}
```

### Ephemeral Storage Models (challenge, rate limit, revocation)

```rust
// crates/yauth-toasty-models/src/challenge.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_challenges")]
pub struct Challenge {
    #[key]
    pub key: String,

    pub value: String,   // JSON serialized
    pub expires_at: String,
}
```

```rust
// crates/yauth-toasty-models/src/rate_limit.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_rate_limits")]
pub struct RateLimit {
    #[key]
    pub key: String,

    pub count: i64,
    pub window_start: String,
}
```

```rust
// crates/yauth-toasty-models/src/revocation.rs

#[derive(Debug, Clone, toasty::Model)]
#[toasty(table = "yauth_revocations")]
pub struct Revocation {
    #[key]
    pub jti: String,

    pub expires_at: String,
}
```

---

## 2. Backend Constructor & `DatabaseBackend` Implementation

```rust
// crates/yauth/src/backends/toasty/mod.rs

use toasty::Db;
use std::sync::Arc;
use crate::repo::{DatabaseBackend, Repositories};

/// Toasty ORM backend for yauth.
///
/// Supports SQLite, PostgreSQL, and MySQL through Toasty's driver system.
/// Accepts a pre-configured `toasty::Db` instance — does not manage connections.
pub struct ToastyBackend {
    db: Arc<Db>,
}

impl ToastyBackend {
    /// Create from an existing Toasty database instance.
    ///
    /// The caller is responsible for:
    /// 1. Configuring the `Db` with all yauth models via `toasty::models!()`
    /// 2. Running migrations via `toasty-cli` or `db.push_schema()`
    pub fn from_db(db: Db) -> Self {
        Self { db: Arc::new(db) }
    }

    /// Get a reference to the underlying Toasty Db instance.
    pub fn db(&self) -> &Db {
        &self.db
    }
}

impl DatabaseBackend for ToastyBackend {
    fn repositories(&self) -> Repositories {
        Repositories {
            users: Arc::new(ToastyUserRepo { db: self.db.clone() }),
            sessions: Arc::new(ToastySessionRepo { db: self.db.clone() }),
            audit: Arc::new(ToastyAuditLogRepo { db: self.db.clone() }),
            session_ops: Arc::new(ToastySessionOpsRepo { db: self.db.clone() }),
            challenges: Arc::new(ToastyChallengeRepo { db: self.db.clone() }),
            rate_limits: Arc::new(ToastyRateLimitRepo { db: self.db.clone() }),
            revocations: Arc::new(ToastyRevocationRepo { db: self.db.clone() }),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(ToastyPasswordRepo { db: self.db.clone() }),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(ToastyEmailVerificationRepo { db: self.db.clone() }),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(ToastyPasswordResetRepo { db: self.db.clone() }),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(ToastyPasskeyRepo { db: self.db.clone() }),

            #[cfg(feature = "mfa")]
            totp: Arc::new(ToastyTotpRepo { db: self.db.clone() }),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(ToastyBackupCodeRepo { db: self.db.clone() }),

            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(ToastyOauthAccountRepo { db: self.db.clone() }),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(ToastyOauthStateRepo { db: self.db.clone() }),

            #[cfg(feature = "api-key")]
            api_keys: Arc::new(ToastyApiKeyRepo { db: self.db.clone() }),

            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(ToastyRefreshTokenRepo { db: self.db.clone() }),

            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(ToastyOauth2ClientRepo { db: self.db.clone() }),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(ToastyAuthorizationCodeRepo { db: self.db.clone() }),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(ToastyConsentRepo { db: self.db.clone() }),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(ToastyDeviceCodeRepo { db: self.db.clone() }),
        }
    }
}
```

---

## 3. Repository Implementations (Idiomatic Toasty Query UX)

Each repository wraps `Arc<Db>` and uses Toasty's generated query methods internally, converting between Toasty model types and yauth domain types.

### UserRepository — full implementation sketch

```rust
// crates/yauth/src/backends/toasty/user_repo.rs

use std::sync::Arc;
use toasty::Db;
use uuid::Uuid;

use crate::domain;
use crate::repo::{sealed, RepoError, RepoFuture, UserRepository};
use yauth_toasty_models::User as ToastyUser;

pub(crate) struct ToastyUserRepo {
    pub(crate) db: Arc<Db>,
}

impl sealed::Sealed for ToastyUserRepo {}

impl UserRepository for ToastyUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: get_by_id on unique key
            match ToastyUser::get_by_id(&mut db, &id.to_string()).await {
                Ok(user) => Ok(Some(user.into_domain())),
                Err(toasty::Error::NotFound) => Ok(None),
                Err(e) => Err(RepoError::Internal(e.into())),
            }
        })
    }

    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>> {
        let email_lower = email.to_lowercase();
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: get_by_email on #[unique] field (case-insensitive via filter)
            let result = ToastyUser::filter(
                ToastyUser::fields().email().eq(&email_lower)
            )
            .first()
            .exec(&mut db)
            .await?;

            Ok(result.map(|u| u.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: create! macro with struct-literal syntax
            let user = toasty::create!(ToastyUser {
                id: input.id.to_string(),
                email: input.email.to_lowercase(),
                display_name: input.display_name,
                email_verified: input.email_verified,
                role: input.role,
                banned: input.banned,
                banned_reason: input.banned_reason,
                banned_until: input.banned_until.map(|dt| dt.to_string()),
                created_at: input.created_at.to_string(),
                updated_at: input.updated_at.to_string(),
            })
            .exec(&mut db)
            .await
            .map_err(|e| match e {
                toasty::Error::UniqueViolation(_) => RepoError::Conflict(
                    "duplicate key value violates unique constraint \"yauth_users_email_key\"".into()
                ),
                other => RepoError::Internal(other.into()),
            })?;

            Ok(user.into_domain())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: fetch then update builder
            let mut user = ToastyUser::get_by_id(&mut db, &id.to_string())
                .await
                .map_err(|_| RepoError::NotFound)?;

            let mut update = user.update();

            if let Some(email) = &changes.email {
                update = update.email(email.to_lowercase());
            }
            if let Some(display_name) = &changes.display_name {
                update = update.display_name(display_name.clone());
            }
            if let Some(email_verified) = changes.email_verified {
                update = update.email_verified(email_verified);
            }
            if let Some(role) = &changes.role {
                update = update.role(role.clone());
            }
            if let Some(banned) = changes.banned {
                update = update.banned(banned);
            }
            // ... remaining fields follow same pattern

            update.exec(&mut db).await.map_err(|e| RepoError::Internal(e.into()))?;

            // Re-fetch to return updated state
            let updated = ToastyUser::get_by_id(&mut db, &id.to_string())
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(updated.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: delete_by_id
            // Cascade handled by DB FK constraints or explicit cleanup
            ToastyUser::delete_by_id(&mut db, &id.to_string())
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn any_exists(&self) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: all() with first() to check existence
            let first = ToastyUser::all().first().exec(&mut db).await?;
            Ok(first.is_some())
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
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: filter + sort + limit
            let query = match &search {
                Some(pattern) => ToastyUser::filter(
                    ToastyUser::fields().email().contains(pattern)
                ),
                None => ToastyUser::all(),
            };

            let total = query.clone().exec(&mut db).await?.len() as i64;

            let users = query
                .sort(ToastyUser::fields().created_at().desc())
                .limit(limit as usize)
                .offset(offset as usize)
                .exec(&mut db)
                .await?
                .into_iter()
                .map(|u| u.into_domain())
                .collect();

            Ok((users, total))
        })
    }
}
```

### SessionOpsRepository — ephemeral session store

```rust
// crates/yauth/src/backends/toasty/session_ops_repo.rs

pub(crate) struct ToastySessionOpsRepo {
    pub(crate) db: Arc<Db>,
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
            let mut db = self.db.handle().await?;
            let id = Uuid::now_v7();
            let now = chrono::Utc::now().naive_utc();
            let expires_at = now + chrono::Duration::from_std(ttl)
                .map_err(|e| RepoError::Internal(e.to_string().into()))?;

            // Toasty idiomatic: create! macro
            toasty::create!(ToastySession {
                id: id.to_string(),
                user_id: user_id.to_string(),
                token_hash: token_hash,
                ip_address: ip_address,
                user_agent: user_agent,
                expires_at: expires_at.to_string(),
                created_at: now.to_string(),
            })
            .exec(&mut db)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;

            Ok(id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: filter on unique field
            let session = ToastySession::filter(
                ToastySession::fields().token_hash().eq(&token_hash)
            )
            .first()
            .exec(&mut db)
            .await?;

            match session {
                Some(s) if !s.is_expired() => Ok(Some(s.into_stored_session())),
                Some(s) => {
                    // Expired — delete and return None
                    s.delete().exec(&mut db).await.ok();
                    Ok(None)
                }
                None => Ok(None),
            }
        })
    }

    fn delete_session(&self, token_hash: &str) -> RepoFuture<'_, bool> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: filter + delete
            let deleted = ToastySession::filter(
                ToastySession::fields().token_hash().eq(&token_hash)
            )
            .delete()
            .exec(&mut db)
            .await?;
            Ok(deleted > 0)
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: filter_by_* + delete
            let deleted = ToastySession::filter_by_user_id(&user_id.to_string())
                .delete()
                .exec(&mut db)
                .await?;
            Ok(deleted as u64)
        })
    }

    fn delete_other_sessions_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> RepoFuture<'_, u64> {
        let keep_hash = keep_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            // Toasty idiomatic: compound filter with ne()
            let deleted = ToastySession::filter(
                ToastySession::fields().user_id().eq(&user_id.to_string())
                    .and(ToastySession::fields().token_hash().ne(&keep_hash))
            )
            .delete()
            .exec(&mut db)
            .await?;
            Ok(deleted as u64)
        })
    }
}
```

### ChallengeRepository — ephemeral key-value with TTL

```rust
// crates/yauth/src/backends/toasty/challenge_repo.rs

pub(crate) struct ToastyChallengeRepo {
    pub(crate) db: Arc<Db>,
}

impl sealed::Sealed for ToastyChallengeRepo {}

impl ChallengeRepository for ToastyChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            let expires_at = chrono::Utc::now().naive_utc()
                + chrono::Duration::seconds(ttl_secs as i64);

            // Toasty idiomatic: upsert via delete + create
            ToastyChallenge::delete_by_key(&mut db, &key).await.ok();
            toasty::create!(ToastyChallenge {
                key: key,
                value: serde_json::to_string(&value).unwrap(),
                expires_at: expires_at.to_string(),
            })
            .exec(&mut db)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;

            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            match ToastyChallenge::get_by_key(&mut db, &key).await {
                Ok(challenge) if !challenge.is_expired() => {
                    Ok(Some(serde_json::from_str(&challenge.value).unwrap()))
                }
                Ok(expired) => {
                    expired.delete().exec(&mut db).await.ok();
                    Ok(None)
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            let mut db = self.db.handle().await?;
            ToastyChallenge::delete_by_key(&mut db, &key).await.ok();
            Ok(())
        })
    }
}
```

---

## 4. Domain Type Conversions

Each Toasty model gets a private `into_domain()` method converting to yauth's ORM-agnostic domain types:

```rust
// crates/yauth/src/backends/toasty/conversions.rs

use yauth_toasty_models as models;
use crate::domain;
use uuid::Uuid;
use chrono::NaiveDateTime;

impl models::User {
    pub(crate) fn into_domain(self) -> domain::User {
        domain::User {
            id: Uuid::parse_str(&self.id).unwrap(),
            email: self.email,
            display_name: self.display_name,
            email_verified: self.email_verified,
            role: self.role,
            banned: self.banned,
            banned_reason: self.banned_reason,
            banned_until: self.banned_until
                .and_then(|s| NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.f").ok()),
            created_at: NaiveDateTime::parse_from_str(&self.created_at, "%Y-%m-%dT%H:%M:%S%.f")
                .unwrap(),
            updated_at: NaiveDateTime::parse_from_str(&self.updated_at, "%Y-%m-%dT%H:%M:%S%.f")
                .unwrap(),
        }
    }
}

impl models::Session {
    pub(crate) fn into_stored_session(self) -> domain::StoredSession {
        domain::StoredSession {
            id: Uuid::parse_str(&self.id).unwrap(),
            user_id: Uuid::parse_str(&self.user_id).unwrap(),
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            expires_at: NaiveDateTime::parse_from_str(&self.expires_at, "%Y-%m-%dT%H:%M:%S%.f")
                .unwrap(),
            created_at: NaiveDateTime::parse_from_str(&self.created_at, "%Y-%m-%dT%H:%M:%S%.f")
                .unwrap(),
        }
    }

    pub(crate) fn is_expired(&self) -> bool {
        let expires = NaiveDateTime::parse_from_str(&self.expires_at, "%Y-%m-%dT%H:%M:%S%.f")
            .unwrap_or_default();
        expires <= chrono::Utc::now().naive_utc()
    }
}

// ... similar conversions for all other models
```

---

## 5. Model Registration & Db Construction (User-Facing API)

```rust
// How a user constructs the Toasty backend

use toasty::Db;
use yauth::backends::toasty::ToastyBackend;
use yauth_toasty_models as models;

/// Macro to collect all active yauth toasty models based on features.
/// Users call this when building their `toasty::Db`.
#[macro_export]
macro_rules! yauth_toasty_models {
    () => {
        toasty::models!(
            models::User,
            models::Session,
            models::AuditLog,
            models::Challenge,
            models::RateLimit,
            models::Revocation,
            // Plugin models conditionally included:
            #[cfg(feature = "email-password")]
            models::Password,
            #[cfg(feature = "email-password")]
            models::EmailVerification,
            #[cfg(feature = "email-password")]
            models::PasswordReset,
            #[cfg(feature = "passkey")]
            models::WebauthnCredential,
            #[cfg(feature = "mfa")]
            models::TotpSecret,
            #[cfg(feature = "mfa")]
            models::BackupCode,
            #[cfg(feature = "oauth")]
            models::OauthAccount,
            #[cfg(feature = "oauth")]
            models::OauthState,
            #[cfg(feature = "api-key")]
            models::ApiKey,
            #[cfg(feature = "bearer")]
            models::RefreshToken,
            #[cfg(feature = "oauth2-server")]
            models::Oauth2Client,
            #[cfg(feature = "oauth2-server")]
            models::AuthorizationCode,
            #[cfg(feature = "oauth2-server")]
            models::Consent,
            #[cfg(feature = "oauth2-server")]
            models::DeviceCode,
        )
    };
}

// User's main.rs:
async fn setup() -> Result<YAuth, Box<dyn std::error::Error>> {
    let db = Db::builder()
        .models(yauth_toasty_models!())
        .connect("sqlite:./app.db")  // or "postgres://..." or "mysql://..."
        .await?;

    // For dev: auto-create schema
    // db.push_schema().await?;

    let backend = ToastyBackend::from_db(db);

    let yauth = YAuthBuilder::new(backend, config)
        .with_email_password(ep_config)
        .with_passkey(pk_config)
        .build()
        .await?;

    Ok(yauth)
}
```

---

## 6. Migration Integration with yauth's Plugin System

### Option A: `toasty-cli` native (recommended for toasty-first projects)

```rust
// src/bin/yauth_cli.rs — user creates a CLI binary for migrations

use toasty_cli::{Config, ToastyCli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load()?;  // reads Toasty.toml

    let db = toasty::Db::builder()
        .models(yauth_toasty_models!())
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;

    let cli = ToastyCli::with_config(db, config);
    cli.parse_and_run().await?;
    Ok(())
}
```

```toml
# Toasty.toml
[migration]
path = "migrations/toasty"
prefix_style = "Sequential"
checksums = true
statement_breakpoints = true
```

```bash
# Workflow:
# 1. Enable a new yauth plugin feature in Cargo.toml
# 2. Models are conditionally compiled into yauth_toasty_models!()
# 3. Generate migration diff:
cargo run --bin yauth_cli -- migration generate --name add_mfa_plugin
# 4. Review generated SQL
# 5. Apply:
cargo run --bin yauth_cli -- migration apply
```

### Option B: `cargo yauth generate` with Toasty dialect (for yauth-first projects)

```rust
// Extension to cargo-yauth CLI: new --orm toasty option

// crates/yauth-migration/src/toasty.rs — new module

/// Generate Toasty-compatible migration SQL from yauth plugin schemas.
/// Produces the same DDL as toasty-cli would, but driven by yauth.toml config.
pub fn generate_toasty_migration(
    config: &YAuthConfig,
    dialect: Dialect,
    output_dir: &Path,
) -> Result<Vec<MigrationFile>, MigrationError>;

/// Diff current yauth.toml against existing Toasty migration history.
pub fn diff_toasty_schema(
    config: &YAuthConfig,
    dialect: Dialect,
    migrations_dir: &Path,
) -> Result<SchemaDiff, MigrationError>;
```

```bash
# yauth.toml
[yauth]
orm = "toasty"
dialect = "sqlite"      # or "postgres", "mysql"
migrations_dir = "migrations/toasty"

[plugins]
email-password = true
passkey = true
mfa = false

# CLI usage:
cargo yauth generate              # generates toasty-format migration files
cargo yauth generate --check      # CI: fails if migrations are stale
cargo yauth add-plugin mfa        # updates yauth.toml + generates migration
```

---

## 7. Feature Flag: `toasty-backend`

```toml
# crates/yauth/Cargo.toml (additions)

[features]
toasty-backend = ["dep:toasty", "dep:yauth-toasty-models"]

[dependencies]
toasty = { version = "0.4", optional = true, features = [] }
yauth-toasty-models = { path = "../yauth-toasty-models", optional = true }
```

```rust
// crates/yauth/src/backends/mod.rs (addition)

#[cfg(feature = "toasty-backend")]
pub mod toasty;
```

---

## 8. New Crate: `yauth-toasty-models`

```toml
# crates/yauth-toasty-models/Cargo.toml

[package]
name = "yauth-toasty-models"
version = "0.1.0"  # managed by knope
edition = "2021"

[dependencies]
toasty = "0.4"

[features]
default = []
email-password = []
passkey = []
mfa = []
oauth = []
api-key = []
bearer = []
oauth2-server = []
account-lockout = []
magic-link = []
webhooks = []
full = [
    "email-password", "passkey", "mfa", "oauth",
    "api-key", "bearer", "oauth2-server",
    "account-lockout", "magic-link", "webhooks",
]
```

```rust
// crates/yauth-toasty-models/src/lib.rs

pub mod user;
pub mod session;
pub mod audit_log;
pub mod challenge;
pub mod rate_limit;
pub mod revocation;

#[cfg(feature = "email-password")]
pub mod password;
#[cfg(feature = "email-password")]
pub mod email_verification;
#[cfg(feature = "email-password")]
pub mod password_reset;

#[cfg(feature = "passkey")]
pub mod webauthn_credential;

#[cfg(feature = "mfa")]
pub mod totp_secret;
#[cfg(feature = "mfa")]
pub mod backup_code;

#[cfg(feature = "oauth")]
pub mod oauth_account;
#[cfg(feature = "oauth")]
pub mod oauth_state;

#[cfg(feature = "api-key")]
pub mod api_key;

#[cfg(feature = "bearer")]
pub mod refresh_token;

#[cfg(feature = "oauth2-server")]
pub mod oauth2_client;
#[cfg(feature = "oauth2-server")]
pub mod authorization_code;
#[cfg(feature = "oauth2-server")]
pub mod consent;
#[cfg(feature = "oauth2-server")]
pub mod device_code;

// Re-exports for convenience
pub use user::User;
pub use session::Session;
pub use audit_log::AuditLog;
pub use challenge::Challenge;
pub use rate_limit::RateLimit;
pub use revocation::Revocation;
```

---

## 9. Relation-Aware Cascade Deletes

Toasty handles FK cascade via nullability rules. For yauth's hard-cascade requirement on user delete:

```rust
// crates/yauth/src/backends/toasty/user_repo.rs

fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
    Box::pin(async move {
        let mut db = self.db.handle().await?;
        let id_str = id.to_string();

        // Explicit cascade — Toasty respects FK constraints but yauth
        // requires cross-table cleanup even without DB-level CASCADE.
        // Uses Toasty batch for efficiency:
        toasty::batch!(
            ToastySession::filter_by_user_id(&id_str).delete(),
            #[cfg(feature = "email-password")]
            ToastyPassword::delete_by_user_id(&mut db, &id_str),
            #[cfg(feature = "email-password")]
            ToastyEmailVerification::filter_by_user_id(&id_str).delete(),
            #[cfg(feature = "email-password")]
            ToastyPasswordReset::filter_by_user_id(&id_str).delete(),
            #[cfg(feature = "passkey")]
            ToastyWebauthnCredential::filter_by_user_id(&id_str).delete(),
            #[cfg(feature = "mfa")]
            ToastyTotpSecret::filter_by_user_id(&id_str).delete(),
            #[cfg(feature = "mfa")]
            ToastyBackupCode::filter_by_user_id(&id_str).delete(),
            #[cfg(feature = "oauth")]
            ToastyOauthAccount::filter_by_user_id(&id_str).delete(),
            #[cfg(feature = "api-key")]
            ToastyApiKey::filter_by_user_id(&id_str).delete(),
            #[cfg(feature = "bearer")]
            ToastyRefreshToken::filter_by_user_id(&id_str).delete(),
        )
        .exec(&mut db)
        .await
        .map_err(|e| RepoError::Internal(e.into()))?;

        // Finally delete the user
        ToastyUser::delete_by_id(&mut db, &id_str)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;

        Ok(())
    })
}
```

---

## 10. End-to-End Usage Example

```rust
// examples/toasty_backend.rs

use yauth::{YAuthBuilder, YAuthConfig, backends::toasty::ToastyBackend};
use yauth::plugins::{EmailPasswordConfig, PasskeyConfig, MfaConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build Toasty DB with yauth models
    let db = toasty::Db::builder()
        .models(yauth::yauth_toasty_models!())
        .connect("postgres://localhost/myapp")
        .await?;

    // 2. Wrap in yauth backend
    let backend = ToastyBackend::from_db(db);

    // 3. Build yauth with plugins
    let config = YAuthConfig::default();
    let yauth = YAuthBuilder::new(backend, config)
        .with_email_password(EmailPasswordConfig::default())
        .with_passkey(PasskeyConfig {
            rp_id: "example.com".into(),
            rp_name: "My App".into(),
            ..Default::default()
        })
        .with_mfa(MfaConfig::default())
        .build()
        .await?;

    // 4. Mount on Axum
    let app = axum::Router::new()
        .merge(yauth.router())
        .with_state(yauth.state().clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

---

## Design Decisions & Trade-offs

| Decision | Rationale |
|----------|-----------|
| Separate `yauth-toasty-models` crate | Toasty's `#[derive(Model)]` generates query methods on the struct — these are backend-internal and shouldn't leak into the public `yauth` API. Isolation also enables the crate to be used standalone. |
| String IDs (not `u64`) | yauth uses UUIDv7 (128-bit). Toasty supports String keys. Avoids `u64` truncation. |
| String datetimes (not native) | Toasty doesn't have built-in `chrono::NaiveDateTime` support across all drivers. ISO 8601 strings are portable across SQLite/PG/MySQL. Conversion happens in `into_domain()`. |
| `db.handle()` per operation | Toasty's `Db` manages connection pooling internally. Each repo method borrows a handle for its query lifetime. |
| Explicit cascade in `delete()` | Toasty's FK cascade depends on DB-level constraints. yauth guarantees cascade regardless of DB config — explicit is safer. |
| `yauth_toasty_models!()` macro | Aggregates feature-gated models into `toasty::models!()`. Users include it in their `Db::builder()` call — keeps model registration explicit and auditable. |
| Two migration paths | Toasty-first users use `toasty-cli` natively. yauth-first users use `cargo yauth generate --orm toasty`. Both produce the same SQL. |
