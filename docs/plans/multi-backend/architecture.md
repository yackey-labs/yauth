# Architecture

## Core Concept

Extend the proven store trait pattern (SessionStore, ChallengeStore, etc. with Memory/Postgres/Redis impls) to cover ALL persistent data — users, passwords, passkeys, OAuth accounts, API keys, etc. The result: yauth's auth logic is fully database-agnostic, and backends are pluggable.

## Data Model Changes

No schema changes. This is a pure refactoring of how code accesses the database. All existing tables, columns, and relationships remain identical.

### New Domain Types (ORM-agnostic)

Extract plain structs that cross the repository trait boundary. These live in a new `src/domain/` module and have NO Diesel derives — just `Debug, Clone, Serialize, Deserialize` with standard field types (Uuid, NaiveDateTime, String, etc.):

```
domain::User, domain::NewUser, domain::UpdateUser
domain::Password, domain::NewPassword
domain::WebauthnCredential, domain::NewWebauthnCredential
domain::TotpSecret, domain::NewTotpSecret
domain::BackupCode, domain::NewBackupCode
domain::OauthAccount, domain::NewOauthAccount
domain::OauthState, domain::NewOauthState
domain::ApiKey, domain::NewApiKey
domain::RefreshToken, domain::NewRefreshToken
domain::MagicLink, domain::NewMagicLink
domain::AuditLog, domain::NewAuditLog
domain::Oauth2Client, domain::NewOauth2Client
domain::AuthorizationCode, domain::NewAuthorizationCode
domain::Consent, domain::DeviceCode, etc.
domain::Webhook, domain::WebhookDelivery, etc.
domain::AccountLock, domain::UnlockToken, etc.
domain::OidcNonce, domain::NewOidcNonce
```

These mirror the existing model structs but without `#[diesel(...)]` attributes. The Diesel backend converts between its internal Diesel-annotated models and these domain types via private methods (not `From`/`Into` trait impls — keeps conversions backend-private and avoids orphan rule issues if crates are ever split).

The `domain/` module is always compiled — it has no backend-specific dependencies.

## Patterns

### RepoError

A dedicated error type for the repository layer, using `thiserror`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("conflict: {0}")]
    Conflict(String),

    #[error("not found")]
    NotFound,

    #[error("{0}")]
    Internal(#[from] Box<dyn std::error::Error + Send + Sync>),
}
```

Named `RepoError` (not `AuthError`) to keep it distinct from the existing `ApiError` and make the layer boundary clear. Implements `std::error::Error` + `Display` via `thiserror`, making it composable with `?` and the standard error ecosystem.

Conversion to `ApiError` via `From`:
```rust
impl From<RepoError> for ApiError {
    fn from(e: RepoError) -> Self {
        match e {
            RepoError::Conflict(msg) => api_err(StatusCode::CONFLICT, &msg),
            RepoError::NotFound => api_err(StatusCode::NOT_FOUND, "Not found"),
            RepoError::Internal(e) => {
                crate::otel::record_error("repo_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            }
        }
    }
}
```

This lets plugin handlers use `?` directly on repo calls: `let user = state.repos.users.find_by_id(id).await?.ok_or(RepoError::NotFound)?;`

### RepoFuture Type Alias

All repository and store traits need object safety for `Arc<dyn XxxRepo>`. RPITIT (`-> impl Future`) makes traits non-object-safe, so all trait methods use a boxed future type alias:

```rust
use std::future::Future;
use std::pin::Pin;

/// Boxed future for repository trait methods.
/// Required for object safety (`Arc<dyn Repo>`) — `impl Future` makes traits non-dyn-compatible.
/// The heap allocation is negligible compared to actual DB I/O.
pub type RepoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RepoError>> + Send + 'a>>;
```

Implementations use `Box::pin(async move { ... })`:
```rust
impl UserRepository for DieselUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<User>> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(|e| RepoError::Internal(e.into()))?;
            // ... Diesel query ...
            Ok(result.map(|r| r.into_domain()))
        })
    }
}
```

This replaces `#[async_trait]` across the entire crate — both new repo traits AND existing store traits. No proc macro needed.

### Sealed Repository Traits

All repository traits use the sealed trait pattern:

```rust
pub(crate) mod sealed {
    pub trait Sealed {}
}
```

Repository traits require `sealed::Sealed` as a supertrait:

```rust
pub trait UserRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<User>>;
    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<User>>;
    fn create(&self, input: NewUser) -> RepoFuture<'_, User>;
    // ...
}
```

Only types inside the yauth crate can implement `Sealed`, so only yauth's own backends can implement repository traits. This gives us freedom to add trait methods in minor releases — downstream consumers can't have implementations that would break.

### Repository Traits

One trait per aggregate, feature-gated to match the plugin. Traits live in `src/repo/` (separate from `src/backends/` which holds implementations):

```
UserRepository          — always available (core)
AuditLogRepository      — always available (core)
PasswordRepository      — #[cfg(feature = "email-password")]
EmailVerificationRepo   — #[cfg(feature = "email-password")]
PasswordResetRepo       — #[cfg(feature = "email-password")]
PasskeyRepository       — #[cfg(feature = "passkey")]
TotpRepository          — #[cfg(feature = "mfa")]
BackupCodeRepository    — #[cfg(feature = "mfa")]
ApiKeyRepository        — #[cfg(feature = "api-key")]
RefreshTokenRepository  — #[cfg(feature = "bearer")]
OauthAccountRepository  — #[cfg(feature = "oauth")]
OauthStateRepository    — #[cfg(feature = "oauth")]
MagicLinkRepository     — #[cfg(feature = "magic-link")]
Oauth2ServerRepository  — #[cfg(feature = "oauth2-server")]
AccountLockRepository   — #[cfg(feature = "account-lockout")]
WebhookRepository       — #[cfg(feature = "webhooks")]
OidcNonceRepository     — #[cfg(feature = "oidc")]
```

All methods return `RepoFuture<'_, T>` — no ORM errors leak through.

### DatabaseBackend Trait

```rust
pub trait DatabaseBackend: Send + Sync {
    /// Run migrations for the enabled features. Backends that use external
    /// migrations can no-op here. InMemoryBackend no-ops.
    fn migrate(&self, features: &EnabledFeatures)
        -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>>;

    /// Construct the full Repositories struct. Called once during build().
    fn repositories(&self) -> Repositories;

    /// Optional: expose a pool for Postgres ephemeral stores.
    /// Returns None for non-Postgres backends (InMemoryBackend, Turso, etc.).
    /// When None, the builder uses memory-based ephemeral stores unless
    /// the user explicitly configured Redis via with_store_backend().
    fn postgres_pool_for_stores(&self) -> Option<DbPool> { None }
}
```

`DatabaseBackend` is NOT sealed — consumers may implement custom backends (e.g., wrapping sqlx before yauth ships an official sqlx backend). Only repository traits are sealed, because we want to freely evolve their method sets.

The builder accepts `Box<dyn DatabaseBackend>`. All methods use `BoxFuture` for object safety, consistent with the repo traits.

### EnabledFeatures

Built from compile-time `cfg!()` macros, NOT from runtime config:

```rust
pub struct EnabledFeatures {
    pub email_password: bool,
    pub passkey: bool,
    pub mfa: bool,
    pub oauth: bool,
    pub bearer: bool,
    pub api_key: bool,
    pub magic_link: bool,
    pub oauth2_server: bool,
    pub account_lockout: bool,
    pub webhooks: bool,
    pub oidc: bool,
}

impl EnabledFeatures {
    pub fn from_compile_flags() -> Self {
        Self {
            email_password: cfg!(feature = "email-password"),
            passkey: cfg!(feature = "passkey"),
            // ...
        }
    }
}
```

This tells the backend which migrations to run and which repos to construct.

### Repositories Struct

Holds all `Arc<dyn XxxRepository>` trait objects. Constructed by `DatabaseBackend::repositories()`:

```rust
pub struct Repositories {
    pub users: Arc<dyn UserRepository>,
    pub audit: Arc<dyn AuditLogRepository>,
    #[cfg(feature = "email-password")]
    pub passwords: Arc<dyn PasswordRepository>,
    #[cfg(feature = "email-password")]
    pub email_verifications: Arc<dyn EmailVerificationRepo>,
    #[cfg(feature = "email-password")]
    pub password_resets: Arc<dyn PasswordResetRepo>,
    #[cfg(feature = "passkey")]
    pub passkeys: Arc<dyn PasskeyRepository>,
    // ... etc for all feature-gated repos
}
```

This replaces the raw `DbPool` in `YAuthState`. Plugins access `state.repos.users.find_by_email(...)` instead of getting a Diesel connection and running queries inline.

### YAuthState Changes

```rust
pub struct YAuthState {
    pub repos: Repositories,          // NEW — replaces `pub db: DbPool`
    pub config: Arc<YAuthConfig>,
    pub dummy_hash: String,
    pub rate_limiter: RateLimiter,
    pub challenge_store: Arc<dyn ChallengeStore>,
    pub rate_limit_store: Arc<dyn RateLimitStore>,
    pub session_store: Arc<dyn SessionStore>,
    pub revocation_store: Arc<dyn RevocationStore>,
    pub email_service: Option<EmailService>,
    pub plugins: Arc<Vec<Box<dyn YAuthPlugin>>>,
    // ... feature-gated configs unchanged
}
```

### Builder Changes

```rust
pub struct YAuthBuilder {
    backend: Box<dyn DatabaseBackend>,  // replaces `db: DbPool`
    config: YAuthConfig,
    store_backend: Option<StoreBackend>, // None = auto-detect from backend
    // ... rest unchanged
}

impl YAuthBuilder {
    pub fn new(backend: impl DatabaseBackend + 'static, config: YAuthConfig) -> Self { ... }

    pub async fn build(mut self) -> Result<YAuth, RepoError> {
        // Migration runs here (async now)
        let features = EnabledFeatures::from_compile_flags();
        self.backend.migrate(&features).await?;

        let repos = self.backend.repositories();

        // Store backend resolution:
        // 1. If user explicitly set store_backend via with_store_backend() or with_redis(), use that
        // 2. Else if backend provides a Postgres pool, use Postgres ephemeral stores
        // 3. Else fall back to memory stores
        let effective_store_backend = self.store_backend.unwrap_or_else(|| {
            match self.backend.postgres_pool_for_stores() {
                Some(_) => StoreBackend::Postgres,
                None => StoreBackend::Memory,
            }
        });

        // ... rest of build logic using repos + effective_store_backend
    }
}
```

Note: `build()` becomes `async` and returns `Result`. This is a breaking API change.

### Directory Layout

```
src/
├── domain/                 — ORM-agnostic types (always compiled, zero backend deps)
│   ├── mod.rs
│   ├── user.rs             — User, NewUser, UpdateUser
│   ├── password.rs         — Password, NewPassword (cfg email-password)
│   └── ...                 — one file per aggregate
├── repo/                   — trait definitions + RepoError + RepoFuture + sealed (always compiled)
│   ├── mod.rs              — DatabaseBackend, Repositories, EnabledFeatures, RepoError, RepoFuture, sealed
│   ├── user.rs             — UserRepository trait
│   ├── audit.rs            — AuditLogRepository trait
│   ├── password.rs         — PasswordRepository trait (cfg email-password)
│   └── ...                 — one file per aggregate
├── backends/               — trait implementations (feature-gated per backend)
│   ├── mod.rs              — re-exports
│   ├── diesel/             — #[cfg(feature = "diesel-backend")]
│   │   ├── mod.rs          — DieselBackend impl + impl sealed::Sealed for each repo type
│   │   ├── models.rs       — Diesel-annotated models (private, with into_domain() methods)
│   │   ├── schema.rs       — diesel::table! macros (moved from db/schema.rs)
│   │   ├── migrations.rs   — SQL migration runner (moved from db/migrations.rs)
│   │   ├── user_repo.rs
│   │   ├── password_repo.rs
│   │   └── ...
│   └── memory/             — #[cfg(feature = "memory-backend")]
│       ├── mod.rs          — InMemoryBackend impl + impl sealed::Sealed for each repo type
│       ├── user_repo.rs
│       └── ...
├── plugins/                — unchanged (but queries replaced with repo calls)
├── stores/                 — unchanged (ephemeral stores, migrated from async_trait to BoxFuture)
├── auth/                   — unchanged
├── otel.rs                 — unchanged
├── telemetry/              — unchanged (except Diesel instrumentation removed from init())
└── ...
```

### DieselBackend Construction

`DieselBackend` handles pool creation internally. All constructors return `Result` (except `from_pool`):

```rust
impl DieselBackend {
    /// Create from a database URL. Handles pool creation, schema validation,
    /// and Diesel query instrumentation setup.
    pub fn new(url: &str) -> Result<Self, RepoError> { ... }

    /// Create with a custom PostgreSQL schema (e.g., "auth").
    /// Validates the schema name and configures search_path on every connection.
    pub fn with_schema(url: &str, schema: &str) -> Result<Self, RepoError> { ... }

    /// Create from an existing pool (for consumers who manage their own pool).
    pub fn from_pool(pool: DbPool) -> Self { ... }

    /// Create from an existing pool with a custom schema.
    pub fn from_pool_with_schema(pool: DbPool, schema: &str) -> Result<Self, RepoError> { ... }
}
```

Schema validation, search_path configuration, and Diesel query instrumentation (`QueryTracing` + `set_default_instrumentation`) all happen inside construction.

`DieselBackend` also implements `postgres_pool_for_stores()` to return the pool for Postgres ephemeral stores.

### Diesel Model Conversions

Diesel-annotated models are private to the Diesel backend. Conversion to/from domain types uses private methods, not `From`/`Into` trait impls:

```rust
// Inside backends/diesel/models.rs — NOT public
#[derive(Queryable, Selectable)]
#[diesel(table_name = yauth_users)]
struct DieselUser {
    id: Uuid,
    email: String,
    // ...
}

impl DieselUser {
    fn into_domain(self) -> domain::User {
        domain::User {
            id: self.id,
            email: self.email,
            // ...
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = yauth_users)]
struct DieselNewUser {
    // ...
}

impl DieselNewUser {
    fn from_domain(input: domain::NewUser) -> Self {
        Self {
            id: input.id,
            email: input.email,
            // ...
        }
    }
}
```

This avoids orphan rule issues if crates are ever split, keeps conversions co-located with the backend that owns them, and prevents leaking Diesel types into the public API.

### Store Backend Interaction

The `StoreBackend` enum (Memory/Postgres/Redis) for ephemeral stores remains **independent** of `DatabaseBackend`:

- `DieselBackend` + `StoreBackend::Redis` — Diesel for persistence, Redis for sessions/rate-limits. Common in production.
- `DieselBackend` + `StoreBackend::Postgres` — Diesel for everything. The Postgres stores get the pool via `backend.postgres_pool_for_stores()`.
- `DieselBackend` + no explicit store config — auto-detects to `StoreBackend::Postgres` (since pool is available).
- `InMemoryBackend` + no explicit store config — auto-detects to `StoreBackend::Memory`.
- `InMemoryBackend` + `StoreBackend::Redis` — in-memory persistence, Redis ephemeral stores. Unusual but valid for testing Redis store behavior.
- `InMemoryBackend` + `StoreBackend::Postgres` — invalid combination (no pool available). Builder returns an error.

### Store Trait Migration

The existing store traits (`SessionStore`, `ChallengeStore`, `RateLimitStore`, `RevocationStore`) currently use `#[async_trait]`. Migrate them to manual `BoxFuture` (`Pin<Box<dyn Future<...> + Send + '_>>`) in the same pass, for consistency with repository traits. Use the same `RepoFuture` type alias (or a similar `StoreFuture` alias if the error type differs). This removes the `async_trait` proc macro dependency entirely.

This is a breaking change for any consumers who implement custom store backends — document it alongside the other breaking changes.

### Public API Changes

- Remove Diesel re-exports from `lib.rs` (`AsyncPgConnection`, `RunQueryDsl`, `DieselPool`, etc.)
- Move them into `backends::diesel` module (still accessible, just namespaced)
- `create_pool()` free function removed — replaced by `DieselBackend::new(url)` / `DieselBackend::with_schema(url, schema)`
- Backward-compat `entity` and `migration` re-export modules removed (or re-pointed to `backends::diesel`)
- `async_trait` removed as a dependency — all traits use manual `BoxFuture`
- `RepoFuture<'a, T>` type alias exported for consumers implementing `DatabaseBackend`

### Telemetry Integration

- The existing native OTel helpers (`crate::otel::*`) work unchanged in repository impls
- Diesel query instrumentation (`QueryTracing` + `set_default_instrumentation`) moves into `DieselBackend` construction — it's Diesel-specific, not a global concern
- `telemetry::init()` is reduced to pure OTel SDK setup (exporter, provider, propagator) — no Diesel-specific code
- Other backends instrument queries their own way (sqlx has built-in tracing, etc.)

## Cross-Milestone Dependencies

- **M1 -> M2**: M1 defines traits, domain types, `RepoError`, `RepoFuture`, and the `Repositories` struct. M2 moves existing Diesel code behind those traits and rewires the builder + state. The traits MUST be designed with all current plugin operations in mind, so M1 requires reading every plugin's DB operations.
- **M2 -> M3**: M2 produces a working Diesel backend with the full trait layer. M3 adds the in-memory backend as a second implementation, validating the abstraction actually works. M3 also validates that Diesel can be fully excluded at compile time via feature flags.
