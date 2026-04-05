# Milestone 3: In-Memory Backend

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

Implement a full in-memory backend to validate the abstraction and enable database-free testing.

### What must work:
1. `InMemoryBackend` in `src/backends/memory/` implements `DatabaseBackend` with all repository traits using `Arc<RwLock<HashMap>>` (or similar) per entity type
2. Each in-memory repo struct implements `sealed::Sealed` + its repository trait, using `Box::pin(async move { ... })` for all methods
3. `InMemoryBackend::migrate()` is a no-op that returns `Ok(())`
4. `InMemoryBackend::postgres_pool_for_stores()` returns `None` — so the builder auto-detects to memory-based ephemeral stores (unless the user explicitly configured Redis)
5. `InMemoryBackend::new()` is infallible — returns `Self`, not `Result` (nothing to fail)
6. Building yauth with `InMemoryBackend` requires zero external dependencies (no Postgres, no Redis)
7. The example server can start and serve auth flows using only `InMemoryBackend` (add a `YAUTH_BACKEND=memory` env var to the example server)
8. Core auth flows work end-to-end: register, login, session validation, logout
9. Feature-gated flows work when enabled: passkey registration/login, MFA setup/verify, API key create/use, bearer token issue/refresh, magic link send/verify

### After building, prove it works:
- Run `cargo test --features full` — all existing tests still pass (Diesel backend unchanged)
- Run `cargo check --no-default-features --features memory-backend,email-password` — compiles without pulling in Diesel at all
- Run `cargo check --no-default-features --features memory-backend,email-password,passkey,mfa,oauth,bearer,api-key,magic-link,admin,status,oauth2-server,account-lockout,webhooks,oidc,telemetry,openapi` — compiles with all plugins but no Diesel
- Run `cargo clippy --features full -- -D warnings` — clean
- Create a minimal integration test (`tests/memory_backend.rs`) that:
  1. Builds YAuth with `InMemoryBackend::new()` and email-password enabled
  2. Registers a user via `POST /register`
  3. Logs in with `POST /login` and gets a session cookie
  4. Calls `GET /session` and confirms the user is authenticated
  5. Logs out via `POST /logout` and confirms session is invalidated
  6. Attempts duplicate registration with the same email — gets 409 Conflict
- Start the example server with `YAUTH_BACKEND=memory`, hit it with curl:
  - `POST /register` with email/password — 200
  - `POST /login` with same credentials — 200 with session cookie
  - `GET /session` with cookie — returns user info
  - `POST /logout` — session invalidated
  - `POST /register` with same email — 409 Conflict

### Test strategy:
Write a new integration test (`tests/memory_backend.rs`) that exercises core flows against `InMemoryBackend`. This validates the trait abstraction works with a completely different implementation. Keep it focused — test the auth contract, not the storage details. A conformance test pattern (same test suite parameterized by backend) is ideal for future backends but not required yet.

### Known pitfalls:
1. **Unique constraint enforcement**: The in-memory backend must enforce uniqueness on email (users), name (API keys per user), token_hash (sessions), OAuth provider+provider_id pairs, WebAuthn credential IDs, etc. — the same constraints that Postgres enforces via unique indexes. Without this, duplicate registrations silently succeed and tests that depend on conflict errors break. Implement uniqueness checks in the repo methods and return `RepoError::Conflict`.
2. **Timestamp handling**: Domain types use `NaiveDateTime`. In-memory must generate timestamps consistently via `chrono::Utc::now().naive_utc()`. Don't use `SystemTime` — it won't match the domain types.
3. **ID generation**: The in-memory backend must generate UUIDs for new entities the same way — `Uuid::new_v4()`. Some entities have `id` as a caller-provided field in the `NewXxx` struct, others don't. Match the existing patterns from M1's domain types.
4. **Expiration/TTL behavior**: Password reset tokens, email verification tokens, magic links, and sessions all have expiration. The in-memory backend must check expiration on read (not background cleanup). Return `None`/expired when `now > expires_at`. This is the domain invariant from the trait contract.
5. **Cascade behavior**: Deleting a user in Postgres cascades to related tables (passwords, sessions, OAuth accounts, etc.) via foreign key constraints. The in-memory backend must explicitly implement cascade deletes in `UserRepository::delete`. Walk through every table that has a `user_id` foreign key and ensure the in-memory impl cleans them all up.
6. **Case-insensitive email lookup**: The trait contract requires case-insensitive email matching. The in-memory backend must `.to_lowercase()` on both storage and lookup to satisfy this invariant.
7. **Thread safety — don't hold locks across await**: Use `Arc<RwLock<HashMap>>` (not `Mutex`) for read-heavy workloads. Since all repo methods return `Box::pin(async move { ... })`, the pattern is: acquire lock, clone data out, drop lock, return. The `RwLockGuard` never crosses an `.await` because all in-memory operations are synchronous — the `async move` block is just for the `BoxFuture` signature. If an operation is purely sync, `Box::pin(async { /* sync code */ })` is fine.
8. **Feature compilation without Diesel**: When `diesel-backend` feature is disabled and only `memory-backend` is active, the crate must compile without pulling in Diesel at all. This means ALL Diesel-specific code (annotated models, `diesel::table!` schema, migrations runner, `DieselPgBackend`) must be behind `#[cfg(feature = "diesel-backend")]`. The `domain/` and `repo/` modules have zero Diesel imports. Verify with: `cargo check --no-default-features --features memory-backend,email-password`.
9. **OAuth state and challenge flow**: The OAuth plugin stores CSRF state tokens in `yauth_oauth_states`. The in-memory `OauthStateRepository` must handle create + lookup + delete for these ephemeral state tokens. Similarly, OIDC nonces. These are easy to forget because they're flow-management, not user data.
10. **Passkey challenge storage**: Passkey registration and authentication use challenge data stored via the `ChallengeStore` (ephemeral store, NOT the repository layer). Since `InMemoryBackend` auto-detects to memory ephemeral stores, this works out of the box — but verify that the challenge flow completes correctly in the integration test if passkey features are tested.
11. **`InMemoryBackend::new()` is infallible**: Unlike `DieselPgBackend::new()` which returns `Result` (pool creation can fail), `InMemoryBackend::new()` just initializes empty HashMaps — nothing to fail. Return `Self` directly. This is a nice ergonomic signal that the in-memory backend is zero-config.
