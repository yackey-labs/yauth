# Dependencies

## Existing
- **diesel 2.2 + diesel-async 0.5** — remains as the default/primary backend implementation. No longer a hard dependency of the core library; moves behind a `diesel-backend` feature flag
- **uuid, chrono, serde, serde_json** — domain types continue using these directly
- **opentelemetry 0.31** — native OTel (tracing crate fully removed). DB instrumentation moves into backend impls rather than global Diesel hook

## To Add
- **thiserror** — derive `std::error::Error` + `Display` on `RepoError`. Standard Rust pattern for library error types. [docs.rs/thiserror](https://docs.rs/thiserror)
- Future backends (sqlx, toasty, turso/libsql) are additive and out of scope for this plan. Each would be a separate feature flag + dependency added when implemented.

## To Remove
- **async-trait** — replaced by manual `BoxFuture` (`Pin<Box<dyn Future + Send + '_>>`) with a `RepoFuture` type alias. All trait methods (repo traits AND store traits) use `BoxFuture` for object safety (`Arc<dyn Repo>` requires it). No proc macro needed — implementations use `Box::pin(async move { ... })`.

## Approach Decisions
- **Trait objects (`Arc<dyn Repo>`) over generics**: Matches the proven store trait pattern already in the codebase. Dynamic dispatch cost is negligible for DB operations. Avoids infecting every handler, plugin, and router with generic parameters.
- **`BoxFuture` on all trait methods (repo + store)**: RPITIT (`-> impl Future`) makes traits non-object-safe — incompatible with `Arc<dyn XxxRepository>`. Manual `Pin<Box<dyn Future<...> + Send + '_>>` via a `RepoFuture<'a, T>` type alias keeps traits object-safe while removing the `async_trait` proc macro dependency. The heap allocation per call is negligible compared to actual DB I/O.
- **Repository-per-aggregate over mega-repository**: One trait per domain (UserRepo, PasswordRepo, etc.) rather than one giant trait. Keeps feature gating clean — `PasskeyRepo` only exists when `passkey` feature is enabled.
- **Domain types separate from ORM types**: Plain structs (no Diesel derives) cross the trait boundary. Each backend maps to/from its own ORM-annotated internal types via private conversion methods (not `From`/`Into` impls — avoids orphan rule issues and keeps conversions backend-private).
- **`DatabaseBackend` meta-trait**: A single trait bundles migration + repository construction. The builder accepts `Box<dyn DatabaseBackend>`. All methods use `BoxFuture` for object safety. This lets backends own their own migration strategy (in-process, external, or skip).
- **Feature flags for backends, not cfg for exclusion**: `diesel-backend` feature enables the Diesel impl. `memory-backend` enables the in-memory impl. `default` includes `diesel-backend` for backward compat. Future backends are additive features (`sqlx-backend`, `turso-backend`). Unlike plugins (which are additive capabilities), backends are exclusive at runtime — but multiple can be compiled in. `full` includes both `diesel-backend` and `memory-backend`.
- **Sealed repository traits**: All repository traits use the sealed trait pattern (`pub(crate) mod sealed { pub trait Sealed {} }`) so only backends inside the crate can implement them. This preserves the freedom to add trait methods in minor releases without it being a breaking change for downstream consumers.
- **`RepoError` with `thiserror`**: A dedicated error type for the repository layer, separate from `ApiError`. Named `RepoError` to make the domain clear. Implements `std::error::Error` + `Display` via `thiserror`. Variants: `Conflict`, `NotFound`, `Internal`. Converts to `ApiError` via `From` impl for ergonomic `?` in handlers.
- **Fallible construction**: `DieselBackend::new()` returns `Result<Self, RepoError>`, not `Self`. Pool creation, schema validation, and instrumentation setup can all fail — make that explicit in the type system rather than panicking.
