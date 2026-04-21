//! Toasty model definitions for all yauth tables.
//!
//! Each model uses `#[derive(toasty::Model)]` and maps to a yauth table.
//! The `yauth_` prefix is applied at runtime via `Db::builder().table_name_prefix("yauth_")`.
//!
//! These entities are shared across all backends (PostgreSQL, MySQL, SQLite).
//! Toasty handles UUID storage differences internally (native UUID on PG,
//! CHAR(36) on MySQL, TEXT on SQLite).
//!
//! All entity modules are always compiled regardless of which plugin features
//! are enabled. This ensures a consistent model set for Toasty's migration
//! snapshot system. Only repository implementations are feature-gated.

// Core tables
mod users;
pub use users::*;

mod sessions;
pub use sessions::*;

mod audit_log;
pub use audit_log::*;

mod challenges;
pub use challenges::*;

mod rate_limits;
pub use rate_limits::*;

mod revocations;
pub use revocations::*;

// Plugin tables (always compiled — feature gates on repos only)
mod passwords;
pub use passwords::*;

mod email_verifications;
pub use email_verifications::*;

mod password_resets;
pub use password_resets::*;

mod passkeys;
pub use passkeys::*;

mod totp_secrets;
pub use totp_secrets::*;

mod backup_codes;
pub use backup_codes::*;

mod oauth_accounts;
pub use oauth_accounts::*;

mod oauth_states;
pub use oauth_states::*;

mod api_keys;
pub use api_keys::*;

mod refresh_tokens;
pub use refresh_tokens::*;

mod magic_links;
pub use magic_links::*;

mod oauth2_clients;
pub use oauth2_clients::*;

mod authorization_codes;
pub use authorization_codes::*;

mod consents;
pub use consents::*;

mod device_codes;
pub use device_codes::*;

mod account_locks;
pub use account_locks::*;

mod unlock_tokens;
pub use unlock_tokens::*;

mod webhooks;
pub use webhooks::*;

mod webhook_deliveries;
pub use webhook_deliveries::*;
