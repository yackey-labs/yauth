//! Toasty model definitions for all yauth tables.
//!
//! Each model uses `#[derive(toasty::Model)]` and maps to a yauth table.
//! The `yauth_` prefix is applied at runtime via `Db::builder().table_name_prefix("yauth_")`.
//!
//! These entities are shared across all backends (PostgreSQL, MySQL, SQLite).
//! Toasty handles UUID storage differences internally (native UUID on PG,
//! CHAR(36) on MySQL, TEXT on SQLite).

// Core tables (always compiled)
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

// Feature-gated tables
#[cfg(feature = "email-password")]
mod passwords;
#[cfg(feature = "email-password")]
pub use passwords::*;

#[cfg(feature = "email-password")]
mod email_verifications;
#[cfg(feature = "email-password")]
pub use email_verifications::*;

#[cfg(feature = "email-password")]
mod password_resets;
#[cfg(feature = "email-password")]
pub use password_resets::*;

#[cfg(feature = "passkey")]
mod passkeys;
#[cfg(feature = "passkey")]
pub use passkeys::*;

#[cfg(feature = "mfa")]
mod totp_secrets;
#[cfg(feature = "mfa")]
pub use totp_secrets::*;

#[cfg(feature = "mfa")]
mod backup_codes;
#[cfg(feature = "mfa")]
pub use backup_codes::*;

#[cfg(feature = "oauth")]
mod oauth_accounts;
#[cfg(feature = "oauth")]
pub use oauth_accounts::*;

#[cfg(feature = "oauth")]
mod oauth_states;
#[cfg(feature = "oauth")]
pub use oauth_states::*;

#[cfg(feature = "api-key")]
mod api_keys;
#[cfg(feature = "api-key")]
pub use api_keys::*;

#[cfg(feature = "bearer")]
mod refresh_tokens;
#[cfg(feature = "bearer")]
pub use refresh_tokens::*;

#[cfg(feature = "magic-link")]
mod magic_links;
#[cfg(feature = "magic-link")]
pub use magic_links::*;

#[cfg(feature = "oauth2-server")]
mod oauth2_clients;
#[cfg(feature = "oauth2-server")]
pub use oauth2_clients::*;

#[cfg(feature = "oauth2-server")]
mod authorization_codes;
#[cfg(feature = "oauth2-server")]
pub use authorization_codes::*;

#[cfg(feature = "oauth2-server")]
mod consents;
#[cfg(feature = "oauth2-server")]
pub use consents::*;

#[cfg(feature = "oauth2-server")]
mod device_codes;
#[cfg(feature = "oauth2-server")]
pub use device_codes::*;

#[cfg(feature = "account-lockout")]
mod account_locks;
#[cfg(feature = "account-lockout")]
pub use account_locks::*;

#[cfg(feature = "account-lockout")]
mod unlock_tokens;
#[cfg(feature = "account-lockout")]
pub use unlock_tokens::*;

#[cfg(feature = "webhooks")]
mod webhooks;
#[cfg(feature = "webhooks")]
pub use webhooks::*;

#[cfg(feature = "webhooks")]
mod webhook_deliveries;
#[cfg(feature = "webhooks")]
pub use webhook_deliveries::*;
