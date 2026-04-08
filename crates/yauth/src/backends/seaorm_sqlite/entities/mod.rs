//! SeaORM entity definitions for all yauth tables (SQLite dialect).
//!
//! Uses SQLite-compatible types: `String` for UUIDs, `Text` for JSON, `DateTimeWithTimeZone` for datetimes.

// Core tables (always compiled)
pub mod audit_log;
pub mod challenges;
pub mod rate_limits;
pub mod revocations;
pub mod sessions;
pub mod users;

// Feature-gated tables
#[cfg(feature = "email-password")]
pub mod email_verifications;
#[cfg(feature = "email-password")]
pub mod password_resets;
#[cfg(feature = "email-password")]
pub mod passwords;

#[cfg(feature = "passkey")]
pub mod passkeys;

#[cfg(feature = "mfa")]
pub mod backup_codes;
#[cfg(feature = "mfa")]
pub mod totp_secrets;

#[cfg(feature = "oauth")]
pub mod oauth_accounts;
#[cfg(feature = "oauth")]
pub mod oauth_states;

#[cfg(feature = "api-key")]
pub mod api_keys;

#[cfg(feature = "bearer")]
pub mod refresh_tokens;

#[cfg(feature = "magic-link")]
pub mod magic_links;

#[cfg(feature = "oauth2-server")]
pub mod authorization_codes;
#[cfg(feature = "oauth2-server")]
pub mod consents;
#[cfg(feature = "oauth2-server")]
pub mod device_codes;
#[cfg(feature = "oauth2-server")]
pub mod oauth2_clients;

#[cfg(feature = "account-lockout")]
pub mod account_locks;
#[cfg(feature = "account-lockout")]
pub mod unlock_tokens;

#[cfg(feature = "webhooks")]
pub mod webhook_deliveries;
#[cfg(feature = "webhooks")]
pub mod webhooks;
