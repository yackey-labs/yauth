#[cfg(feature = "seaorm")]
pub mod audit_log;
#[cfg(feature = "seaorm")]
pub mod sessions;
#[cfg(feature = "seaorm")]
pub mod users;

#[cfg(all(feature = "seaorm", feature = "email-password"))]
pub mod email_verifications;
#[cfg(all(feature = "seaorm", feature = "email-password"))]
pub mod password_resets;
#[cfg(all(feature = "seaorm", feature = "email-password"))]
pub mod passwords;

#[cfg(all(feature = "seaorm", feature = "passkey"))]
pub mod webauthn_credentials;

#[cfg(all(feature = "seaorm", feature = "mfa"))]
pub mod backup_codes;
#[cfg(all(feature = "seaorm", feature = "mfa"))]
pub mod totp_secrets;

#[cfg(all(feature = "seaorm", feature = "oauth"))]
pub mod oauth_accounts;
#[cfg(all(feature = "seaorm", feature = "oauth"))]
pub mod oauth_states;

#[cfg(all(feature = "seaorm", feature = "api-key"))]
pub mod api_keys;

#[cfg(all(feature = "seaorm", feature = "bearer"))]
pub mod refresh_tokens;

#[cfg(all(feature = "seaorm", feature = "magic-link"))]
pub mod magic_links;

#[cfg(all(feature = "seaorm", feature = "oauth2-server"))]
pub mod authorization_codes;
#[cfg(all(feature = "seaorm", feature = "oauth2-server"))]
pub mod consents;
#[cfg(all(feature = "seaorm", feature = "oauth2-server"))]
pub mod device_codes;
#[cfg(all(feature = "seaorm", feature = "oauth2-server"))]
pub mod oauth2_clients;

#[cfg(all(feature = "seaorm", feature = "account-lockout"))]
pub mod account_locks;
#[cfg(all(feature = "seaorm", feature = "account-lockout"))]
pub mod unlock_tokens;

#[cfg(all(feature = "seaorm", feature = "webhooks"))]
pub mod webhook_deliveries;
#[cfg(all(feature = "seaorm", feature = "webhooks"))]
pub mod webhooks;

#[cfg(all(feature = "seaorm", feature = "oidc"))]
pub mod oidc_nonces;

#[cfg(feature = "diesel-async")]
pub mod diesel;
